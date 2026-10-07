#!/usr/bin/env bash
# ISOGrid Nomad agent installer.
#
# Run it on a Docker Swarm manager (or on the machine that will become one):
#
#   curl -fsSL https://raw.githubusercontent.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/main/install.sh -o install.sh
#   sudo bash install.sh
#
# It deploys the agent as a Swarm service, one replica pinned to the managers,
# after asking:
#   - whether to initialise Swarm when this machine is not in one yet,
#   - which overlay networks the agent should join,
#   - where the operator console listens and which addresses may reach it,
#   - where the bundle received from ISOGrid is (the cluster's certificate and
#     key, the intent-signing key, identifiers); without it the agent runs
#     detached,
#   - how to reach Vault or OpenBao (address, CA, AppRole or token file).
#
# Answers are saved in /etc/isogrid-nomad/install.env and offered as defaults
# on the next run. Every answer can also be given through an environment
# variable named NOMAD_<KEY>; with NOMAD_NONINTERACTIVE=1 nothing is asked.
#
#   sudo bash install.sh uninstall [--purge]   removes the service, its secrets
#                                              and configs; --purge also deletes
#                                              the data volume.
set -euo pipefail

SERVICE=isogrid-nomad-agent
STATE_DIR=/etc/isogrid-nomad
ANSWERS="$STATE_DIR/install.env"
VOLUME=isogrid-nomad-agent-data
IMAGE_DEFAULT=ghcr.io/isogrid-by-skyvault/nomad-agent:latest
NETWORK_DEFAULT=isogrid-nomad
NONINTERACTIVE="${NOMAD_NONINTERACTIVE:-0}"
[ -t 0 ] || NONINTERACTIVE=1

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# ask KEY "prompt" "default": sets A_KEY. Precedence: NOMAD_KEY from the
# environment, then the saved answer, then the default; interactive runs show
# that value and accept Enter to keep it.
declare -A SAVED=()
ask() {
    local key="$1" prompt="$2" def="${3:-}" env_name="NOMAD_$1" value reply
    value="${!env_name:-${SAVED[$key]:-$def}}"
    if [ "$NONINTERACTIVE" != 1 ]; then
        read -r -p "$prompt${value:+ [$value]}: " reply
        value="${reply:-$value}"
    fi
    printf -v "A_$key" '%s' "$value"
    SAVED[$key]="$value"
}
yesno() { # KEY "prompt" default(yes|no) -> returns 0 for yes
    ask "$1" "$2 (yes/no)" "$3"
    local v="A_$1"
    case "${!v,,}" in y|yes|true|1) SAVED[$1]=yes; return 0 ;; *) SAVED[$1]=no; return 1 ;; esac
}
load_answers() {
    [ -f "$ANSWERS" ] || return 0
    while IFS='=' read -r k v; do
        [ -n "$k" ] && [ "${k#\#}" = "$k" ] && SAVED[$k]="$v"
    done < "$ANSWERS"
}
save_answers() {
    mkdir -p "$STATE_DIR"
    {
        echo "# Answers from the last run of install.sh; edit or delete freely."
        for k in "${!SAVED[@]}"; do printf '%s=%s\n' "$k" "${SAVED[$k]}"; done | sort
    } > "$ANSWERS"
    chmod 600 "$ANSWERS"
}

primary_iface() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'; }
primary_addr()  { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'; }
primary_cidr()  { local i; i="$(primary_iface)"; [ -n "$i" ] && ip -4 route show dev "$i" scope link 2>/dev/null | awk '{print $1; exit}'; }

need_root() { [ "$(id -u)" = 0 ] || die "run as root (sudo bash install.sh)"; }

# ---------------------------------------------------------------- uninstall
uninstall() {
    need_root
    local purge="${1:-}"
    say "Removing the ISOGrid Nomad agent"
    if docker service inspect "$SERVICE" >/dev/null 2>&1; then
        docker service rm "$SERVICE" >/dev/null && note "service removed"
        sleep 3
    fi
    for s in $(docker secret ls --format '{{.Name}}' | grep "^$SERVICE-" || true); do docker secret rm "$s" >/dev/null && note "secret $s removed"; done
    for c in $(docker config ls --format '{{.Name}}' | grep "^$SERVICE-" || true); do docker config rm "$c" >/dev/null && note "config $c removed"; done
    remove_firewall
    if [ "$purge" = "--purge" ]; then
        # The task that used the volume may still be releasing it.
        local removed=no
        for _ in $(seq 1 15); do
            if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then removed=yes; break; fi
            if docker volume rm "$VOLUME" >/dev/null 2>&1; then removed=yes; break; fi
            sleep 2
        done
        [ "$removed" = yes ] && note "data volume removed" || note "data volume $VOLUME is still in use; remove it later with: docker volume rm $VOLUME"
        rm -rf "$STATE_DIR" && note "$STATE_DIR removed"
    else
        note "data volume $VOLUME and $STATE_DIR kept (use --purge to delete them)"
    fi
}

# ---------------------------------------------------------------- firewall
# The console is published in host mode, which binds every interface. These
# rules in DOCKER-USER (evaluated before Docker's own) keep it to the
# addresses the operator listed. Rules carry a comment so they can be found.
remove_firewall() {
    command -v iptables >/dev/null 2>&1 || return 0
    iptables -S DOCKER-USER 2>/dev/null | grep -- "--comment $SERVICE" | sed 's/^-A /-D /' | while read -r rule; do
        # shellcheck disable=SC2086
        iptables $rule 2>/dev/null || true
    done
}
apply_firewall() { # port "cidr cidr ..."
    local port="$1" allow="$2" iface cidr
    command -v iptables >/dev/null 2>&1 || { note "iptables not found: the console port is open to every interface"; return 0; }
    iptables -L DOCKER-USER -n >/dev/null 2>&1 || { note "DOCKER-USER chain not found: the console port is open to every interface"; return 0; }
    iface="$(primary_iface)"
    remove_firewall
    iptables -I DOCKER-USER 1 -i "$iface" -p tcp --dport "$port" -j DROP -m comment --comment "$SERVICE"
    for cidr in $allow; do
        iptables -I DOCKER-USER 1 -i "$iface" -p tcp --dport "$port" -s "$cidr" -j ACCEPT -m comment --comment "$SERVICE"
    done
    note "console port $port on $iface accepts only: $allow"
    note "(rules live in the DOCKER-USER chain; persist them with your usual tool, e.g. iptables-persistent)"
}

# ---------------------------------------------------------------- install
install() {
    need_root
    load_answers

    say "ISOGrid Nomad agent installer"
    note "This machine will run the agent as a Docker Swarm service."

    # 1. Docker
    if ! command -v docker >/dev/null 2>&1; then
        if yesno INSTALL_DOCKER "Docker is not installed. Install Docker Engine from get.docker.com?" yes; then
            curl -fsSL https://get.docker.com | sh
        else
            die "Docker Engine is required"
        fi
    fi
    systemctl enable --now docker >/dev/null 2>&1 || true
    docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"

    # 2. Swarm
    local state control
    read -r state control <<< "$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')"
    case "$state" in
        active)
            [ "$control" = true ] || die "this node is a Swarm worker; run the installer on a manager"
            note "Swarm manager detected" ;;
        inactive)
            say "This machine is not part of a Swarm."
            if yesno INIT_SWARM "Initialise a new Swarm with this machine as manager?" yes; then
                ask ADVERTISE_ADDR "Address other nodes will reach this manager on" "$(primary_addr)"
                docker swarm init --advertise-addr "$A_ADVERTISE_ADDR" >/dev/null
                note "Swarm initialised; join workers with: $(docker swarm join-token worker -q | sed 's/^/token /') at $A_ADVERTISE_ADDR:2377"
            else
                die "a Swarm manager is required"
            fi ;;
        *) die "Swarm is in state '$state'; fix that first (docker info)" ;;
    esac

    # 3. Image
    say "Agent image"
    ask IMAGE "Image to run" "$IMAGE_DEFAULT"

    # 4. Networks
    say "Swarm networks"
    local -a available=() chosen=()
    mapfile -t available < <(docker network ls --filter driver=overlay --filter scope=swarm --format '{{.Name}}' | grep -vx ingress || true)
    if [ ${#available[@]} -gt 0 ]; then
        note "Overlay networks on this Swarm:"
        local i=1; for n in "${available[@]}"; do note "  $i) $n"; i=$((i+1)); done
        ask NETWORKS "Networks the agent joins (names or numbers, comma separated, empty for none)" ""
        IFS=',' read -r -a picks <<< "$A_NETWORKS"
        for p in "${picks[@]}"; do
            p="$(echo "$p" | xargs)"; [ -z "$p" ] && continue
            if [[ "$p" =~ ^[0-9]+$ ]]; then
                [ "$p" -ge 1 ] && [ "$p" -le ${#available[@]} ] || die "no network numbered $p"
                chosen+=("${available[$((p-1))]}")
            else
                printf '%s\n' "${available[@]}" | grep -qx "$p" || die "no overlay network named $p"
                chosen+=("$p")
            fi
        done
        # Remember names, not list positions: the list may be ordered
        # differently at the next run.
        SAVED[NETWORKS]="$(IFS=,; echo "${chosen[*]}")"
    else
        note "No overlay networks yet (apart from ingress)."
        SAVED[NETWORKS]=""
    fi
    if ! docker network inspect "$NETWORK_DEFAULT" >/dev/null 2>&1; then
        if yesno CREATE_NETWORK "Create the attachable overlay network '$NETWORK_DEFAULT' for services the agent deploys?" yes; then
            docker network create --driver overlay --attachable "$NETWORK_DEFAULT" >/dev/null
            chosen+=("$NETWORK_DEFAULT")
        fi
    else
        chosen+=("$NETWORK_DEFAULT")
    fi
    local -a network_args=()
    for n in $(printf '%s\n' "${chosen[@]}" | sort -u); do network_args+=(--network "$n"); done

    # 5. Console
    say "Operator console"
    note "The console is for your operators only; put your own reverse proxy and identity provider in front of it."
    ask CONSOLE_PORT "Port the console listens on (every interface, host mode)" 8460
    ask CONSOLE_ALLOW "Addresses allowed to reach it (CIDRs, space separated)" "127.0.0.1/32 $(primary_cidr)"
    local firewall=no
    if yesno FIREWALL "Restrict the console port to those addresses with iptables?" yes; then firewall=yes; fi

    # 6. ISOGrid bundle
    say "ISOGrid connection"
    note "ISOGrid gives you a bundle when you add the Nomad integration: agent.env, client.crt, client.key, intent.pub."
    ask BUNDLE_DIR "Directory holding that bundle (empty to run detached, console only)" "$( [ -d "$STATE_DIR/bundle" ] && echo "$STATE_DIR/bundle" )"
    local -a env_args=() secret_args=() config_args=()
    local stamp; stamp="$(date +%Y%m%d%H%M%S)"
    if [ -n "$A_BUNDLE_DIR" ]; then
        for f in agent.env client.crt client.key intent.pub; do
            [ -f "$A_BUNDLE_DIR/$f" ] || die "missing $A_BUNDLE_DIR/$f"
        done
        local k v
        while IFS='=' read -r k v; do
            case "$k" in
                STREAM_URL|CLUSTER_ID|ORGANIZATION_ID|DEVICE_ID|DEVICE_NAME) env_args+=(--env "ISOGRID_NOMAD_$k=$v") ;;
            esac
        done < "$A_BUNDLE_DIR/agent.env"
        docker secret create "$SERVICE-client-key-$stamp" "$A_BUNDLE_DIR/client.key" >/dev/null
        docker config create "$SERVICE-client-cert-$stamp" "$A_BUNDLE_DIR/client.crt" >/dev/null
        docker config create "$SERVICE-intent-pub-$stamp" "$A_BUNDLE_DIR/intent.pub" >/dev/null
        secret_args+=(--secret "source=$SERVICE-client-key-$stamp,target=client.key,uid=10001,gid=10001,mode=0400")
        config_args+=(--config "source=$SERVICE-client-cert-$stamp,target=/etc/nomad-agent/client.crt"
                      --config "source=$SERVICE-intent-pub-$stamp,target=/etc/nomad-agent/intent.pub")
        env_args+=(--env ISOGRID_NOMAD_CLIENT_KEY_FILE=/run/secrets/client.key
                   --env ISOGRID_NOMAD_CLIENT_CERT_FILE=/etc/nomad-agent/client.crt
                   --env ISOGRID_NOMAD_INTENT_PUBLIC_KEY_FILE=/etc/nomad-agent/intent.pub)
        # A lab whose API sits behind a self-signed edge ships its CA as ca.crt.
        if [ -f "$A_BUNDLE_DIR/ca.crt" ]; then
            docker config create "$SERVICE-stream-ca-$stamp" "$A_BUNDLE_DIR/ca.crt" >/dev/null
            config_args+=(--config "source=$SERVICE-stream-ca-$stamp,target=/etc/nomad-agent/stream-ca.crt")
            env_args+=(--env ISOGRID_NOMAD_STREAM_CA_FILE=/etc/nomad-agent/stream-ca.crt)
        fi
    else
        note "No bundle: the agent starts detached and only serves the console."
    fi

    # 7. Vault / OpenBao
    say "Vault or OpenBao"
    ask VAULT_ADDR "Vault address (empty to configure later)" ""
    if [ -n "$A_VAULT_ADDR" ]; then
        ask VAULT_CA "CA certificate file if the Vault certificate is private (empty if public)" ""
        ask VAULT_AUTH_FILE "AppRole env file (VAULT_ROLE_ID and VAULT_SECRET_ID) or a token file" "$( [ -f /etc/isogrid-lab/vault-approle.env ] && echo /etc/isogrid-lab/vault-approle.env )"
        [ -f "$A_VAULT_AUTH_FILE" ] || die "missing $A_VAULT_AUTH_FILE"
        ask VAULT_PREFIX "KV prefix the agent is allowed to use" isogrid
        env_args+=(--env "ISOGRID_NOMAD_VAULT_ADDR=$A_VAULT_ADDR" --env "ISOGRID_NOMAD_VAULT_PREFIX=$A_VAULT_PREFIX")
        if [ -n "$A_VAULT_CA" ]; then
            [ -f "$A_VAULT_CA" ] || die "missing $A_VAULT_CA"
            docker config create "$SERVICE-vault-ca-$stamp" "$A_VAULT_CA" >/dev/null
            config_args+=(--config "source=$SERVICE-vault-ca-$stamp,target=/etc/nomad-agent/vault-ca.crt")
            env_args+=(--env ISOGRID_NOMAD_VAULT_CACERT_FILE=/etc/nomad-agent/vault-ca.crt)
        fi
        if grep -q '^VAULT_ROLE_ID=' "$A_VAULT_AUTH_FILE"; then
            local role_id; role_id="$(sed -n 's/^VAULT_ROLE_ID=//p' "$A_VAULT_AUTH_FILE")"
            sed -n 's/^VAULT_SECRET_ID=//p' "$A_VAULT_AUTH_FILE" | tr -d '\n' | docker secret create "$SERVICE-vault-secret-id-$stamp" - >/dev/null
            secret_args+=(--secret "source=$SERVICE-vault-secret-id-$stamp,target=vault-secret-id,uid=10001,gid=10001,mode=0400")
            env_args+=(--env "ISOGRID_NOMAD_VAULT_ROLE_ID=$role_id" --env ISOGRID_NOMAD_VAULT_SECRET_ID_FILE=/run/secrets/vault-secret-id)
        else
            docker secret create "$SERVICE-vault-token-$stamp" "$A_VAULT_AUTH_FILE" >/dev/null
            secret_args+=(--secret "source=$SERVICE-vault-token-$stamp,target=vault-token,uid=10001,gid=10001,mode=0400")
            env_args+=(--env ISOGRID_NOMAD_VAULT_TOKEN_FILE=/run/secrets/vault-token)
        fi
    fi

    # 8. Deploy
    say "Deploying"
    local docker_gid; docker_gid="$(stat -c %g /var/run/docker.sock)"
    if docker service inspect "$SERVICE" >/dev/null 2>&1; then
        note "replacing the existing service"
        docker service rm "$SERVICE" >/dev/null
        sleep 3
        for s in $(docker secret ls --format '{{.Name}}' | grep "^$SERVICE-" | grep -v -- "-$stamp$" || true); do docker secret rm "$s" >/dev/null || true; done
        for c in $(docker config ls --format '{{.Name}}' | grep "^$SERVICE-" | grep -v -- "-$stamp$" || true); do docker config rm "$c" >/dev/null || true; done
    fi
    docker service create --quiet \
        --name "$SERVICE" \
        --replicas 1 \
        --constraint node.role==manager \
        --restart-condition any \
        --update-order start-first \
        --group "$docker_gid" \
        --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
        --mount "type=volume,source=$VOLUME,target=/var/lib/nomad-agent" \
        --publish "mode=host,published=$A_CONSOLE_PORT,target=8460" \
        --env ISOGRID_NOMAD_LISTEN=0.0.0.0:8460 \
        "${network_args[@]}" "${env_args[@]}" "${secret_args[@]}" "${config_args[@]}" \
        "$A_IMAGE" >/dev/null
    [ "$firewall" = yes ] && apply_firewall "$A_CONSOLE_PORT" "$A_CONSOLE_ALLOW" || remove_firewall
    save_answers

    local ok=no
    for _ in $(seq 1 45); do
        if docker service ps "$SERVICE" --filter desired-state=running --format '{{.CurrentState}}' | grep -q '^Running'; then ok=yes; break; fi
        sleep 2
    done
    if [ "$ok" = yes ]; then
        say "The agent is running."
        note "Console:  http://$(primary_addr):$A_CONSOLE_PORT/"
        note "Health:   curl -s http://127.0.0.1:$A_CONSOLE_PORT/api/healthz"
        local token; token="$(docker service logs "$SERVICE" 2>&1 | grep -o 'setup token: [A-Z2-7]*' | tail -1 || true)"
        if [ -n "$token" ]; then
            note "Account:  the console has no operator yet. Create one there with this $token"
        fi
        note "Logs:     docker service logs -f $SERVICE"
        note "Answers:  $ANSWERS (re-run the installer to change anything)"
    else
        say "The service did not reach Running in time."
        docker service ps "$SERVICE" --no-trunc | head -5
        exit 1
    fi
}

case "${1:-install}" in
    install) install ;;
    uninstall) uninstall "${2:-}" ;;
    -h|--help|help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown command '$1' (install | uninstall [--purge])" ;;
esac
