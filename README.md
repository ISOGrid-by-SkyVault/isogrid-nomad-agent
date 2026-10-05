# ISOGrid Nomad agent

The ISOGrid Nomad agent is the only piece of [ISOGrid](https://isogrid.skyvault.pro)
that runs inside a customer's own infrastructure. It lets a team use the ISOGrid
console to build and deploy on their own Docker Swarm or Kubernetes clusters
while ISOGrid never holds an SSH key to their machines, never sees a secret, and
never reads their logs.

The code is public so that the people who run it can read exactly what it does
before they run it.

## What the agent never does

- It never opens a port for ISOGrid. Every connection is outbound, from the
  agent to the ISOGrid broker. Queries from ISOGrid (list repositories, list
  branches, list images) are answered over that same outbound channel.
- It never accepts a shell command. The control plane sends typed, signed
  *intents* (see [`intents/schema.json`](intents/schema.json)); the agent only
  executes the intents it recognises, with the parameters they declare.
- It never sends a secret value anywhere. ISOGrid knows the *names* and
  *references* of secrets. The values are entered by the customer in the agent's
  own console and stored in the customer's HashiCorp Vault or OpenBao. The
  agent reads them at deploy time and turns them into Docker secrets or
  Kubernetes Secrets locally.
- It never ships logs to ISOGrid. Build logs and container logs are kept in the
  agent's local store and are readable only in the agent console.
- Its console is never reachable by ISOGrid. It is published on the customer's
  network only, behind the customer's own reverse proxy and identity provider
  (OpenID Connect), with a local break-glass account protected by TOTP.

## Architecture

```
 customer network                                     ISOGrid
 ┌──────────────────────────────────────────┐        ┌────────────────────┐
 │  nomad-agent (one per cluster)           │  mTLS  │  RabbitMQ broker   │
 │   ├─ broker client  ───────────────────────────►  │  vhost per org     │◄── control plane
 │   ├─ intent verifier (Ed25519, nonce)    │ AMQPS  │  queue per cluster │    signs intents
 │   ├─ executor: Docker Engine API (socket)│        └────────────────────┘
 │   │            or Kubernetes API         │
 │   ├─ Vault/OpenBao client (AppRole)      │
 │   ├─ SQLite: intents, results, builds    │
 │   ├─ samples: CPU/memory/network per task│
 │   ├─ local log store                     │
 │   └─ operator console (embedded SPA)     │
 │  Vault / OpenBao  ◄── secrets entered here │
 │  Docker Swarm or Kubernetes               │
 │  Customer-managed NGINX / HAProxy         │
 └──────────────────────────────────────────┘
```

- **One agent per cluster, scoped to one organization.** The organization is
  the tenancy boundary on the ISOGrid side (its own broker vhost). The cluster
  is the execution unit: its own client certificate, its own queue.
- **Outbound only.** The agent connects to the broker with mutual TLS. ISOGrid
  also restricts the broker to the customer's declared source addresses, but
  the certificate is the authentication; the allow-list is a second layer.
- **Signed intents.** Each intent is signed with a per-organization key held in
  ISOGrid's own vault, carries a nonce and an expiry, and is executed at most
  once (the id is recorded in SQLite). A compromised broker cannot forge or
  replay an intent.
- **Guard rails on what can run.** Deploy intents that ask for privileged
  containers, host networking, the Docker socket or bind mounts outside an
  allowed root are refused unless an operator approves them in the console.
  Images are pulled only from registries the operator allow-listed.
- **Secrets by reference.** A deploy intent lists `{key, ref}` pairs. The agent
  reads `ref` from Vault under its prefix, creates a Docker secret or injects
  an environment variable, and reports success or failure without the value.
- **Local state.** SQLite (pure Go driver, no cgo) holds intents, results,
  builds, approvals and the operator accounts. Performance samples are stored
  in a compact embedded time-series table with a configurable retention.
  Container logs are stored locally with their own retention.
- **Web tier stays with the customer.** The agent publishes services on the
  networks and ports the customer chose. It does not install or configure
  NGINX, HAProxy or certificates. Optionally it can write an upstream snippet
  into a directory the customer's proxy includes.

## Repository layout

| Path | What |
| --- | --- |
| `cmd/nomad-agent/` | The agent binary and its commands: `run`, `check`, `version`. |
| `internal/config/` | Settings, all `ISOGRID_NOMAD_*` environment variables. |
| `intents/schema.json` | The signed intent envelope the control plane sends. |
| `web/` | The operator console (React, Vite). Its build is embedded into the binary by `web/embed.go`, so one executable ships both. |
| `install.sh` | Interactive installer that deploys the agent as a Swarm service. |
| `Dockerfile` | Builds the console, then the static binary, into a small Alpine image. |

## Install on Docker Swarm

Run the installer on a Swarm manager, or on the machine that should become
one. It asks before it acts and saves its answers for the next run.

```sh
curl -fsSL https://raw.githubusercontent.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/main/install.sh -o install.sh
sudo bash install.sh
```

What it does:

1. Installs Docker Engine if it is missing, and initialises a Swarm if the
   machine is not in one yet. It refuses to run on a worker.
2. Lists the overlay networks and asks which ones the agent should join, and
   whether to create the attachable `isogrid-nomad` network for the services
   it will deploy.
3. Asks where the operator console should listen and which addresses may
   reach it, and restricts the port in the `DOCKER-USER` chain accordingly.
4. Asks for the bundle ISOGrid gave you when you added the integration
   (`agent.env`, `client.crt`, `client.key`, `ca.crt`, `intent.pub`). The key
   becomes a Docker secret and the certificates Docker configs. Without a
   bundle the agent runs detached and only serves its console.
5. Asks how to reach Vault or OpenBao: address, private CA if any, and either
   an AppRole file (`VAULT_ROLE_ID`, `VAULT_SECRET_ID`) or a token file. The
   secret id or token becomes a Docker secret.
6. Creates the service: one replica pinned to the managers, the Docker socket
   mounted, a named volume for its state, the console published in host mode.

`sudo bash install.sh uninstall` removes the service, its secrets and its
configs; add `--purge` to delete the data volume too. Every answer can be
provided as `NOMAD_<KEY>` in the environment, and `NOMAD_NONINTERACTIVE=1`
runs without prompts.

On Kubernetes the agent runs as a Deployment with a ServiceAccount; no API
server has to be reachable from the internet. That manifest follows the Swarm
installer.

## Configuration

All settings are environment variables prefixed `ISOGRID_NOMAD_`. See
[`internal/config/config.go`](internal/config/config.go) for the full list and
defaults. Without a broker URL the agent runs detached: console only.

| Variable | Meaning |
| --- | --- |
| `LISTEN` | Console address, default `127.0.0.1:8460`. The installer sets `0.0.0.0:8460` inside the container and limits who reaches the published port. |
| `DATA_DIR` | Where SQLite, samples and logs live, default `/var/lib/nomad-agent`. |
| `BROKER_URL`, `BROKER_VHOST` | The ISOGrid broker and the organization's vhost. |
| `BROKER_CERT_FILE`, `BROKER_KEY_FILE`, `BROKER_CA_FILE` | Client certificate for mutual TLS and the pinned broker CA. |
| `CLUSTER_ID`, `ORGANIZATION_ID` | Identifiers issued by ISOGrid when the integration was added. |
| `INTENT_PUBLIC_KEY_FILE` | ISOGrid's intent-signing public key for this organization. |
| `VAULT_ADDR`, `VAULT_CACERT_FILE` | The customer's Vault or OpenBao and its private CA, if any. |
| `VAULT_TOKEN_FILE` or `VAULT_ROLE_ID` + `VAULT_SECRET_ID_FILE` | How the agent authenticates to Vault. |
| `VAULT_MOUNT`, `VAULT_PREFIX` | The KV v2 mount and the path prefix the agent is allowed to use. |
| `DOCKER_HOST` | Docker Engine endpoint, default the local unix socket. |

## Develop

```sh
# console with hot reload, proxied to a local agent on 127.0.0.1:8460
cd web && npm install && npm run dev
# full image: console build, static binary, Alpine runtime
docker build -t isogrid/nomad-agent:dev .
docker run --rm -p 127.0.0.1:8460:8460 -e ISOGRID_NOMAD_LISTEN=0.0.0.0:8460 isogrid/nomad-agent:dev
```

`go build ./...` works on a fresh clone without Node: the embedded `web/dist`
then holds only a placeholder and the agent answers that the console is not
built.

## Status

Early scaffold. The configuration, the intent envelope, the console shell with
its overview page, the installer and the CI exist; the broker client, the
executors, the Vault client, the stores and the console's remaining sections
are being built in that order.

## Licence

MIT, see [LICENSE](LICENSE).
