<p align="center"><img src="web/public/nomad-logo.svg" width="360" alt="ISOGrid Nomad: the ISOGrid cloud and shield beside a Touareg head"></p>

# ISOGrid Nomad agent

The ISOGrid Nomad agent is the only piece of [ISOGrid](https://isogrid.skyvault.pro)
that runs inside a customer's own infrastructure. It lets a team use the ISOGrid
console to build and deploy on their own Docker Swarm or Kubernetes clusters
while ISOGrid never holds an SSH key to their machines, never sees a secret, and
never reads their logs.

The code is public so that the people who run it can read exactly what it does
before they run it.

## What the agent never does

- It never opens a port for ISOGrid. The agent opens one outbound WebSocket
  to the ISOGrid API over HTTPS, and everything travels on it: intents down,
  replies and heartbeats up. Queries from ISOGrid (list repositories, list
  branches, list images) are answered over that same channel.
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
 │  nomad-agent (one per cluster)           │  wss   │  API (edge, 443)   │
 │   ├─ stream client  ───────────────────────────►  │  relay per agent   │◄── control plane
 │   ├─ intent verifier (Ed25519, nonce)    │ HTTPS  │  queue per cluster │    signs intents
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
- **Outbound only, over HTTPS.** The agent opens a WebSocket to the ISOGrid
  API through the same edge and certificate as the console: no broker and no
  extra port face the internet. The API sends a nonce; the agent answers with
  the certificate ISOGrid issued for the cluster and the nonce signed with its
  key. ISOGrid also admits the connection only from the customer's declared
  source addresses; the certificate is the authentication, the allow-list a
  second layer.
- **Signed intents.** Each intent is signed with a per-organization key held in
  ISOGrid's own vault, carries a nonce and an expiry, and is executed at most
  once (the id is recorded in SQLite). Nothing on the path can forge or replay
  an intent.
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
   (`agent.env`, `client.crt`, `client.key`, `intent.pub`). The key becomes a
   Docker secret and the certificate and signing key Docker configs. Without
   a bundle the agent runs detached and only serves its console.
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
defaults. Without a stream URL the agent runs detached: console only.

| Variable | Meaning |
| --- | --- |
| `LISTEN` | Console address, default `127.0.0.1:8460`. The installer sets `0.0.0.0:8460` inside the container and limits who reaches the published port. |
| `DATA_DIR` | Where SQLite, samples and logs live, default `/var/lib/nomad-agent`. |
| `STREAM_URL` | Where the agent connects: `wss://<api>/api/v1/nomad/stream`. |
| `CLIENT_CERT_FILE`, `CLIENT_KEY_FILE` | The certificate ISOGrid issued for the cluster, and its key. |
| `STREAM_CA_FILE` | Optional private CA for the API's TLS (labs); the system roots otherwise. |
| `CLUSTER_ID`, `ORGANIZATION_ID` | Identifiers issued by ISOGrid when the integration was added. |
| `DEVICE_ID`, `DEVICE_NAME` | Fleets only: how this device introduces itself. Default the Swarm node id and the engine's host name. |
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

Built:

- the stream client (signed handshake, heartbeats, reconnection with backoff,
  the cluster's overlay networks reported to ISOGrid);
- the intent verifier (Ed25519, scope, freshness) and a durable journal, so an
  intent id is executed at most once across restarts;
- the executors: `ping`, `capabilities.describe`, `networks.list` and
  `service.deploy|status|scale|remove|rollback` on Docker Swarm, with secrets
  resolved by reference from Vault at deploy time;
- the Vault/OpenBao client (AppRole or token file, KV v2 below one prefix);
- the local store (SQLite, pure Go) and the performance sampler;
- the console: a local operator account created with a setup token from the
  agent's log, Argon2id passwords, optional TOTP, and the Overview,
  Deployments, Secrets, Logs, Performance, Activity and Settings sections.

- connections to GitHub, GitLab and container registries, held on the agent
  side, and `build.run` through them. A connection is made in the console
  with a token of yours, or handed over by ISOGrid when a person connecting
  GitHub, GitLab or a registry there chooses "on my Nomad agent": the
  `connection.put` intent carries the credential once into your Vault and
  ISOGrid keeps only the name (`connection.remove` withdraws it). For GitHub,
  ISOGrid forwards its App's one-hour tokens and renews them. The agent never
  lets ISOGrid overwrite or remove a connection an operator made here.

- the primitives ISOGrid's managed databases (PostgreSQL single, pooled and
  Patroni HA, MySQL, MongoDB) are provisioned with on this cluster, each
  generic and each under the same guard rails: `service.inspect`,
  `service.update` (image, size, networks, placement, mounted files),
  `nodes.list`, `network.ensure|remove` (overlays the agent made, only),
  `volume.remove` (volumes the agent made, on this node, only),
  `secret.ensure|remove` and `job.run` (a one-off container on an overlay,
  fed on stdin, for the SQL and the probes). ISOGrid never writes a database
  password: it sends `{{secret:databases/<instance>/<name>}}` placeholders,
  the agent mints the values in your Vault (`secret.ensure`) and substitutes
  them in environment, mounted files and stdin itself. The files a router or
  pooler mounts become Swarm configs, or Swarm secrets when they hold
  passwords (PgBouncer's userlist). The passwords are readable in this
  console's Secrets section and nowhere on ISOGrid.

Next: an approval step for deploys an operator wants to review, a log store
with its own retention (logs are read from the engine today), backups of
managed databases on an agent cluster, and the Kubernetes executor.

## The console

Open it on the address the installer printed. The first visit asks for the
setup token:

```sh
docker service logs isogrid-nomad-agent 2>&1 | grep "setup token"
```

Sessions last twelve hours. Sign-in is slowed down after five failures.
Secret values are write-only: the console lists references and never shows a
value again. Put your own reverse proxy and identity provider in front of it
for anything beyond the break-glass account.

## Protocol notes

- The stream handshake: the API sends `{"type":"challenge","nonce":...}`; the
  agent answers `{"type":"hello","cluster_id","certificate","signature",
  "version","capabilities"}` where `signature` is base64 of a DER ECDSA
  P-256/SHA-256 signature over the nonce's UTF-8 bytes; the API answers
  `welcome` with `heartbeat_seconds`. Then `intent` frames come down and
  `reply` and `heartbeat` frames go up. Close codes: 4000 bad hello, 4003
  refused (shown as such in the console, retried every two minutes), 4008
  idle, 4011 platform unavailable.
- An intent's signature covers the canonical JSON of the envelope without its
  `signature` member: keys sorted at every level, no whitespace, numbers as
  written on the wire, strings escaped like Python's `json.dumps(...,
  ensure_ascii=False)`. The control plane produces it with
  `json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
  and signs those bytes with the organization's Ed25519 key.
- A reply is `{id, kind, cluster_id, status, result?, error?, code?,
  agent_version, completed_at}` with `status` one of `ok`, `error`,
  `rejected` (the envelope did not verify; `code` says why) or `unsupported`.

## Fleets

The same bundle may be installed on many devices (a *fleet* on ISOGrid). Each
agent then says in its hello which device it is (`device`, `device_name`:
the Swarm node id and host name unless `DEVICE_ID`/`DEVICE_NAME` are set),
reads a queue of its own, and every intent sent to the fleet reaches every
device. Three things make an update survive a link that drops half-way:

- intents run under the agent's lifetime, not the session's, so a dropped
  socket never cancels a half-done update;
- a deploy with `atomic: true` pulls the image before the service is
  touched, swaps only once it is on disk, and reports a rollback as a
  failure rather than a degraded success;
- replies are kept in the local store until the platform acknowledges them
  (`ack` frame), and re-sent at the next connection.

## Licence

MIT, see [LICENSE](LICENSE).
