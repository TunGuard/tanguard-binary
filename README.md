# TunGuard
<p align="center">
  <img src="https://img.shields.io/badge/WireGuard-88171A?style=for-the-badge&logo=wireguard&logoColor=white" alt="WireGuard">
  <img src="https://img.shields.io/badge/MikroTik-293239?style=for-the-badge&logo=mikrotik&logoColor=white" alt="MikroTik">
  <img src="https://img.shields.io/badge/OpenWrt-00B5E2?style=for-the-badge&logo=openwrt&logoColor=white" alt="OpenWrt">
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/RouterOS-293239?style=for-the-badge&logo=mikrotik&logoColor=white" alt="RouterOS">
  <img src="https://img.shields.io/badge/IPv4%20%2F%20IPv6-00599C?style=for-the-badge&logo=internetexplorer&logoColor=white" alt="IPv4 IPv6">
</p>

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/TunGuard/tanguard-binary?style=flat-square" alt="Go Version">
  <img src="https://img.shields.io/github/license/TunGuard/tanguard-binary?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/TunGuard/tanguard-binary?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/actions/workflow/status/TunGuard/tanguard-binary/release.yml?branch=main&style=flat-square" alt="Build">
  <img src="https://img.shields.io/github/downloads/TunGuard/tanguard-binary/total?style=flat-square" alt="Downloads">
  <img src="https://img.shields.io/github/stars/TunGuard/tanguard-binary?style=flat-square" alt="Stars">
</p>

**Userspace WireGuard VPN Server — Web Dashboard — SSH Gateway**

TunGuard is a self-contained WireGuard server that runs entirely in userspace — no kernel modules, no `apt install wireguard`, no kernel configuration. It includes a web dashboard for managing peers (clients) and generating ready-to-use configuration files with QR codes for your phone.

```bash
sudo ./tanguard -web
# Open http://yourserver:9000 → add clients from your browser
```

## Quick Start

### Install the latest binary (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/TunGuard/get/main/installer.sh | bash
```

### Or build from source

```bash
git clone https://github.com/TunGuard/tanguard-binary.git
cd tanguard-binary
go build -o tanguard .

sudo ./tanguard -web
```

## The dashboard will be available at:

http://YOUR_SERVER_IP:9000

## 3. Log in

On a fresh installation, use the default dashboard credentials:
```
Username: admin
Password: tanguard
```
You must change these credentials on your first login.

After logging in, TunGuard will immediately take you to the dashboard login setup screen. Choose a new username and password before continuing.

«Important: Do not leave the default "admin" / "tanguard" credentials in use on an Internet-facing server.»

Your new dashboard credentials are also used by the optional SSH Gateway.

## 4. Connect your first device

You can connect a normal WireGuard device or provision a MikroTik router.

WireGuard device

1. Open Peers.
2. Click Generate Config.
3. Enter a device name, such as "My Phone".
4. Click Generate.
5. Download or copy the ".conf" file, or scan the displayed QR code with the WireGuard mobile app.

That's it. Your device can now connect to the TunGuard VPN.
---

#### MikroTik router

For MikroTik routers, you can use MikroTik Provision to generate and apply the required RouterOS configuration.

Open:

<a href="https://mikrotik-provision.vercel.app/">
  <img src="https://img.shields.io/badge/OPEN%20MIKROTIK%20PROVISION-Configure%20Your%20Router%20%E2%86%92-0066FF?style=for-the-badge&logo=mikrotik&logoColor=white" alt="Open MikroTik Provision" height="52">
</a>

- Enter your TunGuard server details and follow the provisioning instructions to configure the MikroTik router as a WireGuard client.

This is useful when you want to connect an entire network behind a MikroTik router instead of configuring individual devices.


### Full service: VPN + Web UI + SSH jump host

```bash
sudo ./tanguard -web -ssh
```

- The WireGuard VPN listens on **UDP port 13231** (default).
- The web dashboard is disabled by default — start it explicitly with `-web` (or `WEB_ENABLED=true`).
- When enabled, the web dashboard is at **http://yourserver:9000**.
- Default web login: `admin` / `tanguard`. On first login you will be required to set a new username and password.

## Connecting Clients

### 1. Generate a client config from the web UI

1. Open `http://yourserver:9000` and log in.
2. Go to the **Peers** page, click **Generate Config**.
3. Enter a device name (e.g. "My Phone"), click **Generate**.
4. A complete `.conf` file is created — **Copy**, **Download**, or scan the **QR code** with the WireGuard mobile app.

The config will look like this:

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.100.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = yourserver:13231
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### 2. Import the config on your device

| Device | How to import |
|---|---|
| **Windows / macOS / Linux** | Open the WireGuard app → "Add Tunnel" → "Import from file" |
| **iOS / Android** | Use the WireGuard app to scan the QR code from the dashboard |
| **Linux (wg-quick)** | Copy the `.conf` to `/etc/wireguard/wg0.conf`, run `wg-quick up wg0` |

### 3. That's it

Your device is now connected to the VPN. All traffic is routed through your server.

### Adding an existing key

If you already have a WireGuard keypair (e.g. from a router or a device that generated its own keys), go to the **Peers** page → **Add Existing Key** and enter the public key and the IP you want to assign.

### Removing a peer

Click the **Remove** button next to any peer on the Peers page, or call:

```bash
curl -X POST http://localhost:9000/api/peer/remove \
  -H "Content-Type: application/json" \
  -d '{"public_key":"..."}'
```

## Web Dashboard

The dashboard runs on port **9000** (same port as the API). It is **disabled by default** — enable it with `-web` or `WEB_ENABLED=true`. Its sections:

| Section | What you can do |
|---|---|
| **Dashboard** | Server status, peer count, data transfer totals |
| **Peers** | List peers, add/generate configs, view status, download configs, scan QR codes, remove peers |
| **P2P** | Mesh nodes and groups, direct/relayed links, PSK join credentials |
| **TRP** | TCP port-mapping proxies and their live connections |
| **Domains** | Point a domain at a TRP mapping or tunneled service with automatic HTTPS (Let's Encrypt) |
| **Policy Groups** | Restrict what devices in a group may reach — see below |
| **Settings** | Reference of all configuration options |

The status page refreshes every 10 seconds. You'll see transfer stats, last handshake times, and online/offline status for each peer.

### Changing the dashboard login

When you log in with the default `admin` / `tanguard` credentials for the first time, the server sends you to its own setup page (`login.html`) instead of the dashboard. That page carries the same form as **Settings → Dashboard Login**, and states the version you are running, until you set a new username and password. Nothing else in the dashboard is reachable until you do.

You can change the dashboard login again at any time under **Settings → Dashboard Login**. The new credentials are saved (hashed) in `web_credentials.json` inside your `DATA_DIR` and take effect immediately.

### Forgotten dashboard password

If you forget the dashboard password, reset it from the terminal:

```bash
sudo ./tanguard --reset
```

This removes the stored login and restores the default `admin` / `tanguard`. Start the server again and log in to set a new password.

## Policy Groups (optional)

Policy groups are an administrative filter over connections that already exist.
A group has four switches, and a device is in exactly one group:

| Switch | When off, the group's devices… |
|---|---|
| **Allow devices in this group to talk to each other** | cannot reach each other on the tunnel, in either direction |
| **Allow P2P automatic mesh features** | are not punched together and are not offered each other's endpoints |
| **Allow TRP proxy port mapping features** | cannot be the target of a port mapping on this server |
| **Allow standard WireGuard internet access** | cannot reach anything outside the tunnel |

**Groups are isolated from each other.** Device-to-device traffic never crosses a
group boundary: the switch above only opens traffic between two devices of the
*same* group, so devices in the default group reach only other default-group
devices, and a private group is reachable only from inside itself. A direct P2P
link is refused for the same reason, because it never passes through the server
and so cannot be filtered on the way through.

**Nothing about a connection changes.** Devices keep the same WireGuard config,
stay authenticated, and see no error — a blocked packet is silently discarded,
so a denied device just times out exactly as if the target were unreachable. The
tunnel itself, and reaching this server, always work regardless of the switches,
so a misconfigured group can always be fixed from the dashboard or the API.

### The Default Global Group

Every peer starts in the **Default Global Group**, which has all four switches
**on** and cannot be edited or deleted. A server that has never had a policy
group created filters nothing at all, so existing deployments see no change in
behaviour, performance or traffic. Create a group only when you want to start
restricting something.

Moving devices into a group is explicit: they leave the Default Global Group,
and removing them returns them to it. A group is always deny-by-default — every
switch starts off when you create one.

Rules are re-evaluated live, so flipping a switch or moving a device takes
effect on the next packet, without a restart and without touching the device.

Groups live in `policy_groups.json` inside your `DATA_DIR` (mode 0600), which is
covered by the usual backup and restore flow.

## SSH Gateway (optional)

Enable with `-ssh` or `SSH_ENABLED=true`. This turns TunGuard into an SSH jump host so you can SSH into any connected peer through the server:

```bash
ssh -J admin@yourserver:2222 root@10.100.0.2
```

The SSH gateway authenticates with the **same login as the web dashboard** — if you change the username or password in **Settings → Dashboard Login**, the SSH access password changes with it. No separate `SSH_USER` / `SSH_PASSWORD` credentials are used.

You can also SSH directly from the web dashboard — click the **SSH** button next to any online peer to open a browser terminal.

The dashboard **Terminal** (and the SSH gateway prompt itself) has a built-in `ssh` client, so you can reach peers or any host the server can reach without a second terminal:

```text
ssh root@10.100.0.2        # interactive session to a peer
ssh laptop                 # a peer by its device label
ssh host uptime            # run one command and exit
```

`Ctrl-]` detaches an interactive session and returns to the TunGuard prompt. See [commands.md](commands.md#ssh-client) for the full option set.

## Domains

The domain proxy is **on by default** and stays completely out of the way
until you add a mapping — it binds no ports and makes no ACME call until the
first domain is configured. Set `DOMAIN_ENABLED=false` to turn it off. A
public domain is proxied to an existing **TRP** port mapping, or to a service
reachable over the tunnel (a `--wg ip:port` backend), and TLS is handled
automatically with a Let's Encrypt certificate (HTTP-01 challenge). Point the
domain's A/AAAA record at this server so ports 80 and 443 reach it.

On first use TunGuard detects the server's web stack:

- **nginx / Apache / Caddy / Traefik** — the mapping is written into that
  server's config and reloaded (introspected, never rewritten blindly);
- **otherwise** the built-in reverse proxy binds ports 80/443 itself.

Manage mappings from the console (`domain list|add|update|remove`), the
**Domains** page in the dashboard, or the API:

```bash
curl -u admin:pass -X POST http://localhost:9000/api/domain/add \
  -H "Content-Type: application/json" \
  -d '{"domain":"app.example.com","backend":"trp","proxy_ref":"<mapping id>"}'
```

```bash
curl -u admin:pass -X POST http://localhost:9000/api/domain/add \
  -H "Content-Type: application/json" \
  -d '{"domain":"api.example.com","backend":"wg","target_ip":"10.100.0.2","target_port":8080}'
```

See [commands.md](commands.md#domains-https-reverse-proxy) for the full CLI
reference and the `DOMAIN_*` settings table under [Configuration](#configuration).

## Running as a systemd Service

```bash
sudo cp tanguard.service /etc/systemd/system/
sudo mkdir -p /var/lib/tanguard
sudo systemctl daemon-reload
sudo systemctl enable tanguard
sudo systemctl start tanguard
```

### Updating to a new release

Re-run the installer (`curl -fsSL ...installer.sh | bash`). On an existing install it only replaces the binary and **keeps your service configuration untouched** — your custom ports, subnet, and credentials stay exactly as you configured them. Your data in `DATA_DIR` is never modified, and the installer saves a safety backup of it to `/var/backups/` first.

## Configuration

All settings are configured via environment variables.

| Variable | Default | Description |
|---|---|---|
| `WG_INTERFACE` | `wg0` | WireGuard interface name |
| `WG_LISTEN_PORT` | `13231` | WireGuard UDP port (the port clients connect to) |
| `WG_ADDRESS` | `10.100.0.1/24` | Server IP on the VPN subnet |
| `WG_SUBNET` | `10.100.0.0/24` | Subnet assigned to VPN clients |
| `WG_MTU` | `1420` | WireGuard MTU |
| `API_LISTEN` | `:9000` | Web dashboard + API address |
| `DATA_DIR` | `.` | Directory for keys and peer data |
| `EXTERNAL_NIC` | auto | External network interface for NAT (auto-detected) |
| `WEB_ENABLED` | `false` | Enable the web dashboard (or use `-web`) |
| `WEB_USERNAME` | `admin` | Dashboard login username (only used until changed from the dashboard) |
| `WEB_PASSWORD` | `tanguard` | Dashboard login password (only used until changed from the dashboard) |
| `SSH_ENABLED` | `false` | Enable SSH gateway (or use `-ssh`) |
| `SSH_LISTEN` | `:2222` | SSH gateway address |
| `SSH_KEY_FILE` | auto | SSH host key path (auto-generated if missing) |
| `TUNGARD_API_KEY` | — | API key for PHP / script integration (also settable per-request) |
| `DOMAIN_ENABLED` | `true` | HTTPS domain proxy. On by default; set to `false` to turn it off |
| `DOMAIN_HTTP_PORT` | `80` | Public HTTP port used for the ACME challenge and redirects |
| `DOMAIN_HTTPS_PORT` | `443` | Public HTTPS port of the domain proxy |
| `DOMAIN_CHALLENGE_PORT` | `8100` | Local port the Let's Encrypt HTTP-01 challenge answers on |

## Building from Source

```bash
git clone <repo> && cd tanguard
go build -o tanguard .
```

Requires Go 1.22+. The binary is statically linked — copy it to any Linux server.

## Backups

Updating TunGuard only replaces the binary — your peers, server key, dashboard login, and SSH host key are stored in `DATA_DIR` and are never touched by the installer or an update. Still, keep a backup before major changes.

### Download a backup (web dashboard)

Settings → **Backup & Restore** → **Download Backup** saves a `.tar.gz` containing:

- `peers.json` — all peers (including client private keys for generated configs)
- `server_private.key` — the server WireGuard key
- `web_credentials.json` — the hashed dashboard login
- `ssh_host_key` — the SSH gateway host key
- `api_key.json` — the API key
- `manifest.json` — backup metadata

### Restore a backup

Use the same **Restore Backup** button in Settings. Restoring:

1. Validates the archive before touching anything.
2. Replaces the state files in `DATA_DIR`.
3. Applies the restored key and peers to the **running** server immediately (no restart required).

If the restored server key differs from the current one, connected clients need to re-import their configs (the new server public key is shown after restore).

Restoring never touches the binary, the systemd service, or your firewall rules.

### CLI backup (terminal)

```bash
sudo tar -czf ~/tanguard-backup.tar.gz -C /var/lib/tanguard .
```

## Security Notes

- **Change the default passwords** (`WEB_PASSWORD`) in production. The dashboard forces you to set a new web login on first use; use `tanguard --reset` if you ever lose it. The SSH gateway shares this login.
- **Protect the API.** Every `/api/*` endpoint (except `/api/health`) now requires the dashboard login or an API key. Generate your API key in **Settings → API Key** and pass it as the `X-API-Key` header. Regenerate it any time it may have leaked.
- The web dashboard uses HTTP Basic Auth over plain HTTP by default. Put it behind a reverse proxy with TLS (e.g. Caddy, Nginx, or Traefik) for production use.
- The SSH gateway uses password auth by default. Consider key-based auth for production.
- Client private keys created by **Generate Config** are stored in `peers.json` (mode 0600, inside `DATA_DIR`) so configs can be re-downloaded / re-scanned from the dashboard. Manually added peers (public key only) have no stored client key.

## API Reference (curl)

All `/api/*` endpoints (except `/api/health`) require authentication. You can
authenticate either with the **dashboard login** (`-u admin:password`) or with
an **API key** from **Settings → API Key**, sent as the `X-API-Key` header (or
`Authorization: Bearer <key>`).

Get / regenerate your API key from the dashboard at **Settings → API Key**, or
from the terminal:

```bash
# Create / rotate the API key (dashboard login required)
curl -X POST -u admin:PASSWORD http://localhost:9000/api/key/regenerate
```

Then call the API with the key:

```bash
API_KEY="REPLACE_WITH_YOUR_KEY"

# Server info
curl -H "X-API-Key: $API_KEY" http://localhost:9000/api/status
curl -H "X-API-Key: $API_KEY" http://localhost:9000/api/server_key
curl -H "X-API-Key: $API_KEY" http://localhost:9000/api/peers

# Add a peer with an existing key
curl -X POST http://localhost:9000/api/peer/add \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"public_key":"PEER_PUBKEY_HEX","allowed_ip":"10.100.0.2/32","device_name":"my-device"}'

# Auto-generate a new client config (server creates keypair)
curl -X POST http://localhost:9000/api/peer/generate-config \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"device_name":"my-phone","server_host":"vpn.example.com"}'

# Re-download / re-render the full config (with the client PrivateKey) for a
# peer created via generate-config
curl -X POST http://localhost:9000/api/peer/config \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"public_key":"PEER_PUBKEY_HEX","server_host":"vpn.example.com"}'

# Remove a peer
curl -X POST http://localhost:9000/api/peer/remove \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"public_key":"PEER_PUBKEY_HEX"}'
```

Host facts, version and self-update:

```bash
# CPU, memory, disk and network counters
curl -H "X-API-Key: $API_KEY" http://localhost:9000/api/system

# The version this server is running, plus the latest published release.
# Add ?refresh=1 to query GitHub now instead of using the hourly cache.
curl -H "X-API-Key: $API_KEY" http://localhost:9000/api/version
curl -H "X-API-Key: $API_KEY" "http://localhost:9000/api/version?refresh=1"

# Download and install the release for this server's architecture
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:9000/api/update
```

Backups over the API, for automation that never opens the dashboard:

```bash
# The same .tar.gz the Settings page downloads
curl -H "X-API-Key: $API_KEY" -o backup.tar.gz \
  http://localhost:9000/api/backup/download

# Restore one: multipart upload under the field name "backup"
curl -X POST -H "X-API-Key: $API_KEY" -F backup=@backup.tar.gz \
  http://localhost:9000/api/backup/restore
```

Three endpoints take the **dashboard login only** and reject an API key, because
they hand out or replace the credentials themselves: `/api/key` (read the current
key), `/api/key/regenerate`, and `/api/web/credentials` (change the login).

`/api/health` stays open for uptime checks and exposes no sensitive data.

See `INTEGRATION.md` for the WebSocket SSH protocol and PHP integration.

## P2P and TRP API (curl)

These endpoints automate the mesh control plane and TCP relay, so provisioning
doesn't need the dashboard. They all require the same credentials as the rest of
`/api/*`.

They answer whenever the tun control plane is running, which is both modes:
`-mesh-only`, and a full WireGuard server too (`MESH_ENABLED` defaults to true,
so the mesh comes up automatically). With `MESH_ENABLED=false` the hub is never
started and every endpoint below returns `503 tun control plane is disabled` —
and in `-mesh-only` mode the process refuses to start at all.

Mutating calls are `POST` with a JSON body. A `GET` on them returns `405`.

```bash
API_KEY="REPLACE_WITH_YOUR_KEY"
H="X-API-Key: $API_KEY"
JSON="Content-Type: application/json"
API="http://localhost:9000"
```

### Nodes and groups

A node is a client allowed onto the mesh. Nodes that share a PSK form a group
and auto-mesh with each other; a node with no PSK gets a unique one. Every node
add returns the generated `psk` — save it, it's the join credential.

```bash
# Mesh state: enabled, node/group counts, listen addresses
curl -H "$H" $API/api/mesh/status

# List nodes. PSKs are masked; add ?show_psk=1 to reveal them
curl -H "$H" $API/api/mesh/nodes
curl -H "$H" "$API/api/mesh/nodes?show_psk=1"

# Devices bucketed by shared PSK, with per-group link counts
curl -H "$H" $API/api/mesh/groups

# Current direct and relayed links between nodes. Each link also carries the
# client's own link test: "tested" true and "rtt_ms" is the round trip each
# device measured to its peer. "direct" on its own only means a punch landed.
curl -H "$H" $API/api/mesh/links

# Add a node. Omit "psk" to have one generated.
# A "name" is only a label — it is NOT a unique key, and duplicates are allowed.
# The returned "id" is the handle every other call needs.
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/node/add \
  -d '{"name":"edge-a"}'
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/node/add \
  -d '{"name":"edge-a","psk":"shared-group-key"}'

# Remove a node, or reset it (clears its link state, keeps the record).
# Removing a node also releases every TRP mapping that targeted it.
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/node/remove \
  -d '{"id":"NODE_ID"}'
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/node/reset \
  -d '{"id":"NODE_ID"}'
```

### P2P: direct paths

Nodes in the same group are punched to each other automatically. These calls
force a re-punch, drop a group back to relayed, or take a node off the mesh
entirely. `p2p/connect` needs both nodes online — an offline or unknown id
returns `400 node offline`.

A direct path never passes through the server, so it cannot be filtered on the
way through. Two nodes whose devices are in **different policy groups** are
therefore never punched together, and `p2p/connect` refuses the pair with
`400 policy groups are isolated` — the same boundary the packet filter applies
to their relayed traffic. Put both devices in one group to link them.

```bash
# Force an immediate direct path between two nodes
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/p2p/connect \
  -d '{"a":"NODE_ID_A","b":"NODE_ID_B"}'

# Re-punch a whole group. "group" is the PSK.
# {"enable":false} tears the group's direct links down (relay only)
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/p2p/mesh \
  -d '{"group":"shared-group-key"}'
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/p2p/mesh \
  -d '{"group":"shared-group-key","enable":false}'

# Pin a relayed path src -> dst, or drop every link from src
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/relay/link \
  -d '{"src":"NODE_ID_A","dst":"NODE_ID_B"}'
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/relay/unlink \
  -d '{"src":"NODE_ID_A"}'

# Attach a node to the relay hub, or detach it.
# Both need the node connected - an offline or unknown id gives 400 node offline
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/relay/join  -d '{"id":"NODE_ID"}'
curl -X POST -H "$H" -H "$JSON" $API/api/mesh/relay/leave -d '{"id":"NODE_ID"}'
```

### TRP: TCP relay

A proxy listens locally on the hub and forwards each connection to
`target_ip:target_port` on the target node over its mesh path. Leave `bind_port`
as `""` to let the OS pick a free port — the chosen port comes back as
`bind_port` and in `public_url`. `"0"` is rejected; only an empty string means
auto-assign. `target_port` is always required and always numeric.

```bash
# List proxies, with live connection counts
curl -H "$H" $API/api/trp/proxies

# Auto-assigned listen port, forwarding to port 8022 on the node
curl -X POST -H "$H" -H "$JSON" $API/api/trp/proxy/add \
  -d '{"node_id":"NODE_ID","bind_port":"","target_port":"8022"}'

# Fixed listen port, and an explicit target address
curl -X POST -H "$H" -H "$JSON" $API/api/trp/proxy/add \
  -d '{"node_id":"NODE_ID","bind_ip":"0.0.0.0","bind_port":"18022","target_ip":"127.0.0.1","target_port":"8022"}'

# Remove a proxy
curl -X POST -H "$H" -H "$JSON" $API/api/trp/proxy/remove \
  -d '{"id":"PROXY_ID"}'
```

### Errors

Failures are JSON with an `error` field, so scripts can branch on them:

| Status | Meaning |
| --- | --- |
| `400` | Bad request — `id required`, `node_id required`, `bind_port`/`target_port` out of range, `unknown group`, `node offline`, or malformed JSON |
| `401` | Missing or invalid dashboard login / API key |
| `404` | No such node, proxy, or binding |
| `405` | `GET` used on a `POST`-only route |
| `503` | Mesh control plane not running — set `MESH_ENABLED=true` (the default), or start with `-mesh-only` |

### End-to-end example

```bash
#!/usr/bin/env bash
set -euo pipefail
API_KEY="REPLACE_WITH_YOUR_KEY"
API="http://localhost:9000"
field() { python3 -c "import json,sys;print(json.load(sys.stdin)['$1'])"; }

# Add a node and keep its id and psk
ADDED="$(curl -sS -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" "$API/api/mesh/node/add" \
  -d '{"name":"edge-a"}')"
NODE_ID="$(printf '%s' "$ADDED" | field id)"
PSK="$(printf '%s' "$ADDED" | field psk)"
echo "node=$NODE_ID psk=$PSK"

# Expose a service running on the node
PROXY="$(curl -sS -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" "$API/api/trp/proxy/add" \
  -d "{\"node_id\":\"$NODE_ID\",\"bind_port\":\"\",\"target_port\":\"8022\"}")"
echo "reachable at $(printf '%s' "$PROXY" | field public_url)"

# Tear down
curl -sS -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" "$API/api/trp/proxy/remove" \
  -d "{\"id\":\"$(printf '%s' "$PROXY" | field id)\"}"
curl -sS -X POST -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" "$API/api/mesh/node/remove" \
  -d "{\"id\":\"$NODE_ID\"}"
```

Note: removing a node releases every TRP mapping that pointed at it and frees
the ports they were holding. A mapping whose target node no longer exists could
never forward again, so it is removed with the node rather than left holding a
port.

## Policy Groups API (curl)

These endpoints manage the same filter as the **Policy Groups** dashboard page.
They use the same credentials as the rest of `/api/*`, and `GET` on a
`POST`-only route returns `405`.

```bash
API_KEY="REPLACE_WITH_YOUR_KEY"
H="X-API-Key: $API_KEY"
JSON="Content-Type: application/json"
API="http://localhost:9000"
```

`GET /api/policy/groups` returns every group with its members, the full peer
list (each peer's `group_id` and `group_name` included), and the drop counters
the page displays:

```bash
curl -H "$H" $API/api/policy/groups
```

```json
{
  "groups": [
    { "id": "default", "name": "Default Global Group", "allow_inter_device": true,
      "allow_p2p_mesh": true, "allow_trp": true, "allow_wg_access": true,
      "builtin": true, "devices": [ { "public_key": "…", "allowed_ip": "10.100.0.2/32" } ] },
    { "id": "7f3a1c22", "name": "Guests", "allow_inter_device": false,
      "allow_p2p_mesh": false, "allow_trp": false, "allow_wg_access": true, "devices": [] }
  ],
  "peers": [ /* every peer, with group_id / group_name */ ],
  "drop_count": { "inter_device": 0, "internet": 0 }
}
```

Creating a group: every omitted switch is **off**, so this group can talk to the
internet but nothing else. `allow_inter_device` opens traffic between devices of
**this group only** — it never reaches into or out of another group:

```bash
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/create \
  -d '{"name":"Guests","allow_wg_access":true}'
```

Updating is partial — **only the switches you send are changed**, so flipping
one rule never silently clears the other three:

```bash
# Turn on inter-device traffic, leave the other three as they are
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/update \
  -d '{"id":"7f3a1c22","allow_inter_device":true}'
```

Moving devices in and out. `assign` is idempotent, so re-sending a device that
is already in the group is not an error. Assigning moves a device *out* of
whatever group it was in, including the default one:

```bash
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/assign \
  -d '{"id":"7f3a1c22","devices":["PEER_PUBKEY_HEX","OTHER_PUBKEY_HEX"]}'

# Back to the Default Global Group
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/unassign \
  -d '{"id":"7f3a1c22","devices":["PEER_PUBKEY_HEX"]}
```

Both endpoints take WireGuard peers, named by public key. A tun-client device
that has no peer of its own is named by its device id instead, and moves through
its own pair of endpoints:

```bash
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/assign-device \
  -d '{"id":"7f3a1c22","devices":["abcd1234"]}'

curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/unassign-device \
  -d '{"id":"7f3a1c22","devices":["abcd1234"]}'
```

A device that is both a peer and a tun client is grouped by its public key, and
its device id is refused by `assign-device`, so one device is never in two groups
at once. The device list at `GET /api/policy/groups` returns both kinds, with
`client_device` set on the ones that have no peer.

A group must be empty before it can be deleted:

```bash
curl -X POST -H "$H" -H "$JSON" $API/api/policy/group/delete -d '{"id":"7f3a1c22"}'
```

`POST /api/policy/apply` declares the whole policy at once, which is the
provisioning call — it replaces all custom groups and every membership in a
single atomic step. Omit `id` to have one generated, and omit a switch to leave
it off:

```bash
curl -X POST -H "$H" -H "$JSON" $API/api/policy/apply \
  -d '{"groups":[{"name":"Guests","allow_wg_access":true},
                 {"name":"IoT","allow_inter_device":true}],
       "assign":{"PEER_PUBKEY_HEX":"GROUP_ID","OTHER_PUBKEY_HEX":"GROUP_ID"}}'
```

Send `{"groups":[],"assign":{}}` to return the server to unrestricted. An
invalid payload is rejected whole: nothing is changed if any group, name,
duplicate or unknown membership is bad. The default group is reserved — it can
never be declared, overridden or deleted, which is what guarantees an apply can
never lock every device out.

### Policy API errors

| Status | Meaning |
| --- | --- |
| `400` | Bad payload — `name required`, `group not found`, `duplicate group id`, `the default group is managed automatically and cannot be declared`, an empty group name, or a membership naming an unknown device or group |
| `401` | Missing or invalid dashboard login / API key |
| `405` | `GET` used on a `POST`-only route |

## License

MIT
