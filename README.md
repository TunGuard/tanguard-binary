# TunGuard

[![Go Version](https://img.shields.io/github/go-mod/go-version/TunGuard/tanguard-binary)](https://golang.org)
[![License](https://img.shields.io/github/license/TunGuard/tanguard-binary)](LICENSE)
[![Release](https://img.shields.io/github/v/release/TunGuard/tanguard-binary)](https://github.com/TunGuard/tanguard-binary/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/TunGuard/tanguard-binary/release.yml?branch=main)](https://github.com/TunGuard/tanguard-binary/actions)

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

The dashboard runs on port **9000** (same port as the API). It is **disabled by default** — enable it with `-web` or `WEB_ENABLED=true`. It has three sections:

| Section | What you can do |
|---|---|
| **Dashboard** | Server status, peer count, data transfer totals |
| **Peers** | List peers, add/generate configs, view status, download configs, scan QR codes, remove peers |
| **Settings** | Reference of all configuration options |

The status page refreshes every 10 seconds. You'll see transfer stats, last handshake times, and online/offline status for each peer.

### Changing the dashboard login

When you log in with the default `admin` / `tanguard` credentials for the first time, you are taken straight to a screen that requires you to set a new username and password before you can use the dashboard.

You can change the dashboard login again at any time under **Settings → Dashboard Login**. The new credentials are saved (hashed) in `web_credentials.json` inside your `DATA_DIR` and take effect immediately.

### Forgotten dashboard password

If you forget the dashboard password, reset it from the terminal:

```bash
sudo ./tanguard --reset
```

This removes the stored login and restores the default `admin` / `tanguard`. Start the server again and log in to set a new password.

## SSH Gateway (optional)

Enable with `-ssh` or `SSH_ENABLED=true`. This turns TunGuard into an SSH jump host so you can SSH into any connected peer through the server:

```bash
ssh -J admin@yourserver:2222 root@10.100.0.2
```

The SSH gateway authenticates with the **same login as the web dashboard** — if you change the username or password in **Settings → Dashboard Login**, the SSH access password changes with it. No separate `SSH_USER` / `SSH_PASSWORD` credentials are used.

You can also SSH directly from the web dashboard — click the **SSH** button next to any online peer to open a browser terminal.

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

`/api/health` stays open for uptime checks and exposes no sensitive data.

See `INTEGRATION.md` for the WebSocket SSH protocol and PHP integration.

## License

MIT
