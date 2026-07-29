# StackWISP - Userspace WireGuard Server

Drop-in replacement for kernel WireGuard. No `apt install wireguard` needed.

## Quick Start

```bash
# Build (already done, binary is ./stackwg)
cd stackwg
go build -o stackwg .

# Run as root (needs TUN device access)
sudo ./stackwg
```

The server starts two services:
- **WireGuard UDP** on port `13231` (configurable)
- **HTTP API** on port `9000` (for PHP integration)

## Configuration

Copy `.env.example` to `.env` or set environment variables:

| Variable | Default | Description |
|---|---|---|
| `WG_INTERFACE` | `wg0` | Virtual interface name |
| `WG_LISTEN_PORT` | `13231` | WireGuard UDP port |
| `WG_ADDRESS` | `10.100.0.1/24` | Server IP on WireGuard subnet |
| `WG_SUBNET` | `10.100.0.0/24` | Client subnet for NAT |
| `WG_MTU` | `1420` | WireGuard MTU |
| `API_LISTEN` | `:9000` | HTTP API listen address |
| `DATA_DIR` | `.` | Directory for keys and peer data |
| `WG_LOG_LEVEL` | `2` | 0=quiet, 1=error, 2=info, 3=debug |
| `EXTERNAL_NIC` | auto | External NIC for NAT (auto-detected) |

## HTTP API

All endpoints accept/return JSON.

### Health Check
```bash
curl http://localhost:9000/api/health
# {"status":"ok"}
```

### Server Status
```bash
curl http://localhost:9000/api/status
# {"server_public_key":"...","listen_port":13231,"peers":[...],"peer_count":2}
```

### Server Public Key
```bash
curl http://localhost:9000/api/server_key
# {"public_key":"abc123...","listen_port":"13231"}
```

### Add Peer
```bash
curl -X POST http://localhost:9000/api/peer/add \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "ROUTER_PUBLIC_KEY_HEX",
    "allowed_ip": "10.100.0.2/32",
    "device_id": "device-uuid-here",
    "device_name": "sirari-mt-49152"
  }'
# {"success":true,"public_key":"...","allowed_ip":"...","device_id":"..."}
```

### Remove Peer
```bash
curl -X POST http://localhost:9000/api/peer/remove \
  -H "Content-Type: application/json" \
  -d '{"public_key": "ROUTER_PUBLIC_KEY_HEX"}'
# {"success":true,"public_key":"..."}
```

### List Peers
```bash
curl http://localhost:9000/api/peers
# {"peers":[{"public_key":"...","endpoint":"1.2.3.4:51820","latest_handshake":1234567890,"tx_bytes":1234,"rx_bytes":5678}],"peer_count":1}
```

## PHP Integration

The PHP app currently calls `wg` shell commands via `exec()`. To switch to the Go API:

### Step 1: Include the helper
```php
// In api/mikrotik.php, near the top:
require_once __DIR__ . '/../stackwg/stackwg_api.php';
```

### Step 2: Replace function calls

**Before** (shell exec with sudo):
```php
function addWireGuardPeer($peerPubKey, $allowedIP) {
    $escaped = escapeshellarg($peerPubKey);
    $ipEsc = escapeshellarg("$allowedIP/32");
    exec("echo 'jackal' | sudo -S wg set wg0 peer $escaped allowed-ips $ipEsc 2>&1", $output, $returnCode);
    return $returnCode === 0;
}
```

**After** (HTTP API call):
```php
function addWireGuardPeer($peerPubKey, $allowedIP) {
    return stackwg_addPeer($peerPubKey, $allowedIP);
}
```

### All replacements:

| Original Function | StackWISP Replacement |
|---|---|
| `addWireGuardPeer($key, $ip)` | `stackwg_addPeer($key, $ip)` |
| `removeWireGuardPeer($key)` | `stackwg_removePeer($key)` |
| `peerExists($key)` | `stackwg_peerExists($key)` |
| `checkWgHandshake($key)` | `stackwg_checkHandshake($key)` |
| `getServerPublicKey()` | `stackwg_getServerPublicKey()` |
| `getServerWgPort()` | `stackwg_getServerWgPort()` |

### Or use the class directly:
```php
$api = new StackWGAPI(); // defaults to http://127.0.0.1:9000

$api->addPeer($pubKey, '10.100.0.2/32', $deviceId);
$api->removePeer($pubKey);
$api->peerExists($pubKey);      // bool
$api->hasRecentHandshake($pubKey); // bool (within 180s)
$api->getServerPublicKey();      // string
$api->getStatus();               // array
```

## Run as systemd Service

```bash
sudo cp stackwg.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable stackwg
sudo systemctl start stackwg
sudo systemctl status stackwg
```

## What This Replaces

| Before | After |
|---|---|
| `apt install wireguard wireguard-tools` | `go build -o stackwg .` |
| `sudo wg set wg0 peer ...` | `POST /api/peer/add` |
| `sudo wg show wg0` | `GET /api/status` |
| `wg show wg0 public-key` | `GET /api/server_key` |
| `systemctl enable wg-quick@wg0` | `systemctl enable stackwg` |
| `/etc/wireguard/wg0.conf` | `peers.json` (auto-managed) |

## Files

```
stackwg/
├── stackwg              # Compiled binary (9.8MB, statically linked)
├── main.go              # Entry point
├── wg.go                # WireGuard device management
├── api.go               # HTTP API handlers
├── peer_store.go        # Peer persistence (peers.json)
├── crypto.go            # Key generation (Curve25519)
├── nat.go               # iptables NAT setup
├── config.go            # Configuration
├── fileutil.go          # File I/O helpers
├── stackwg_api.php      # PHP drop-in helper
├── stackwg.service      # systemd service file
├── .env.example         # Configuration template
├── go.mod / go.sum      # Go dependencies
└── peers.json           # Persisted peer state (auto-created)
```

## Troubleshooting

### "operation not permitted" on startup
The binary needs root access to create TUN devices. Run with `sudo ./stackwg`.

### Peers not connecting
1. Check the server's public key: `curl localhost:9000/api/server_key`
2. Make sure the router's WireGuard endpoint points to the server's public IP and port 13231
3. Check firewall: `sudo ufw allow 13231/udp`

### No internet access for WireGuard clients
The Go binary sets up iptables NAT automatically. If it doesn't work:
```bash
# Manual check:
sudo iptables -t nat -L -n | grep MASQUERADE
sudo cat /proc/sys/net/ipv4/ip_forward  # should be 1
```

### PHP can't reach the API
Ensure stackwg is running: `curl localhost:9000/api/health`
If running behind a firewall, ensure port 9000 is accessible from the PHP server (usually localhost only).
