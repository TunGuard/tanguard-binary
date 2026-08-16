# Integration Guide

PHP helper and systemd service for TunGuard.

## Files

- `tanguard_api.php` — PHP class & functions to call the TunGuard HTTP API
- `tanguard.service` — systemd service unit

## PHP Integration

The API is protected: every `/api/*` endpoint (except `/api/health`) requires a
valid **API key** (from **Settings → API Key** in the dashboard) or the
dashboard login. Pass the API key to the constructor, or set it once via the
`TUNGARD_API_KEY` environment variable:

```php
require_once '/path/to/tanguard_api.php';

$api = new TunGuardAPI('http://127.0.0.1:9000', 'YOUR_API_KEY');

$api->addPeer($pubKey, '10.100.0.2/32', $deviceId);
$api->removePeer($pubKey);
$api->peerExists($pubKey);
$api->hasRecentHandshake($pubKey); // bool, within 180s
$api->getServerPublicKey();
$api->getStatus();
```

Or use the standalone functions (the key is taken from the `TUNGARD_API_KEY`
environment variable):

```php
putenv('TUNGARD_API_KEY=YOUR_API_KEY');
require_once '/path/to/tanguard_api.php';

// Add a peer
if (tanguard_addPeer('PEER_PUBKEY_HEX', '10.100.0.2')) {
    echo "Peer added successfully\n";
}

// Check if peer exists
if (tanguard_peerExists('PEER_PUBKEY_HEX')) {
    echo "Peer is registered\n";
}

// Check recent handshake (within last 180s)
if (tanguard_checkHandshake('PEER_PUBKEY_HEX')) {
    echo "Peer has connected recently\n";
}

// Get server info
$pubkey = tanguard_getServerPublicKey();
$port   = tanguard_getServerWgPort();
echo "Server: $pubkey on UDP $port\n";

// Remove a peer
tanguard_removePeer('PEER_PUBKEY_HEX');
```

The key is sent on every request as the `X-API-Key` header. If you leave it
empty, only the dashboard login can call the API.

## systemd Service

```bash
sudo cp tanguard.service /etc/systemd/system/
sudo mkdir -p /var/lib/tanguard
sudo systemctl daemon-reload
sudo systemctl enable tanguard
sudo systemctl start tanguard
sudo systemctl status tanguard
```

## Configuration

See the [README](README.md#configuration) for all environment variables.
