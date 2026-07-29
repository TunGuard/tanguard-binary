# Integration Guide

PHP helper and systemd service for TunGuard.

## Files

- `tanguard_api.php` — PHP class & functions to call the TunGuard HTTP API
- `tanguard.service` — systemd service unit

## PHP Integration

```php
require_once '/path/to/tanguard_api.php';

$api = new TunGuardAPI(); // defaults to http://127.0.0.1:9000

$api->addPeer($pubKey, '10.100.0.2/32', $deviceId);
$api->removePeer($pubKey);
$api->peerExists($pubKey);
$api->hasRecentHandshake($pubKey); // bool, within 180s
$api->getServerPublicKey();
$api->getStatus();
```

Or use the standalone functions:

```php
tanguard_addPeer($pubKey, '10.100.0.2');
tanguard_removePeer($pubKey);
tanguard_peerExists($pubKey);
tanguard_checkHandshake($pubKey);
tanguard_getServerPublicKey();
tanguard_getServerWgPort();
```

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
