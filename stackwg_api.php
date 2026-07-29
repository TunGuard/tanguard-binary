<?php
/**
 * stackwg_api.php - PHP helper for the stackwg userspace WireGuard server
 *
 * Drop-in replacement for all `wg` shell_exec calls in mikrotik.php and wireguard_register.php.
 * Calls the Go HTTP API on localhost:9000 instead of running `wg` commands.
 *
 * USAGE:
 *   require_once __DIR__ . '/../stackwg/stackwg_api.php';
 *
 *   $api = new StackWGAPI();
 *   $api->addPeer($pubKey, $allowedIP, $deviceId);
 *   $api->removePeer($pubKey);
 *   $api->peerExists($pubKey);
 *   $api->getServerPublicKey();
 *   $api->getServerListenPort();
 *   $api->getPeerHandshake($pubKey);
 *   $api->getStatus();
 */

class StackWGAPI {
    private string $baseUrl;

    public function __construct(string $apiUrl = 'http://127.0.0.1:9000') {
        $this->baseUrl = rtrim($apiUrl, '/');
    }

    private function get(string $path): ?array {
        $url = $this->baseUrl . $path;
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 5,
                'header' => "Content-Type: application/json\r\n",
            ],
        ]);
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) return null;
        return json_decode($resp, true);
    }

    private function post(string $path, array $data = []): ?array {
        $url = $this->baseUrl . $path;
        $payload = json_encode($data);
        $ctx = stream_context_create([
            'http' => [
                'method' => 'POST',
                'timeout' => 5,
                'header' => "Content-Type: application/json\r\n",
                'content' => $payload,
            ],
        ]);
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) return null;
        return json_decode($resp, true);
    }

    /**
     * Check if the stackwg server is running and healthy.
     */
    public function isHealthy(): bool {
        $r = $this->get('/api/health');
        return isset($r['status']) && $r['status'] === 'ok';
    }

    /**
     * Get the server's WireGuard public key.
     */
    public function getServerPublicKey(): ?string {
        $r = $this->get('/api/server_key');
        if (!$r || !isset($r['public_key'])) return null;
        return $r['public_key'];
    }

    /**
     * Get the server's WireGuard listen port.
     */
    public function getServerListenPort(): ?int {
        $r = $this->get('/api/server_key');
        if (!$r || !isset($r['listen_port'])) return null;
        return intval($r['listen_port']);
    }

    /**
     * Add a WireGuard peer.
     *
     * @param string $publicKey  Peer's WireGuard public key (hex)
     * @param string $allowedIP  Allowed IP with CIDR (e.g. "10.100.0.2/32")
     * @param string $deviceId   Device ID for tracking (optional)
     * @param string $deviceName Device name for tracking (optional)
     * @param string $psk        Pre-shared key (optional)
     */
    public function addPeer(
        string $publicKey,
        string $allowedIP,
        string $deviceId = '',
        string $deviceName = '',
        string $psk = ''
    ): bool {
        $r = $this->post('/api/peer/add', [
            'public_key'    => $publicKey,
            'allowed_ip'    => $allowedIP,
            'device_id'     => $deviceId,
            'device_name'   => $deviceName,
            'preshared_key' => $psk,
        ]);
        return isset($r['success']) && $r['success'] === true;
    }

    /**
     * Remove a WireGuard peer.
     */
    public function removePeer(string $publicKey): bool {
        $r = $this->post('/api/peer/remove', [
            'public_key' => $publicKey,
        ]);
        return isset($r['success']) && $r['success'] === true;
    }

    /**
     * Check if a peer exists (by public key).
     */
    public function peerExists(string $publicKey): bool {
        $status = $this->getStatus();
        if (!$status || !isset($status['peers'])) return false;
        foreach ($status['peers'] as $peer) {
            if (($peer['public_key'] ?? '') === $publicKey) return true;
        }
        return false;
    }

    /**
     * Get the timestamp of the latest handshake for a peer (unix seconds).
     * Returns 0 if no handshake has occurred.
     */
    public function getPeerHandshake(string $publicKey): int {
        $status = $this->getStatus();
        if (!$status || !isset($status['peers'])) return 0;
        foreach ($status['peers'] as $peer) {
            if (($peer['public_key'] ?? '') === $publicKey) {
                return intval($peer['latest_handshake'] ?? 0);
            }
        }
        return 0;
    }

    /**
     * Check if a peer had a recent handshake (within $within seconds).
     */
    public function hasRecentHandshake(string $publicKey, int $within = 180): bool {
        $ts = $this->getPeerHandshake($publicKey);
        if ($ts === 0) return false;
        return (time() - $ts) < $within;
    }

    /**
     * Get full server and peer status.
     */
    public function getStatus(): ?array {
        return $this->get('/api/status');
    }

    /**
     * Get list of all peers with metadata.
     */
    public function getPeers(): array {
        $r = $this->get('/api/peers');
        return $r['peers'] ?? [];
    }
}

// ==========================================
// DROP-IN REPLACEMENT FUNCTIONS
// ==========================================
// These match the function signatures used in mikrotik.php and wireguard_register.php.
// Replace the original functions with these and the `exec()` calls are eliminated.

/**
 * Replacement for addWireGuardPeer() in mikrotik.php.
 *
 * BEFORE: exec("echo 'jackal' | sudo -S wg set wg0 peer $escaped allowed-ips $ipEsc 2>&1", ...)
 * AFTER:  stackwg_addPeer($peerPubKey, $allowedIP)
 */
function stackwg_addPeer(string $peerPubKey, string $allowedIP): bool {
    $api = new StackWGAPI();
    return $api->addPeer($peerPubKey, "$allowedIP/32");
}

/**
 * Replacement for removeWireGuardPeer() in mikrotik.php.
 *
 * BEFORE: exec("echo 'jackal' | sudo -S wg set wg0 peer $escaped remove 2>&1", ...)
 * AFTER:  stackwg_removePeer($peerPubKey)
 */
function stackwg_removePeer(string $peerPubKey): bool {
    $api = new StackWGAPI();
    return $api->removePeer($peerPubKey);
}

/**
 * Replacement for peerExists() in mikrotik.php.
 *
 * BEFORE: exec("wg show wg0 peers | grep -c " . escapeshellarg($peerPubKey), ...)
 * AFTER:  stackwg_peerExists($peerPubKey)
 */
function stackwg_peerExists(string $peerPubKey): bool {
    $api = new StackWGAPI();
    return $api->peerExists($peerPubKey);
}

/**
 * Replacement for checkWgHandshake() in mikrotik.php.
 *
 * BEFORE: exec("wg show wg0 latest-handshakes | grep " . escapeshellarg($peerPubKey), ...)
 * AFTER:  stackwg_checkHandshake($peerPubKey, $within)
 */
function stackwg_checkHandshake(string $peerPubKey, int $within = 180): bool {
    $api = new StackWGAPI();
    return $api->hasRecentHandshake($peerPubKey, $within);
}

/**
 * Replacement for getServerPublicKey() in mikrotik.php.
 *
 * BEFORE: shell_exec('wg show wg0 public-key 2>/dev/null')
 * AFTER:  stackwg_getServerPublicKey()
 */
function stackwg_getServerPublicKey(): ?string {
    $api = new StackWGAPI();
    return $api->getServerPublicKey();
}

/**
 * Replacement for getServerWgPort() in mikrotik.php.
 *
 * BEFORE: exec("wg show wg0 listen-port 2>/dev/null", ...)
 * AFTER:  stackwg_getServerWgPort()
 */
function stackwg_getServerWgPort(): int {
    $api = new StackWGAPI();
    return $api->getServerListenPort() ?? 13231;
}
