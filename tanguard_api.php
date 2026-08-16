<?php
/**
 * tanguard_api.php - PHP helper for the TunGuard userspace WireGuard server
 *
 * Calls the Go HTTP API instead of running `wg` shell commands.
 *
 * USAGE:
 *   require_once __DIR__ . '/tanguard_api.php';
 *
 *   $api = new TunGuardAPI('http://127.0.0.1:9000', 'YOUR_API_KEY');
 *   $api->addPeer($pubKey, $allowedIP, $deviceId);
 *   $api->removePeer($pubKey);
 *   $api->getServerPublicKey();
 *
 * The API key can also be set via the TUNGARD_API_KEY environment variable.
 * If no key is given, the dashboard login (HTTP Basic Auth) is required to
 * call every endpoint except /api/health, so supply the key in production.
 */

class TunGuardAPI {
    private string $baseUrl;
    private string $apiKey;

    public function __construct(string $apiUrl = 'http://127.0.0.1:9000', ?string $apiKey = null) {
        $this->baseUrl = rtrim($apiUrl, '/');
        $envKey = getenv('TUNGARD_API_KEY');
        $this->apiKey = $apiKey ?? ($envKey !== false ? $envKey : '');
    }

    private function authHeader(): string {
        if ($this->apiKey === '') return '';
        return 'X-API-Key: ' . $this->apiKey . "\r\n";
    }

    private function get(string $path): ?array {
        $url = $this->baseUrl . $path;
        $ctx = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 5,
                'header' => "Content-Type: application/json\r\n" . $this->authHeader(),
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
                'header' => "Content-Type: application/json\r\n" . $this->authHeader(),
                'content' => $payload,
            ],
        ]);
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) return null;
        return json_decode($resp, true);
    }

    public function isHealthy(): bool {
        $r = $this->get('/api/health');
        return isset($r['status']) && $r['status'] === 'ok';
    }

    public function getServerPublicKey(): ?string {
        $r = $this->get('/api/server_key');
        if (!$r || !isset($r['public_key'])) return null;
        return $r['public_key'];
    }

    public function getServerListenPort(): ?int {
        $r = $this->get('/api/server_key');
        if (!$r || !isset($r['listen_port'])) return null;
        return intval($r['listen_port']);
    }

    public function addPeer(
        string $publicKey,
        string $allowedIP,
        string $deviceId = '',
        string $deviceName = '',
        string $psk = ''
    ): bool {
        $r = $this->post('/api/peer/add', [
            'public_key'     => $publicKey,
            'allowed_ip'     => $allowedIP,
            'device_id'      => $deviceId,
            'device_name'    => $deviceName,
            'preshared_key'  => $psk,
        ]);
        return isset($r['success']) && $r['success'] === true;
    }

    public function removePeer(string $publicKey): bool {
        $r = $this->post('/api/peer/remove', [
            'public_key' => $publicKey,
        ]);
        return isset($r['success']) && $r['success'] === true;
    }

    public function peerExists(string $publicKey): bool {
        $status = $this->getStatus();
        if (!$status || !isset($status['peers'])) return false;
        foreach ($status['peers'] as $peer) {
            if (($peer['public_key'] ?? '') === $publicKey) return true;
        }
        return false;
    }

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

    public function hasRecentHandshake(string $publicKey, int $within = 180): bool {
        $ts = $this->getPeerHandshake($publicKey);
        if ($ts === 0) return false;
        return (time() - $ts) < $within;
    }

    public function getStatus(): ?array {
        return $this->get('/api/status');
    }

    public function getPeers(): array {
        $r = $this->get('/api/peers');
        return $r['peers'] ?? [];
    }
}

function tanguard_addPeer(string $peerPubKey, string $allowedIP): bool {
    $api = new TunGuardAPI();
    return $api->addPeer($peerPubKey, "$allowedIP/32");
}

function tanguard_removePeer(string $peerPubKey): bool {
    $api = new TunGuardAPI();
    return $api->removePeer($peerPubKey);
}

function tanguard_peerExists(string $peerPubKey): bool {
    $api = new TunGuardAPI();
    return $api->peerExists($peerPubKey);
}

function tanguard_checkHandshake(string $peerPubKey, int $within = 180): bool {
    $api = new TunGuardAPI();
    return $api->hasRecentHandshake($peerPubKey, $within);
}

function tanguard_getServerPublicKey(): ?string {
    $api = new TunGuardAPI();
    return $api->getServerPublicKey();
}

function tanguard_getServerWgPort(): int {
    $api = new TunGuardAPI();
    return $api->getServerListenPort() ?? 13231;
}
