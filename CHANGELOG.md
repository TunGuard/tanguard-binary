# Changelog

All notable changes to TunGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-08-18

### Fixed

- **Peers page "last handshake" time now shows second precision.** The `timeAgo`
  display previously dropped seconds for durations between 1–59 minutes (e.g.
  showing "1m ago" at 97 seconds). It now shows the exact time like "1m37s ago",
  matching the `STALE_97S` monitor events.

## [2.2.0] - 2026-08-17

### Added

- **TLS/HTTPS support.** Set `TLS_CERT_FILE` and `TLS_KEY_FILE` environment
  variables to serve the API and web dashboard over HTTPS. When unset, the
  server falls back to plain HTTP.

### Changed

- **CPU percent is now sampled in a background goroutine** every 3 seconds
  instead of blocking the request handler for up to 250 ms on every
  `/api/system` call.
- **Dashboard status polling is conditional.** The sidebar status interval is
  only active on non-dashboard pages; the dashboard's own `loadDashboard()`
  reads the same cached status directly, eliminating duplicate `/api/status`
  requests.
- **HTTP server hardened with timeouts:** `ReadTimeout: 15s`,
  `WriteTimeout: 60s`, `IdleTimeout: 120s`.
- **Request body size capped at 1 MB** via `limitedDecoder()` applied to all
  JSON-decoded API endpoints.
- **Network data size limits:** GitHub API responses capped at 1 MB and update
  downloads capped at 256 MB via `io.LimitReader`.
- Version refresh (`?refresh=1`) is now synchronous — the existing `checking`
  guard prevents duplicate GitHub API calls.

### Fixed

- **WebSocket write race in SSH terminal.** All `conn.WriteJSON` calls are
  serialized through a per-connection `sync.Mutex` (`wsWrite` helper).
- **SSH client leak on reconnect.** `startSSHSession` now tracks the
  `*ssh.Client` in the outer scope and closes the previous client alongside
  the session and stdin when a new connection is established.
- **WebSocket read buffer overflow.** Added `conn.SetReadLimit(64 KB)` to
  prevent unbounded memory growth from malicious input.
- **`readFirstLine` double conversion.** Fixed redundant `string()` wrapping
  of `os.ReadFile` output in `stats.go`.

## [2.1.3] - 2026-08-17

### Changed

- Clicking the version badge now triggers a live GitHub release check
  instead of only reading from the background cache.

## [2.1.2] - 2026-08-16

### Fixed

- **Web SSH terminal input dead after login.** The password prompt handler was
  overwriting `term.onData` and never restoring it, so shell input after
  authentication went nowhere.

## [2.1.1] - 2026-08-16

### Added

- **Network traffic graph on the dashboard.** The System card now shows a
  real-time Chart.js line graph tracking RX/TX rates for tun0, wgo, and eth0
  interfaces, with up to 60 data points (10 minutes at 10-second intervals).
- Network interfaces are now filtered to show only **tun0, wgo, and eth0**
  instead of every interface on the host.
- **In-app update checker.** The topbar shows a version badge that
  auto-checks GitHub releases every hour in a background goroutine with zero
  request-path latency. Clicking the badge opens a modal with release notes
  and a one-click install button that downloads the correct architecture
  binary, replaces the running executable, and restarts the server.

### Fixed

- **Dashboard no longer spams "unauthorized" error toasts.** Removed the
  `WWW-Authenticate` header from API 401 responses, which was causing the
  browser to clear its cached Basic Auth credentials on transient failures,
  creating an auth-loop. `fetchAPI` now silently returns `null` on non-200
  responses; all callers already handle this gracefully.
- **SSH direct-tcpip now handles IPv6 addresses correctly.** The connection
  target is formatted with `net.JoinHostPort` instead of `fmt.Sprintf("%s:%d")`,
  which produced invalid addresses for IPv6 hosts.
- **SSH WebSocket reconnect no longer leaks sessions.** Starting a new SSH
  session via the WebSocket terminal now properly closes the previous session
  and stdin pipe before creating new ones.

## [2.1.0] - 2026-08-16

### Added

- **API key authentication.** Every `/api/*` endpoint (except `/api/health`)
  now requires either the dashboard login (HTTP Basic Auth) or a valid API key
  sent as the `X-API-Key` header (or `Authorization: Bearer`). Previously the
  API was completely open.
- **API key management in the dashboard** (Settings → API Key): view, copy,
  and regenerate the key. The key is stored in `api_key.json` inside `DATA_DIR`
  (mode 0600) and regenerating immediately invalidates the old one.
- The API key is included in **backup & restore**, so a restored backup also
  restores the key in use at backup time.
- The PHP helper (`tanguard_api.php`) now sends the API key via the
  `TUNGARD_API_KEY` environment variable or the `TunGuardAPI` constructor
  argument.

### Changed

- **The SSH gateway now authenticates with the same login as the web
  dashboard.** Changing the username or password under Settings → Dashboard
  Login immediately applies to SSH jump-host access too. The `SSH_USER` and
  `SSH_PASSWORD` environment variables are no longer used.

## [2.0.0] - 2026-08-14

### Added

- **Completely redesigned web dashboard** with a custom Material Design-style
  theme. The Bootstrap, AdminLTE, jQuery, and Font Awesome CDN dependencies are
  gone — the dashboard now works fully offline, styled with a single bundled
  `style.css`.
- **Live server status panel in the sidebar** showing listen port, subnet, and
  peer counts (total + online), with a peer-count badge on the Peers nav item.
  It refreshes automatically every 10 seconds.
- **Type-to-confirm peer removal.** Removing a peer now requires typing the
  device name before the removal button becomes available, preventing
  accidental deletions.
- **XSS hardening** in the dashboard: all user-supplied values (device names,
  public keys, endpoints) are HTML-escaped before rendering.

### Changed

- Peers are now applied to the WireGuard device **incrementally** via `IpcSet`
  instead of a full `replace_peers` reconfiguration, so peer changes no longer
  rebind the listening socket.
- Peer add/remove and config generation are serialized on a mutex, and the API
  now rejects duplicate public keys and already-assigned IPs with clear errors
  instead of silently overwriting state.

### Fixed

- Adding or removing a peer no longer resets the session of every connected
  device. Existing devices stay connected when a new device joins.
- Duplicate client IPs are now rejected on peer add, and auto-assigned IPs are
  allocated atomically, so a new device can no longer take over an IP that is
  already in use by an older device.

## [1.3.0] - 2026-08-07

### Added

- **Backup & Restore** from the web dashboard (Settings → Backup & Restore):
  - `GET /api/backup/download` returns a `.tar.gz` of `peers.json`, `server_private.key`, `web_credentials.json`, and `ssh_host_key`.
  - `POST /api/backup/restore` validates the archive, replaces the state files in `DATA_DIR`, and applies the restored key and peers to the running server without a restart.
- The installer now makes a safety backup of `DATA_DIR` to `/var/backups/` before each install.

### Changed

- **Updates no longer touch user state.** The installer keeps an existing `/etc/systemd/system/tanguard.service` byte-for-byte and only replaces the binary, so custom ports, subnet, and credentials survive an update.
- The server private key is never regenerated on a read error — only when it is genuinely missing.
- `peers.json` is never overwritten with an empty file if it failed to load; duplicate peer adds no longer clobber the existing record.

## [1.2.1] - 2026-08-04

### Fixed

- Peers page no longer shows "No peers connected" when peers exist: `loadPeers()` referenced a `peer-count` element that only existed on the dashboard page, causing a TypeError that aborted rendering before the table was populated. The peers page now has its own peer-count badge, and the JS update is null-safe.

## [1.2.0] - 2026-08-03

### Added

- Web dashboard split into separate pages: Dashboard (`index.html`), Peers (`peers.html`), and Settings (`settings.html`).
- QR library bundled into the binary and served locally — no external CDN dependency.

### Fixed

- QR code generation in the web dashboard now renders correctly (the QR library was loaded from a non-existent CDN path, and the canvas element was passed to `QRCode.toCanvas` instead of a real `<canvas>`).

## [1.1.0] - 2026-08-03

### Added

- Web dashboard credential management:
  - Change the dashboard username and password from **Settings → Dashboard Login**.
  - First login with the default `admin` / `tanguard` credentials now forces you to set a new login before using the dashboard.
  - Credentials are stored hashed (bcrypt) in `web_credentials.json` inside `DATA_DIR`.
  - `./tanguard --reset` restores the default web login (`admin` / `tanguard`) if the password is forgotten.

### Changed

- The web dashboard is now **disabled by default**. Enable it explicitly with `-web` or `WEB_ENABLED=true`; running `tanguard` alone only serves the API.
- The dashboard password is no longer printed in the startup logs.

## [1.0.0] - 2026-07-01

### Added

- Userspace WireGuard VPN server (no kernel modules required).
- Web dashboard for managing peers and generating client configs with QR codes.
- SSH gateway / jump host (`-ssh`).
- Peer persistence via `peers.json`.
- NAT setup for VPN clients.
