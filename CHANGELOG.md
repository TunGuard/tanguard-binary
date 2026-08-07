# Changelog

All notable changes to TunGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
