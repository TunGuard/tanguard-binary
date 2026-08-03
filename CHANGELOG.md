# Changelog

All notable changes to TunGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
