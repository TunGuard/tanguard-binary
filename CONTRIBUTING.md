# Contributing

Contributions are welcome! Here's how to get started.

## Prerequisites

- Go 1.24+
- Linux (or WSL2 on Windows)

## Development

```bash
git clone https://github.com/TunGuard/tanguard-binary.git
cd tanguard-binary
go build -o tanguard .
sudo ./tanguard -web
```

## Project Structure

Source is grouped into packages by what they own. `main.go` only parses flags
and wires the pieces together; everything it starts lives in one of these:

| Path                | Description                                |
|---------------------|--------------------------------------------|
| `main.go`           | Entry point, CLI flags, orchestration       |
| `config/`           | Configuration from environment vars, key generation, file I/O helpers, build version |
| `auth/`             | Dashboard credentials and the API key store |
| `peers/`            | Peer persistence                           |
| `policy/`           | Policy groups, the packet filter, group enforcement |
| `wg/`               | WireGuard device management, NAT/iptables setup, peer monitor, system stats |
| `p2p/`              | Tun control plane, node control, P2P relay  |
| `trp/`              | TRP reverse-proxy bindings                  |
| `api/`              | HTTP API, web dashboard handlers, backup/restore, SSH gateway |
| `webui/`            | Dashboard HTML/JS/CSS and the handler that serves them |
| `internal/testenv/` | Test-only helpers shared across packages   |

Tests live next to the code they cover (`p2p/mesh_test.go` and so on), except
for the end-to-end tests that need the real client binary: those live in the
package whose behaviour they prove end to end.

Package dependencies run one way: `main` → `api` → `wg`/`p2p`/`trp`/`policy` →
`peers`/`auth`/`config`. `p2p` reaches TRP through a small interface so the two
do not depend on each other.

## Making Changes

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes and test them.
4. Run `go vet ./...` and `go build ./...` to check for issues.
5. Commit with a clear message: `git commit -m "feat: add ..."`
6. Push and open a Pull Request.

## Commit Style

We use conventional commits:

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation changes
- `chore:` maintenance, dependencies
- `ci:` CI/CD changes

## Pull Request Process

1. Keep changes focused — one feature or fix per PR.
2. Update the README if your change affects configuration or usage.
3. Ensure the binary still builds: `go build -o tanguard .`
4. Once approved, a maintainer will merge.
