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

| Path            | Description                        |
|-----------------|------------------------------------|
| `main.go`       | Entry point, CLI flags, orchestration |
| `config.go`     | Configuration from environment vars |
| `wg.go`         | WireGuard device management         |
| `api.go`        | HTTP API and web dashboard          |
| `webui.go`      | Web UI handler with embedded HTML   |
| `ssh.go`        | SSH gateway for peer access         |
| `crypto.go`     | Key generation utilities            |
| `nat.go`        | NAT/iptables setup and teardown     |
| `peer_store.go` | Peer persistence                    |
| `fileutil.go`   | File I/O helpers                    |

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
