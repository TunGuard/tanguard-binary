# TunGuard CLI — commands

The same command-line interface runs in two places:

- **SSH gateway** — `ssh admin@your-server -p 2222` (port from `SSH_LISTEN`, default `2222`). Log in with the dashboard credentials.
- **Dashboard Terminal** — open **Terminal** in the sidebar. It is the same CLI, in your browser.
- **System Logs window** — open **System Logs** in the sidebar; it is this CLI's `logs` command as a live view.

Everything the web dashboard can do — peers, mesh, TRP, policy, backup, updates — can be done from here. The commands below are the complete user-facing surface.

## Reading the prompt

```text
admin@yourserver:~$
```

`exit` or `quit` ends the session (`Ctrl-D` on an empty line does too).

## Help and completion

```bash
help                 # list every command
help peer            # usage for one command
```

**Tab** completes commands, sub-commands and names (`pol<Tab>`, `mesh remove ph<Tab>`).

## Editing keys

| Key | Action |
|---|---|
| `Tab` | complete |
| `↑` / `↓` | history (200 entries) |
| `Ctrl-A` / `Ctrl-E` | start / end of line |
| `Ctrl-U` | delete before cursor |
| `Ctrl-K` | delete after cursor |
| `Ctrl-W` | delete previous word |
| `Ctrl-L` | clear screen |
| `Ctrl-C` | cancel line, cancel a prompt, or stop a running tool / `logs -f` |
| `Ctrl-D` | exit, or cancel the current prompt |
| `Ctrl-]` | detach from an interactive `ssh` session |

## Status and server

```bash
status                  # server, tunnel, mesh and policy overview
version                 # running version + cached update state
version --refresh       # ask GitHub for the latest release
jump                    # print the ssh -J line for this server
ssh <host> [command]    # open an ssh session to a device from here
clear                   # clear the screen
```

## SSH client

The terminal is a small ssh client, so you can log in to a WireGuard peer — or
any host this server can reach — without leaving the dashboard. Peers can be
named by their device label or tunnel address; a password is asked for when no
key matches.

```bash
ssh root@10.100.0.5                 # interactive session to a peer
ssh laptop                          # a peer by its device label
ssh -p 2222 -l alice jumpbox        # alternate port / login
ssh -i ~/.ssh/id_ed25519 host       # use a specific private key
ssh host uptime                     # run one remote command and exit
ssh --password s3cret host          # non-interactive password (scripts)
```

While an interactive session is open, `Ctrl-]` detaches and returns to the
TunGuard prompt; typing `exit` on the remote host closes the connection cleanly.
`ssh host command` streams the remote output and reports the remote exit status.

## System logs

The same in-memory log the dashboard's **System Logs** window tails. `-f`
streams it like `tail -f`; `Ctrl-C` stops it.

```bash
logs                    # the last 20 lines
logs -n 100             # the last 100 lines
logs error              # only lines containing "error"
logs -f                 # follow the log live — Ctrl-C stops
logs -f http            # follow, keeping only lines mentioning http
```

Lines show a dim `HH:MM:SS` timestamp; errors are red, warnings amber.

## Settings

```bash
settings                        # show interface, subnet, ports, enabled services
settings set port 51821         # WireGuard listen port (restart to apply)
settings set key <hex>          # set the server private key (applies immediately)
```

Everything else in `settings` is an environment variable (`WEB_ENABLED`,
`SSH_ENABLED`, `MESH_ENABLED`, `TLS_CERT_FILE`, …) and applies after a restart.

Changing the server key invalidates every client config — re-issue them with
`peer config <name>`.

## Login

```bash
password
```

Three prompts: username (Enter keeps the current one), new password, repeat.
The password is not echoed. Minimum 8 characters. The dashboard and the SSH
gateway both use this login.

## API key and server key

```bash
key                     # show the API key (X-API-Key header on /api)
key server              # server public key, port and endpoint
key regenerate          # new API key — asks for confirmation
```

## Peers (WireGuard clients)

```bash
peers                           # list: name, address, key, last seen, rx/tx, group
peer new laptop                 # generate a keypair, prints a ready-to-use .conf
peer new laptop --ip 10.100.0.7 --host vpn.example.com --dns 1.1.1.1
peer add phone <pubkey>         # import an existing public key
peer add phone <pubkey> --ip 10.100.0.8 --psk <key> --id <device-id>
peer remove laptop              # by name, address or key prefix
peer config laptop              # print the .conf again (DNS defaults to 1.1.1.1)
peer config laptop --dns 9.9.9.9 --host vpn.example.com
```

Peers require WireGuard to be attached; a mesh-only process says so instead of
failing.

## Mesh (tun control plane)

```bash
mesh status                     # control/relay endpoints, nodes, groups
mesh nodes                      # registered nodes: state, control IP, seen
mesh groups                     # PSK groups and their links
mesh links                      # node pairs: direct or via hub, link test, endpoint

mesh join phone                 # register a node — prints its join key
mesh join phone --psk <key>     # with a pre-shared key
mesh remove phone               # unregister a node
mesh reset phone                # node re-identifies on its next connection
mesh punch phone laptop         # force a direct connection attempt
mesh group office on            # auto-mesh a PSK group (by label or PSK)
mesh group office off           # drop its relay links, direct links stay

mesh relay join phone           # phone now carries relay traffic for others
mesh relay leave phone
mesh relay link phone laptop    # force a relay path between two nodes
mesh relay unlink phone
```

Nodes and groups may be referred to by name, id or a unique id prefix.
Mesh commands need `MESH_ENABLED`.

## TRP (reverse-proxy port mappings)

```bash
trp list                                        # mappings: id, node, bind, target, state
trp add phone auto 192.168.1.10 80              # bind port chosen by the OS
trp add phone 8080 192.168.1.10 80              # fixed bind port on the server
trp add phone 8080 192.168.1.10 80 --bind 10.100.0.1   # only on that address
trp remove 3                                    # by id or bind-address:port
```

## Domains (HTTPS reverse proxy)

```bash
domain list                                     # mappings: domain, backend, target, state
domain add app.example.com --trp 3              # behind an existing TRP mapping
domain add api.example.com --wg 10.100.0.2 8080 # behind a tunneled service
domain update app.example.com --disable         # pause without deleting
domain update app.example.com --domain new.example.com
domain remove app.example.com                   # by id or domain name
```

The domain points at this server; TunGuard terminates TLS with a Let's
Encrypt certificate and proxies to the backend. If nginx, Apache, Caddy or
Traefik is detected, the route is written into that server and reloaded;
otherwise the built-in proxy listens on ports 80/443. The proxy is on by
default and does nothing until the first mapping is added; disable it with
`DOMAIN_ENABLED=false`. Ports are configurable with `DOMAIN_HTTP_PORT`,
`DOMAIN_HTTPS_PORT` and `DOMAIN_CHALLENGE_PORT`.

## Policy groups

```bash
policy list                         # groups: id, devices, rule flags, notes
policy show Guests                  # rules and members of one group

policy create Guests --wg on
policy create Staff --inter on --p2p on --trp on --wg on
policy update Guests --wg off       # unmentioned rules keep their value
policy update Guests --name Staff   # rename
policy delete Guests                # its devices return to default

policy assign Guests laptop phone   # device names, addresses or key prefixes
policy unassign laptop              # back to the default group

policy export /root/policy.json     # groups + assignments to a file
policy apply /root/policy.json      # validate and activate a policy file
```

Rules: `--inter` device-to-device, `--p2p` automatic mesh, `--trp` port
mapping, `--wg` internet access. A switch without a value means `on`.
Tab completion offers group and device names.

## Backup

```bash
backup export /root/tanguard-backup.tar.gz      # complete state archive
backup import /root/tanguard-backup.tar.gz      # asks y/N first
```

The restore replaces peers, groups, keys and credentials — confirm with `y`.
An archive taken here restores from the dashboard too, and vice versa.

## Updates

```bash
update check              # latest known release
update check --refresh    # ask GitHub now
update install            # download and restart — asks y/N first
```

## Network diagnostics

These run **on the server** and stream their output live. `Ctrl-C` stops them.
They are the only external commands the CLI runs, and they need the matching
tool installed on the host (`iproute2`, `dnsutils`, `curl`, …):

```bash
ping -c 4 1.1.1.1                     # ICMP echo
ping 10.100.0.5                       # ping a tunnel client
traceroute example.com                # packet path to a host
dig example.com A @1.1.1.1            # DNS lookup
curl -sS https://example.com/health    # fetch a URL (handy behind the tunnel)
ss -tunap                             # sockets and listening ports
ip addr                               # interfaces
ip route                              # routing table
```

## Confirmations

Destructive actions ask first and default to **no**:

```text
Restore /root/tanguard-backup.tar.gz? Peers, groups, keys and credentials are replaced [y/N]:
Regenerate the API key? Existing API clients stop working [y/N]:
Install v2.5.0? The server restarts [y/N]:
```

Answer `y` to proceed, anything else (or Enter) cancels.
