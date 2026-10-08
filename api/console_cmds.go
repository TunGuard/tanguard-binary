package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tanguard/config"
	"tanguard/peers"
	"tanguard/policy"
	"tanguard/wg"
)

// cliCommand is one verb of the TunGuard CLI: everything the dashboard can
// do has a command here, and the network tools after them make the terminal
// usable as a diagnostic console too. run receives everything after the verb;
// complete returns the candidates for the word being typed.
type cliCommand struct {
	name     string
	subs     []string
	usage    string
	desc     string
	run      func(*consoleSession, []string)
	complete func(*consoleSession, []string) []string
}

// netTool is a system utility exposed under its own name. It runs with its
// arguments untouched (no shell), streams output live and stops on Ctrl-C.
type netTool struct {
	name  string
	bin   string
	usage string
	desc  string
}

var netTools = []netTool{
	{name: "ping", bin: "ping", usage: "ping [-c count] [-i seconds] <host>",
		desc: "ICMP echo with live output (Ctrl-C stops)"},
	{name: "traceroute", bin: "traceroute", usage: "traceroute <host>",
		desc: "show the packet path to a host"},
	{name: "dig", bin: "dig", usage: "dig <name> [type] [@server]",
		desc: "DNS lookup"},
	{name: "curl", bin: "curl", usage: "curl [-sS] <url>",
		desc: "fetch a URL — handy for JSON APIs behind the tunnel"},
	{name: "ss", bin: "ss", usage: "ss [-tunap] [filter]",
		desc: "sockets and listening ports"},
	{name: "ip", bin: "ip", usage: "ip addr | ip route | ip link",
		desc: "interfaces and routes"},
}

// The command table is built once and then shared: help lists it, dispatch
// looks it up, completion walks it. Building it lazily (rather than as a
// package-level variable) is what lets the commands reference the helpers
// that themselves need the table — help and lookup — without an
// initialization cycle.
var (
	cliOnce     sync.Once
	cliCommands []*cliCommand
)

func allCommands() []*cliCommand {
	cliOnce.Do(func() { cliCommands = buildCommands() })
	return cliCommands
}

func buildCommands() []*cliCommand {
	cmds := []*cliCommand{
		{
			name:  "help",
			usage: "help [command]",
			desc:  "list commands, or show one command's usage",
			run:   cmdHelp,
			complete: func(s *consoleSession, rest []string) []string {
				if len(rest) > 0 {
					return nil
				}
				var names []string
				for _, c := range allCommands() {
					names = append(names, c.name)
				}
				return names
			},
		},
		{
			name:  "status",
			usage: "status",
			desc:  "server, tunnel, mesh and policy overview",
			run:   cmdStatus,
		},
		{
			name:  "logs",
			usage: "logs [-f] [-n count] [filter]",
			desc:  "show the server log; -f follows it live (Ctrl-C stops)",
			run:   cmdLogs,
			complete: func(s *consoleSession, rest []string) []string {
				if len(rest) == 0 || strings.HasPrefix(rest[len(rest)-1], "-") {
					return []string{"-f", "-n"}
				}
				return nil
			},
		},
		{
			name:  "peers",
			usage: "peers",
			desc:  "list peers (same as `peer list`)",
			run:   cmdPeerList,
		},
		{
			name:     "peer",
			subs:     []string{"list", "new", "add", "remove", "config"},
			usage:    "peer [list] | peer new <name> [--ip a.b.c.d] [--host h] [--dns ips] | peer add <name> <pubkey> [--ip a.b.c.d] [--psk key] [--id dev] | peer remove <ref> | peer config <ref> [--host h] [--dns ips]",
			desc:     "list, create, import and remove WireGuard peers",
			run:      cmdPeer,
			complete: completePeer,
		},
		{
			name:     "mesh",
			subs:     []string{"status", "nodes", "groups", "links", "join", "remove", "reset", "punch", "group", "relay"},
			usage:    "mesh status | nodes | groups | links | join <name> [--psk key] | remove <node> | reset <node> | punch <a> <b> | group <label> on|off | relay join|leave|link|unlink …",
			desc:     "inspect and steer the tun control plane",
			run:      cmdMesh,
			complete: completeMesh,
		},
		{
			name:     "trp",
			subs:     []string{"list", "add", "remove"},
			usage:    "trp list | trp add <node> <bind-port|auto> <target-ip> <target-port> [--bind ip] | trp remove <ref>",
			desc:     "manage TRP reverse-proxy port mappings",
			run:      cmdTRP,
			complete: completeTRP,
		},
		{
			name:     "policy",
			subs:     []string{"list", "show", "create", "update", "delete", "assign", "unassign", "export", "apply"},
			usage:    "policy list | show <group> | create <name> [--inter on|off] [--p2p on|off] [--trp on|off] [--wg on|off] | update <group> [--name n] [--inter on|off] … | delete <group> | assign <group> <device…> | unassign <device…> | export <file> | apply <file>",
			desc:     "manage policy groups and device membership",
			run:      cmdPolicy,
			complete: completePolicy,
		},
		{
			name:  "settings",
			subs:  []string{"set"},
			usage: "settings | settings set port <n> | settings set key <hex>",
			desc:  "show or change the server configuration",
			run:   cmdSettings,
		},
		{
			name:  "key",
			subs:  []string{"show", "server", "regenerate"},
			usage: "key [show] | key server | key regenerate",
			desc:  "API key for /api clients, and the server's WireGuard key",
			run:   cmdKey,
		},
		{
			name:  "password",
			usage: "password",
			desc:  "change the dashboard / ssh gateway login",
			run:   cmdPassword,
		},
		{
			name:  "backup",
			subs:  []string{"export", "import"},
			usage: "backup export <file> | backup import <file>",
			desc:  "save or restore the full server state",
			run:   cmdBackup,
		},
		{
			name:  "update",
			subs:  []string{"check", "install"},
			usage: "update [check] [--refresh] | update install",
			desc:  "check for or install a new release",
			run:   cmdUpdate,
		},
		{
			name:  "version",
			usage: "version [--refresh]",
			desc:  "show the running version and update status",
			run:   cmdVersion,
		},
		{
			name:  "jump",
			usage: "jump",
			desc:  "how to use this server as an ssh jump host",
			run:   cmdJump,
		},
		{
			name:  "clear",
			usage: "clear",
			desc:  "clear the screen (also: Ctrl-L)",
			run: func(s *consoleSession, _ []string) {
				s.write("\x1b[2J\x1b[H")
			},
		},
	}
	for _, t := range netTools {
		tool := t
		cmds = append(cmds, &cliCommand{
			name:  tool.name,
			usage: tool.usage,
			desc:  tool.desc,
			run: func(s *consoleSession, args []string) {
				s.runTool(tool.bin, args)
			},
		})
	}
	return cmds
}

func lookupCommand(name string) *cliCommand {
	for _, c := range allCommands() {
		if c.name == name {
			return c
		}
	}
	return nil
}

// ─── general ─────────────────────────────────────────────────────────────

func cmdHelp(s *consoleSession, args []string) {
	if len(args) == 0 {
		s.printf("\x1b[1mTunGuard CLI\x1b[0m — commands:\r\n\r\n")
		width := 0
		for _, c := range allCommands() {
			if len(c.name) > width {
				width = len(c.name)
			}
		}
		for _, c := range allCommands() {
			s.printf("  \x1b[1m%-*s\x1b[0m  %s\r\n", width, c.name, c.desc)
		}
		s.printf("\r\nTab completes commands and arguments; ↑/↓ walks history.\r\n")
		s.printf("`help <command>` shows usage. `exit` disconnects.\r\n")
		return
	}
	c := lookupCommand(args[0])
	if c == nil {
		s.errf("no such command %q", args[0])
		return
	}
	s.printf("\x1b[1m%s\x1b[0m — %s\r\n\r\n", c.name, c.desc)
	s.printf("usage: %s\r\n", c.usage)
	if len(c.subs) > 0 {
		s.printf("words: %s\r\n", strings.Join(c.subs, ", "))
	}
}

func cmdStatus(s *consoleSession, _ []string) {
	a := s.api
	st := wg.CollectSystemStats(a.cfg.DataDir)

	s.printf("\x1b[1;36mTunGuard\x1b[0m %s — %s\r\n", config.Version, st.Hostname)
	if st.OS != "" || st.Kernel != "" {
		s.printf("  system        : %s %s\r\n", st.OS, st.Kernel)
	}
	s.printf("  uptime        : %s\r\n", uptimeTextU(st.Uptime))
	s.printf("  cpu           : %.0f%% of %d core(s), load %s\r\n", st.CPUPercent, st.CPUCores, loadText(st.Load))
	s.printf("  memory        : %s / %s (%.0f%%)\r\n", humanBytesU(st.Memory.Used), humanBytesU(st.Memory.Total), st.Memory.Percent)
	if st.Disk.Path != "" {
		s.printf("  disk          : %s / %s (%.0f%%) %s\r\n", humanBytesU(st.Disk.Used), humanBytesU(st.Disk.Total), st.Disk.Percent, st.Disk.Path)
	}
	s.printf("  subnet        : %s\r\n", a.cfg.Subnet)

	if a.wg != nil {
		if dev, err := a.wg.GetStatus(); err == nil {
			s.printf("  wireguard     : port %d, %d peer(s), key %s\r\n",
				dev.ListenPort, len(dev.Peers), peers.ShortKey(dev.ServerPublicKey))
		}
	} else {
		s.printf("  wireguard     : not attached (mesh-only process)\r\n")
	}

	s.printf("  dashboard     : %s\r\n", a.cfg.APIListen)
	if a.cfg.SSHEnabled {
		s.printf("  ssh gateway   : %s (jump host, dashboard login)\r\n", a.cfg.SSHListen)
	} else {
		s.printf("  ssh gateway   : disabled (SSH_ENABLED)\r\n")
	}

	if a.hub != nil {
		m := a.hub.MeshStatus()
		s.printf("  mesh          : %v node(s), %v online, %v group(s) — control %v\r\n",
			m["nodes"], m["online"], m["groups"], m["control_listen"])
	} else {
		s.printf("  mesh          : disabled (MESH_ENABLED)\r\n")
	}

	if a.policies != nil {
		custom := len(a.policies.List()) - 1
		if custom < 0 {
			custom = 0
		}
		state := "inactive"
		if a.policies.IsActive() {
			state = "active"
		}
		s.printf("  policy        : %d group(s), %s\r\n", custom, state)
	}
}

// ─── logs ────────────────────────────────────────────────────────────────

// printLogLine writes one buffered line the way a device console would: a
// dim timestamp, then the message — red for errors, amber for warnings.
func printLogLine(s *consoleSession, e LogEntry) {
	ts := time.UnixMilli(e.TS).Format("15:04:05")
	switch {
	case strings.Contains(e.Line, "ERROR") || strings.Contains(e.Line, "error:"):
		s.printf("\x1b[2m%s\x1b[0m \x1b[31m%s\x1b[0m\r\n", ts, e.Line)
	case strings.Contains(e.Line, "WARN"):
		s.printf("\x1b[2m%s\x1b[0m \x1b[33m%s\x1b[0m\r\n", ts, e.Line)
	default:
		s.printf("\x1b[2m%s\x1b[0m %s\r\n", ts, e.Line)
	}
}

// cmdLogs reads the same in-memory ring the System Logs window shows. Without
// -f it prints a window of history and returns; with -f it becomes a
// foreground job — output streams until Ctrl-C, exactly like ping.
func cmdLogs(s *consoleSession, args []string) {
	follow := false
	n := -1
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--follow":
			follow = true
		case a == "-n" || a == "--lines":
			i++
			if i >= len(args) {
				s.errf("-n needs a line count")
				return
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				s.errf("line count must be a positive number")
				return
			}
			n = v
		case strings.HasPrefix(a, "-") && len(a) > 1:
			v, err := strconv.Atoi(a[1:])
			if err != nil || v < 1 {
				s.errf("unknown flag %s — try `logs -f -n 100 [filter]`", a)
				return
			}
			n = v
		default:
			words = append(words, a)
		}
	}
	if n < 0 {
		n = 20
		if follow {
			n = 10
		}
	}
	filter := strings.Join(words, " ")
	match := func(line string) bool { return filter == "" || strings.Contains(line, filter) }

	entries, latest, _ := ServerLogBuffer().Since(0, 0)
	var shown []LogEntry
	for _, e := range entries {
		if match(e.Line) {
			shown = append(shown, e)
		}
	}
	if len(shown) > n {
		shown = shown[len(shown)-n:]
	}
	lastID := latest
	if len(shown) == 0 && !follow {
		if filter != "" {
			s.printf("no log lines match %q\r\n", filter)
		} else {
			s.printf("no log entries yet — service output appears here\r\n")
		}
		return
	}
	for _, e := range shown {
		printLogLine(s, e)
	}
	if !follow {
		return
	}

	s.printf("\x1b[2m-- following, Ctrl-C stops --\x1b[0m\r\n")
	stopCh := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(stopCh) }) }
	s.startForeground(stop, func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-s.closed:
				return
			case <-ticker.C:
				fresh, newLatest, _ := ServerLogBuffer().Since(lastID, 200)
				for _, e := range fresh {
					if match(e.Line) {
						printLogLine(s, e)
					}
				}
				if newLatest > lastID {
					lastID = newLatest
				}
			}
		}
	})
}

// ─── peers ───────────────────────────────────────────────────────────────

func cmdPeer(s *consoleSession, args []string) {
	verb := "list"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}
	switch verb {
	case "list", "":
		cmdPeerList(s, nil)
	case "new":
		cmdPeerNew(s, args)
	case "add":
		cmdPeerAdd(s, args)
	case "remove":
		cmdPeerRemove(s, args)
	case "config":
		cmdPeerConfig(s, args)
	default:
		s.errf("usage: %s", lookupCommand("peer").usage)
	}
}

func cmdPeerList(s *consoleSession, _ []string) {
	a := s.api
	if a.wg == nil {
		s.errf("wireguard is not attached (mesh-only process)")
		return
	}
	dev, err := a.wg.GetStatus()
	if err != nil {
		s.errf("%s", err)
		return
	}
	byKey := make(map[string]wg.PeerStatus, len(dev.Peers))
	for _, p := range dev.Peers {
		byKey[p.PublicKey] = p
	}

	var rows [][]string
	for _, rec := range a.store.All() {
		seen := "never"
		rx, tx := "—", "—"
		if p, ok := byKey[rec.PublicKey]; ok {
			seen = ageText(p.LastHandshakeSec)
			rx = humanBytes(p.RxBytes)
			tx = humanBytes(p.TxBytes)
		}
		group := "—"
		if a.policies != nil {
			group = "default"
			if g := a.policies.GroupForPeer(rec.PublicKey); g != nil && g.ID != policy.DefaultPolicyGroupID {
				group = g.Name
			}
		}
		rows = append(rows, []string{
			deviceLabel(rec), rec.AllowedIP, peers.ShortKey(rec.PublicKey), seen, rx, tx, group,
		})
	}
	if len(rows) == 0 {
		s.printf("no peers yet — `peer new <name>` creates one\r\n")
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	s.table([]string{"NAME", "ADDRESS", "PUBLIC KEY", "SEEN", "RX", "TX", "GROUP"}, rows)
}

func cmdPeerNew(s *consoleSession, args []string) {
	a := s.api
	if a.wg == nil {
		s.errf("wireguard is not attached (mesh-only process)")
		return
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "--") {
		s.errf("usage: peer new <name> [--ip a.b.c.d] [--host h] [--dns ips]")
		return
	}
	name := args[0]
	wantedIP := flagValue(args[1:], "--ip")
	host := a.cfg.APIListen
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	dns := flagValue(args[1:], "--dns")

	privBytes, pubBytes, err := config.GenerateKeyPair()
	if err != nil {
		s.errf("key generation failed: %s", err)
		return
	}
	clientPriv := hex.EncodeToString(privBytes)
	clientPub := hex.EncodeToString(pubBytes)

	a.ipMu.Lock()
	var ip string
	if wantedIP != "" {
		if !strings.Contains(wantedIP, "/") {
			wantedIP += "/32"
		}
		if _, _, err := net.ParseCIDR(wantedIP); err != nil {
			a.ipMu.Unlock()
			s.errf("invalid --ip %s: use a CIDR like 10.100.0.5/32", wantedIP)
			return
		}
		if a.store.AllowedIPInUse(wantedIP) {
			a.ipMu.Unlock()
			s.errf("address %s is already assigned", wantedIP)
			return
		}
		ip = wantedIP
	} else {
		next, err := a.nextAvailableIP()
		if err != nil {
			a.ipMu.Unlock()
			s.errf("%s", err)
			return
		}
		ip = next.String() + "/32"
	}
	if err := a.wg.AddPeer(clientPub, ip, ""); err != nil {
		a.ipMu.Unlock()
		s.errf("add peer: %s", err)
		return
	}
	rec := &peers.PeerRecord{
		PublicKey:        clientPub,
		AllowedIP:        ip,
		DeviceName:       name,
		ClientPrivateKey: clientPriv,
		AddedAt:          time.Now(),
	}
	a.store.Add(rec)
	saveErr := a.store.Save()
	a.ipMu.Unlock()
	if saveErr != nil {
		s.errf("peer created, but persisting failed: %s", saveErr)
		return
	}

	s.printf("created \x1b[1m%s\x1b[0m at %s\r\n", name, ip)
	s.printf("  public key : %s\r\n", clientPub)
	s.printf("  endpoint   : %s:%d\r\n\r\n", host, a.cfg.ListenPort)
	s.printf("%s", a.peerConfigText(rec, host, dns))
}

// cmdPeerAdd imports a peer that already has a keypair — the CLI form of the
// dashboard's import dialog (/api/peer/add).
func cmdPeerAdd(s *consoleSession, args []string) {
	a := s.api
	if a.wg == nil {
		s.errf("wireguard is not attached (mesh-only process)")
		return
	}
	if len(args) < 2 || strings.HasPrefix(args[0], "--") {
		s.errf("usage: peer add <name> <pubkey> [--ip a.b.c.d] [--psk key] [--id device-id]")
		return
	}
	name := args[0]
	pub := strings.TrimSpace(args[1])
	rest := args[2:]
	wantedIP := flagValue(rest, "--ip")
	psk := strings.TrimSpace(flagValue(rest, "--psk"))
	deviceID := strings.TrimSpace(flagValue(rest, "--id"))

	if _, err := config.ValidateHexKey(pub); err != nil {
		s.errf("invalid public key: %s", err)
		return
	}
	if psk != "" {
		if _, err := config.ValidateHexKey(psk); err != nil {
			s.errf("invalid --psk: %s", err)
			return
		}
	}

	a.ipMu.Lock()
	unlock := func() { a.ipMu.Unlock() }

	if a.store.Get(pub) != nil {
		unlock()
		s.errf("a peer with this public key already exists")
		return
	}
	ip := wantedIP
	if ip == "" {
		next, err := a.nextAvailableIP()
		if err != nil {
			unlock()
			s.errf("%s", err)
			return
		}
		ip = next.String() + "/32"
	} else {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		if _, _, err := net.ParseCIDR(ip); err != nil {
			unlock()
			s.errf("invalid --ip %s: use a CIDR like 10.100.0.7/32", ip)
			return
		}
		if a.store.AllowedIPInUse(ip) {
			unlock()
			s.errf("address %s is already assigned to another peer", ip)
			return
		}
	}
	if err := a.wg.AddPeer(pub, ip, psk); err != nil {
		unlock()
		s.errf("add peer: %s", err)
		return
	}
	a.store.Add(&peers.PeerRecord{
		PublicKey:    pub,
		AllowedIP:    ip,
		DeviceName:   name,
		DeviceID:     deviceID,
		PreSharedKey: psk,
		AddedAt:      time.Now(),
	})
	saveErr := a.store.Save()
	unlock()
	if saveErr != nil {
		s.errf("peer added, but persisting failed: %s", saveErr)
		return
	}
	s.printf("imported \x1b[1m%s\x1b[0m at %s (key %s)\r\n", name, ip, peers.ShortKey(pub))
}

func cmdPeerRemove(s *consoleSession, args []string) {
	a := s.api
	if len(args) != 1 {
		s.errf("usage: peer remove <name|address|key>")
		return
	}
	rec, err := a.resolvePeer(args[0])
	if err != nil {
		s.errf("%s", err)
		return
	}
	a.ipMu.Lock()
	if a.wg != nil {
		if err := a.wg.RemovePeer(rec.PublicKey); err != nil {
			a.ipMu.Unlock()
			s.errf("remove peer: %s", err)
			return
		}
	}
	a.store.Remove(rec.PublicKey)
	a.ipMu.Unlock()
	if err := a.store.Save(); err != nil {
		s.errf("peer removed, but persisting failed: %s", err)
		return
	}
	s.printf("removed %s (%s)\r\n", deviceLabel(rec), rec.AllowedIP)
}

func cmdPeerConfig(s *consoleSession, args []string) {
	a := s.api
	// The reference is the first non-flag argument, so `peer config laptop
	// --host vpn.example.com --dns 9.9.9.9` parses the way it reads.
	var ref string
	var rest []string
	for _, arg := range args {
		if ref == "" && !strings.HasPrefix(arg, "--") {
			ref = arg
			continue
		}
		rest = append(rest, arg)
	}
	if ref == "" {
		s.errf("usage: peer config <name|address|key> [--host h] [--dns ips]")
		return
	}
	rec, err := a.resolvePeer(ref)
	if err != nil {
		s.errf("%s", err)
		return
	}
	if rec.ClientPrivateKey == "" {
		s.errf("%s has no stored client key (imported peers cannot be re-issued)", deviceLabel(rec))
		return
	}
	if a.wg == nil {
		s.errf("wireguard is not attached (mesh-only process)")
		return
	}
	dns := flagValue(rest, "--dns")
	host := flagValue(rest, "--host")
	if host == "" {
		host = a.cfg.APIListen
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	s.printf("%s", a.peerConfigText(rec, host, dns))
}

// ─── mesh ────────────────────────────────────────────────────────────────

func cmdMesh(s *consoleSession, args []string) {
	a := s.api
	if a.hub == nil {
		s.errf("mesh control plane is disabled (MESH_ENABLED)")
		return
	}
	verb := "status"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}

	switch verb {
	case "status", "":
		m := a.hub.MeshStatus()
		s.printf("control  : %v\r\n", m["control_listen"])
		s.printf("relay    : %v\r\n", m["relay_listen"])
		s.printf("nodes    : %v (%v online)\r\n", m["nodes"], m["online"])
		s.printf("groups   : %v\r\n", m["groups"])
		s.printf("clients  : %v tun client device(s)\r\n", m["client_devices"])
	case "nodes":
		var rows [][]string
		for _, n := range a.hub.ListNodes(false) {
			state := "offline"
			if n.Online {
				state = "online"
			}
			rows = append(rows, []string{
				n.Name, shortID(n.ID), state, orDash(n.ControlIP),
				fmt.Sprintf("%d/%d", n.DirectPeers, n.Peers),
				nodeAge(n.LastSeen, n.ConnectedFor),
			})
		}
		if len(rows) == 0 {
			s.printf("no nodes registered — `mesh join <name>` creates one\r\n")
			return
		}
		s.table([]string{"NAME", "ID", "STATE", "CONTROL", "DIRECT", "SEEN"}, rows)
	case "groups":
		groups := a.hub.ListGroups(false)
		if len(groups) == 0 {
			s.printf("no PSK groups yet — they appear as devices enroll\r\n")
			return
		}
		var rows [][]string
		for _, g := range groups {
			rows = append(rows, []string{
				orDash(g.Label), shortPSK(g.PSK),
				fmt.Sprintf("%d", g.Nodes), fmt.Sprintf("%d", g.Online),
				fmt.Sprintf("%d/%d", g.Direct, g.Links),
			})
		}
		s.table([]string{"GROUP", "PSK", "NODES", "ONLINE", "DIRECT/LINKS"}, rows)
		s.printf("auto-mesh runs per group: `mesh group <label> off` drops its relay links\r\n")
	case "links":
		links := a.hub.ListLinks()
		if len(links) == 0 {
			s.printf("no links (both ends online ⇒ they link up on their own)\r\n")
			return
		}
		var rows [][]string
		for _, l := range links {
			state := "via hub"
			if l.Direct {
				state = "direct"
			}
			test := "—"
			if !l.Online {
				test = "offline"
			} else if l.Tested {
				test = fmt.Sprintf("%d ms", l.RTTMS)
			} else if l.Direct {
				test = "no answer"
			}
			rows = append(rows, []string{
				orDash(l.FromName), orDash(l.ToName), state, test, orDash(l.Endpoint),
			})
		}
		s.table([]string{"FROM", "TO", "PATH", "LINK TEST", "ENDPOINT"}, rows)
	case "join":
		if len(args) == 0 || strings.HasPrefix(args[0], "--") {
			s.errf("usage: mesh join <name> [--psk key]")
			return
		}
		psk := strings.TrimSpace(flagValue(args[1:], "--psk"))
		rec, err := a.hub.AddNode(args[0], psk)
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("node \x1b[1m%s\x1b[0m registered\r\n", rec.Name)
		s.printf("  id       : %s\r\n", rec.ID)
		s.printf("  join key : %s\r\n", rec.PSK)
		s.printf("  enter the join key on the device to enroll it\r\n")
	case "remove":
		if len(args) != 1 {
			s.errf("usage: mesh remove <node>")
			return
		}
		id, err := a.resolveNode(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.hub.RemoveNode(id); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("node %s removed\r\n", id)
	case "reset":
		if len(args) != 1 {
			s.errf("usage: mesh reset <node>")
			return
		}
		id, err := a.resolveNode(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		a.hub.ResetNode(id)
		s.printf("node %s reset — it re-identifies on its next connection\r\n", id)
	case "punch":
		if len(args) != 2 {
			s.errf("usage: mesh punch <node-a> <node-b>")
			return
		}
		src, err := a.resolveNode(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		dst, err := a.resolveNode(args[1])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.hub.DirectConnect(src, dst); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("punching %s ↔ %s\r\n", args[0], args[1])
	case "group":
		if len(args) != 2 {
			s.errf("usage: mesh group <label> on|off")
			return
		}
		enable, err := parseOnOff(args[1])
		if err != nil {
			s.errf("usage: mesh group <label> on|off")
			return
		}
		psk, err := a.resolveMeshGroup(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		n, err := a.hub.MeshGroup(psk, enable)
		if err != nil {
			s.errf("%s", err)
			return
		}
		if enable {
			s.printf("auto-mesh re-punched for %d node(s) in %s\r\n", n, args[0])
		} else {
			s.printf("relay links dropped for %d node(s) in %s (direct links stay)\r\n", n, args[0])
		}
	case "relay":
		cmdMeshRelay(s, args)
	default:
		s.errf("usage: %s", lookupCommand("mesh").usage)
	}
}

func cmdMeshRelay(s *consoleSession, args []string) {
	a := s.api
	if len(args) == 0 {
		s.errf("usage: mesh relay join <node> | leave <node> | link <a> <b> | unlink <node>")
		return
	}
	sub := args[0]
	args = args[1:]
	needNode := func(usage string) (string, bool) {
		if len(args) != 1 {
			s.errf("usage: %s", usage)
			return "", false
		}
		id, err := a.resolveNode(args[0])
		if err != nil {
			s.errf("%s", err)
			return "", false
		}
		return id, true
	}
	switch sub {
	case "join":
		if id, ok := needNode("mesh relay join <node>"); ok {
			if err := a.hub.JoinRelay(id); err != nil {
				s.errf("%s", err)
				return
			}
			s.printf("node %s now carries relay traffic for others\r\n", id)
		}
	case "leave":
		if id, ok := needNode("mesh relay leave <node>"); ok {
			if err := a.hub.LeaveRelay(id); err != nil {
				s.errf("%s", err)
				return
			}
			s.printf("node %s left the relay set\r\n", id)
		}
	case "link":
		if len(args) != 2 {
			s.errf("usage: mesh relay link <a> <b>")
			return
		}
		src, err := a.resolveNode(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		dst, err := a.resolveNode(args[1])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.hub.Relay().LinkRelay(src, dst); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("relay link %s → %s established\r\n", args[0], args[1])
	case "unlink":
		if id, ok := needNode("mesh relay unlink <node>"); ok {
			a.hub.Relay().Unlink(id)
			s.printf("relay link for %s removed\r\n", id)
		}
	default:
		s.errf("usage: mesh relay join <node> | leave <node> | link <a> <b> | unlink <node>")
	}
}

// resolveMeshGroup maps a group label (or PSK prefix) to the PSK the hub
// keys auto-meshing by.
func (a *API) resolveMeshGroup(ref string) (string, error) {
	for _, g := range a.hub.ListGroups(false) {
		if strings.EqualFold(g.Label, ref) || strings.EqualFold(g.PSK, ref) {
			return g.PSK, nil
		}
	}
	var matches []string
	for _, g := range a.hub.ListGroups(false) {
		if strings.HasPrefix(strings.ToLower(g.PSK), strings.ToLower(ref)) {
			matches = append(matches, g.PSK)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no mesh group matches %q", ref)
	default:
		return "", fmt.Errorf("%q matches several groups — use the label", ref)
	}
}

// ─── TRP ─────────────────────────────────────────────────────────────────

func cmdTRP(s *consoleSession, args []string) {
	a := s.api
	if a.hub == nil || a.trp == nil {
		s.errf("mesh control plane is disabled (MESH_ENABLED)")
		return
	}
	verb := "list"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}

	switch verb {
	case "list", "":
		proxies := a.trp.ListProxies()
		if len(proxies) == 0 {
			s.printf("no port mappings — `trp add <node> <port> <ip> <port>` creates one\r\n")
			return
		}
		var rows [][]string
		for _, p := range proxies {
			state := "disabled"
			if en, ok := p["enabled"].(bool); ok && en {
				state = "enabled"
			}
			nodeName := orDashStr(p["name"], p["node_id"])
			if id, ok := p["node_id"].(string); ok && id != "" {
				if rec := a.hub.GetNode(id); rec != nil && rec.Name != "" {
					nodeName = rec.Name
				}
			}
			rows = append(rows, []string{
				fmt.Sprint(p["id"]),
				nodeName,
				fmt.Sprintf("%v:%v", orDashStr(p["bind_ip"], "*"), p["bind_port"]),
				fmt.Sprintf("%v:%v", orDashStr(p["target_ip"], ""), p["target_port"]),
				state,
			})
		}
		s.table([]string{"ID", "NODE", "BIND", "TARGET", "STATE"}, rows)
	case "add":
		// Positionals may be interleaved with flags: the dashboard's mapping
		// form has a bind address too, so --bind must land the same way.
		var pos []string
		bindIP := ""
		for i := 0; i < len(args); i++ {
			if args[i] == "--bind" {
				i++
				if i >= len(args) {
					s.errf("--bind needs an address (e.g. 10.100.0.1 or 0.0.0.0)")
					return
				}
				bindIP = args[i]
				continue
			}
			if strings.HasPrefix(args[i], "--") {
				s.errf("unknown flag %s — usage: trp add <node> <bind-port|auto> <target-ip> <target-port> [--bind ip]", args[i])
				return
			}
			pos = append(pos, args[i])
		}
		if len(pos) != 4 {
			s.errf("usage: trp add <node> <bind-port|auto> <target-ip> <target-port> [--bind ip]")
			return
		}
		nodeID, err := a.resolveNode(pos[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		bindPort := 0
		if pos[1] != "auto" && pos[1] != "-" {
			n, err := strconv.Atoi(pos[1])
			if err != nil || n < 0 || n > 65535 {
				s.errf("bind port must be 1-65535 or `auto`")
				return
			}
			bindPort = n
		}
		targetPort, err := strconv.Atoi(pos[3])
		if err != nil || targetPort < 1 || targetPort > 65535 {
			s.errf("target port must be 1-65535")
			return
		}
		rec, err := a.trp.CreateProxy(nodeID, bindIP, bindPort, targetPort, pos[2])
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("mapping %s:%d → %s:%d (id %s)\r\n", rec.BindIP, rec.BindPort, rec.TargetIP, targetPort, rec.ID)
	case "remove":
		if len(args) != 1 {
			s.errf("usage: trp remove <id|bind-address:port>")
			return
		}
		id, err := a.resolveProxy(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.trp.RemoveProxy(id); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("mapping %s removed\r\n", id)
	default:
		s.errf("usage: %s", lookupCommand("trp").usage)
	}
}

// ─── policy ──────────────────────────────────────────────────────────────

func cmdPolicy(s *consoleSession, args []string) {
	a := s.api
	if a.policies == nil {
		s.errf("policy store not loaded")
		return
	}
	verb := "list"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}

	switch verb {
	case "list", "":
		var rows [][]string
		for _, g := range a.policies.List() {
			members := len(a.policies.Members(g.ID)) + len(a.policies.DeviceMembers(g.ID))
			if g.ID == policy.DefaultPolicyGroupID {
				members = 0
				for _, info := range a.peerPolicyInfo() {
					if info.GroupID == policy.DefaultPolicyGroupID || info.GroupID == "" {
						members++
					}
				}
			}
			rows = append(rows, []string{
				g.Name, g.ID, strconv.Itoa(members), ruleFlags(g), builtinTag(g),
			})
		}
		s.table([]string{"GROUP", "ID", "DEVICES", "RULES", "NOTE"}, rows)
		s.printf("rules: device-to-device, p2p mesh, trp mapping, wg internet (y/n)\r\n")
		if a.wg != nil {
			inter, access := a.wg.PolicyDrops()
			if inter+access > 0 {
				s.printf("dropped by policy: %d inter-device, %d internet packet(s)\r\n", inter, access)
			}
		}
	case "show":
		if len(args) != 1 {
			s.errf("usage: policy show <group>")
			return
		}
		g, err := a.groupRef(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("\x1b[1m%s\x1b[0m (%s)%s\r\n", g.Name, g.ID, builtinTag(g))
		s.printf("  devices talk to each other : %s\r\n", yesNo(g.AllowInterDevice))
		s.printf("  p2p automatic mesh         : %s\r\n", yesNo(g.AllowP2PMesh))
		s.printf("  trp port mapping           : %s\r\n", yesNo(g.AllowTRP))
		s.printf("  wg internet access         : %s\r\n", yesNo(g.AllowWGAccess))
		ids := a.policies.Members(g.ID)
		if len(ids) > 0 {
			s.printf("  members:\r\n")
			for _, key := range ids {
				label := peers.ShortKey(key)
				if rec := a.store.Get(key); rec != nil {
					label = deviceLabel(rec)
				}
				s.printf("    %s\r\n", label)
			}
		}
		deviceIDs := a.policies.DeviceMembers(g.ID)
		if len(deviceIDs) > 0 {
			s.printf("  client devices:\r\n")
			for _, id := range deviceIDs {
				s.printf("    %s\r\n", id)
			}
		}
	case "create":
		if len(args) == 0 {
			s.errf("usage: policy create <name> [--inter on|off] [--p2p on|off] [--trp on|off] [--wg on|off]")
			return
		}
		name := args[0]
		switches, err := parseRuleSwitches(args[1:])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if _, ok := switches["--name"]; ok {
			s.errf("the name is positional: policy create <name>")
			return
		}
		g, err := a.policies.Create(name, rulesFromSwitches(switches))
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("group \x1b[1m%s\x1b[0m created\r\n", g.Name)
		s.printf("  rules: %s — change them with `policy update %s --wg on …`\r\n", ruleFlags(g), g.Name)
	case "update":
		if len(args) == 0 {
			s.errf("usage: policy update <group> [--name n] [--inter on|off] [--p2p on|off] [--trp on|off] [--wg on|off]")
			return
		}
		g, err := a.groupRef(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		switches, err := parseRuleSwitches(args[1:])
		if err != nil {
			s.errf("%s", err)
			return
		}
		// Unmentioned switches keep their current value — same rule the
		// dashboard's update request follows.
		next := policyRules{
			Name:             g.Name,
			AllowInterDevice: &g.AllowInterDevice,
			AllowP2PMesh:     &g.AllowP2PMesh,
			AllowTRP:         &g.AllowTRP,
			AllowWGAccess:    &g.AllowWGAccess,
		}
		if name, ok := switches["--name"]; ok {
			if strings.TrimSpace(name) == "" {
				s.errf("--name cannot be empty")
				return
			}
			next.Name = name
		}
		if v, ok := switches["--inter"]; ok {
			b := v == "on"
			next.AllowInterDevice = &b
		}
		if v, ok := switches["--p2p"]; ok {
			b := v == "on"
			next.AllowP2PMesh = &b
		}
		if v, ok := switches["--trp"]; ok {
			b := v == "on"
			next.AllowTRP = &b
		}
		if v, ok := switches["--wg"]; ok {
			b := v == "on"
			next.AllowWGAccess = &b
		}
		updated, err := a.policies.Update(g.ID, next.apply())
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("group \x1b[1m%s\x1b[0m updated: %s\r\n", updated.Name, ruleFlags(updated))
	case "delete":
		if len(args) != 1 {
			s.errf("usage: policy delete <group>")
			return
		}
		g, err := a.groupRef(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.policies.Delete(g.ID); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("group %s deleted — its devices returned to default\r\n", g.Name)
	case "assign":
		if len(args) < 2 {
			s.errf("usage: policy assign <group> <device...>")
			return
		}
		g, err := a.groupRef(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		var keys, deviceIDs []string
		for _, ref := range args[1:] {
			id, err := a.policyDevices(ref)
			if err != nil {
				s.errf("%s", err)
				return
			}
			if a.store.Get(id) != nil {
				keys = append(keys, id)
			} else {
				deviceIDs = append(deviceIDs, id)
			}
		}
		if len(keys) > 0 {
			if err := a.policies.Assign(g.ID, keys, func(key string) bool { return a.store.Get(key) != nil }); err != nil {
				s.errf("%s", err)
				return
			}
		}
		if len(deviceIDs) > 0 {
			if err := a.policies.AssignDevices(g.ID, deviceIDs, a.clientDeviceLookup(), a.isPeerDevice); err != nil {
				s.errf("%s", err)
				return
			}
		}
		s.printf("%d device(s) moved into %s\r\n", len(keys)+len(deviceIDs), g.Name)
	case "unassign":
		if len(args) == 0 {
			s.errf("usage: policy unassign <device...>")
			return
		}
		var keys, deviceIDs []string
		for _, ref := range args {
			id, err := a.policyDevices(ref)
			if err != nil {
				s.errf("%s", err)
				return
			}
			if a.store.Get(id) != nil {
				keys = append(keys, id)
			} else {
				deviceIDs = append(deviceIDs, id)
			}
		}
		if len(keys) > 0 {
			if err := a.policies.Unassign(keys); err != nil {
				s.errf("%s", err)
				return
			}
		}
		if len(deviceIDs) > 0 {
			if err := a.policies.UnassignDevices(deviceIDs); err != nil {
				s.errf("%s", err)
				return
			}
		}
		s.printf("%d device(s) returned to the default group\r\n", len(keys)+len(deviceIDs))
	case "export":
		if len(args) != 1 {
			s.errf("usage: policy export <file>")
			return
		}
		pf := policy.PolicyFile{
			Groups:       []*policy.PolicyGroup{},
			Assign:       map[string]string{},
			DeviceAssign: map[string]string{},
			UpdatedAt:    time.Now(),
		}
		for _, g := range a.policies.List() {
			if g.ID == policy.DefaultPolicyGroupID {
				continue // the default group is implicit and must stay undeclared
			}
			pf.Groups = append(pf.Groups, g)
			for _, key := range a.policies.Members(g.ID) {
				pf.Assign[key] = g.ID
			}
			for _, id := range a.policies.DeviceMembers(g.ID) {
				pf.DeviceAssign[id] = g.ID
			}
		}
		data, err := json.MarshalIndent(pf, "", "  ")
		if err != nil {
			s.errf("encode policy: %s", err)
			return
		}
		if err := os.WriteFile(args[0], append(data, '\n'), 0600); err != nil {
			s.errf("write %s: %s", args[0], err)
			return
		}
		s.printf("wrote %d group(s) and %d assignment(s) to %s\r\n",
			len(pf.Groups), len(pf.Assign)+len(pf.DeviceAssign), args[0])
	case "apply":
		if len(args) != 1 {
			s.errf("usage: policy apply <file>")
			return
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			s.errf("read %s: %s", args[0], err)
			return
		}
		var pf policy.PolicyFile
		if err := json.Unmarshal(data, &pf); err != nil {
			s.errf("%s is not a policy file: %s", args[0], err)
			return
		}
		if err := a.policies.Apply(pf, func(key string) bool {
			return a.store.Get(key) != nil
		}, a.clientDeviceLookup()); err != nil {
			s.errf("%s", err)
			return
		}
		groups := len(a.policies.List()) - 1
		members := 0
		for _, g := range a.policies.List() {
			if g.ID != policy.DefaultPolicyGroupID {
				members += len(a.policies.Members(g.ID)) + len(a.policies.DeviceMembers(g.ID))
			}
		}
		s.printf("applied %d group(s), %d assigned device(s) — policy %s\r\n",
			groups, members, map[bool]string{true: "active", false: "inactive"}[a.policies.IsActive()])
	default:
		s.errf("usage: %s", lookupCommand("policy").usage)
	}
}

// parseRuleSwitches reads `[--name v] [--inter on|off] …` into a map keyed by
// the flag. A switch on its own counts as `on`, matching how the dashboard's
// toggles send only what was touched.
func parseRuleSwitches(args []string) (map[string]string, error) {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if !strings.HasPrefix(flag, "--") {
			return nil, fmt.Errorf("unexpected %q — options look like --inter on", flag)
		}
		needValue := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", flag)
			}
			i++
			return args[i], nil
		}
		switch flag {
		case "--name":
			v, err := needValue()
			if err != nil {
				return nil, err
			}
			out[flag] = v
		case "--inter", "--p2p", "--trp", "--wg":
			// Bare switch means enable — also when the next token is another
			// flag, so `--wg --trp off` is two options, not a bad value.
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				out[flag] = "on"
				continue
			}
			v, err := needValue()
			if err != nil {
				return nil, err
			}
			switch strings.ToLower(v) {
			case "on", "true", "yes", "1":
				out[flag] = "on"
			case "off", "false", "no", "0":
				out[flag] = "off"
			default:
				return nil, fmt.Errorf("%s wants on or off, not %q", flag, v)
			}
		default:
			return nil, fmt.Errorf("unknown option %q", flag)
		}
	}
	return out, nil
}

func rulesFromSwitches(switches map[string]string) policy.PolicyGroup {
	var g policy.PolicyGroup
	if v, ok := switches["--inter"]; ok {
		g.AllowInterDevice = v == "on"
	}
	if v, ok := switches["--p2p"]; ok {
		g.AllowP2PMesh = v == "on"
	}
	if v, ok := switches["--trp"]; ok {
		g.AllowTRP = v == "on"
	}
	if v, ok := switches["--wg"]; ok {
		g.AllowWGAccess = v == "on"
	}
	return g
}

// ─── settings, key, password ─────────────────────────────────────────────

func cmdSettings(s *consoleSession, args []string) {
	a := s.api
	if len(args) > 0 && args[0] == "set" {
		cmdSettingsSet(s, args[1:])
		return
	}
	s.printf("  interface   : %s (%s, mtu %d)\r\n", a.cfg.InterfaceName, a.cfg.Address, a.cfg.MTU)
	s.printf("  subnet      : %s\r\n", a.cfg.Subnet)
	s.printf("  wg port     : %d\r\n", a.cfg.ListenPort)
	s.printf("  api         : %s\r\n", a.cfg.APIListen)
	s.printf("  data dir    : %s\r\n", a.cfg.DataDir)
	if a.cfg.WebEnabled {
		s.printf("  dashboard   : enabled (login %s)\r\n", a.effectiveWebUsername())
	} else {
		s.printf("  dashboard   : disabled (WEB_ENABLED)\r\n")
	}
	if a.cfg.SSHEnabled {
		s.printf("  ssh gateway : %s (key %s)\r\n", a.cfg.SSHListen, orDash(a.cfg.SSHKeyFile))
	} else {
		s.printf("  ssh gateway : disabled (SSH_ENABLED)\r\n")
	}
	if a.cfg.TLSCertFile != "" {
		s.printf("  tls         : %s + %s\r\n", a.cfg.TLSCertFile, a.cfg.TLSKeyFile)
	} else {
		s.printf("  tls         : disabled (TLS_CERT_FILE / TLS_KEY_FILE)\r\n")
	}
	if a.hub != nil {
		s.printf("  mesh        : enabled\r\n")
	} else {
		s.printf("  mesh        : disabled (MESH_ENABLED)\r\n")
	}
	s.printf("\r\nRuntime keys: `settings set port <n>`, `settings set key <hex>`.\r\n")
	s.printf("Everything else is an environment variable and applies after a restart.\r\n")
}

func cmdSettingsSet(s *consoleSession, args []string) {
	a := s.api
	if len(args) != 2 {
		s.errf("usage: settings set port <1-65535> | settings set key <hex>")
		return
	}
	switch args[0] {
	case "port", "listen-port":
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 || n > 65535 {
			s.errf("port must be 1-65535")
			return
		}
		a.cfg.ListenPort = n
		s.printf("listen port set to %d — restart required to apply\r\n", n)
	case "key", "private-key":
		if a.wg == nil {
			s.errf("wireguard is not attached (mesh-only process)")
			return
		}
		key := strings.TrimSpace(args[1])
		if _, err := config.ValidateHexKey(key); err != nil {
			s.errf("invalid private key: %s", err)
			return
		}
		if err := a.wg.Configure(key, a.cfg.ListenPort); err != nil {
			s.errf("configure: %s", err)
			return
		}
		keyFile := a.cfg.DataDir + "/server_private.key"
		if err := config.WriteFile(keyFile, []byte(key), 0600); err != nil {
			s.errf("key applied, but saving %s failed: %s", keyFile, err)
			return
		}
		s.printf("server key updated — public key is now %s\r\n", a.wg.PublicKey())
		s.printf("every client config must be regenerated (`peer config <name>`)\r\n")
	default:
		s.errf("unknown setting %q — keys: port, key", args[0])
	}
}

func cmdKey(s *consoleSession, args []string) {
	a := s.api
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "show", "":
		key, ok := a.apiKey.Key()
		if !ok {
			s.printf("no API key yet — `key regenerate` creates one\r\n")
			return
		}
		s.printf("API key    : %s\r\n", key)
		if ts, ok := a.apiKey.CreatedAt(); ok {
			s.printf("created    : %s\r\n", ts.Format(time.RFC3339))
		}
		s.printf("use it as the X-API-Key header on /api requests\r\n")
	case "server":
		if a.wg == nil {
			s.errf("wireguard is not attached (mesh-only process)")
			return
		}
		pub := a.wg.PublicKey()
		if pub == "" {
			s.errf("server key not initialized")
			return
		}
		s.printf("server public key : %s\r\n", pub)
		s.printf("listen port       : %d\r\n", a.cfg.ListenPort)
		s.printf("endpoint          : %s:%d\r\n", a.cfg.APIListen, a.cfg.ListenPort)
	case "regenerate":
		s.confirm("Regenerate the API key? Existing API clients stop working [y/N]: ", func(yes bool) {
			if !yes {
				s.printf("cancelled\r\n")
				return
			}
			key, err := a.apiKey.Generate()
			if err != nil {
				s.errf("generate API key: %s", err)
				return
			}
			s.printf("new API key: %s\r\n", key)
			s.printf("store it now — it is shown only once here\r\n")
		})
	default:
		s.errf("usage: %s", lookupCommand("key").usage)
	}
}

// cmdPassword walks the same rules the dashboard's change form enforces
// (non-empty user, ≥8 characters, confirmation), one question at a time.
func cmdPassword(s *consoleSession, _ []string) {
	a := s.api
	current, _ := a.creds.Username()
	s.ask(fmt.Sprintf("Username [%s]: ", current), false, func(line string) {
		user := strings.TrimSpace(line)
		if user == "" {
			user = current
		}
		if user == "" {
			s.errf("username cannot be empty")
			return
		}
		s.ask("New password: ", true, func(pw string) {
			if len(pw) < 8 {
				s.errf("password must be at least 8 characters")
				return
			}
			s.ask("Repeat password: ", true, func(pw2 string) {
				if pw != pw2 {
					s.errf("passwords do not match")
					return
				}
				if err := a.creds.Set(user, pw); err != nil {
					s.errf("save credentials: %s", err)
					return
				}
				s.printf("login updated for %q — dashboard and ssh gateway both use it\r\n", user)
			})
		})
	})
}

// ─── backup ──────────────────────────────────────────────────────────────

func cmdBackup(s *consoleSession, args []string) {
	a := s.api
	verb := "export"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}
	switch verb {
	case "export":
		if len(args) != 1 {
			s.errf("usage: backup export <file>")
			return
		}
		f, err := os.Create(args[0])
		if err != nil {
			s.errf("create %s: %s", args[0], err)
			return
		}
		exportErr := a.exportBackup(f)
		if cerr := f.Close(); exportErr == nil {
			exportErr = cerr
		}
		if exportErr != nil {
			s.errf("%s", exportErr)
			return
		}
		info, _ := os.Stat(args[0])
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		s.printf("backup written to %s (%s)\r\n", args[0], humanBytes(size))
	case "import":
		if len(args) != 1 {
			s.errf("usage: backup import <file>")
			return
		}
		path := args[0]
		if _, err := os.Stat(path); err != nil {
			s.errf("%s: %s", path, err)
			return
		}
		s.confirm(fmt.Sprintf("Restore %s? Peers, groups, keys and credentials are replaced [y/N]: ", path), func(yes bool) {
			if !yes {
				s.printf("restore cancelled\r\n")
				return
			}
			// Open only now: the question sits between dispatch and this
			// callback, and a handle opened earlier would already be closed.
			f, err := os.Open(path)
			if err != nil {
				s.errf("open %s: %s", path, err)
				return
			}
			defer f.Close()
			summary, err := a.importBackup(f)
			if err != nil {
				s.errf("%s", err)
				return
			}
			s.printf("restored from %s: %v peer(s), server key %s\r\n",
				path, summary["peer_count"], orDash(fmt.Sprint(summary["server_public_key"])))
		})
	default:
		s.errf("usage: %s", lookupCommand("backup").usage)
	}
}

// ─── update ──────────────────────────────────────────────────────────────

func cmdUpdate(s *consoleSession, args []string) {
	a := s.api
	verb := "check"
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		verb = args[0]
		args = args[1:]
	}
	switch verb {
	case "check", "":
		if hasFlag(args, "--refresh") {
			a.checkGitHubRelease()
		}
		versionCache.mu.RLock()
		latest := versionCache.latestVersion
		avail := versionCache.updateAvailable
		notes := versionCache.releaseNotes
		releaseURL := versionCache.releaseURL
		versionCache.mu.RUnlock()
		if latest == "" {
			s.printf("no update information yet — `update check --refresh` asks GitHub\r\n")
			return
		}
		if avail {
			s.printf("update available: v%s (running v%s)\r\n", latest, config.Version)
		} else {
			s.printf("up to date: v%s is the latest release\r\n", config.Version)
		}
		if releaseURL != "" {
			s.printf("release: %s\r\n", releaseURL)
		}
		if notes != "" {
			s.printf("\r\n%s\r\n", toCRLF(truncateLines(notes, 12)))
		}
	case "install":
		versionCache.mu.RLock()
		avail := versionCache.updateAvailable
		url := versionCache.downloadURL
		latest := versionCache.latestVersion
		versionCache.mu.RUnlock()
		if url == "" || !avail {
			if !avail && latest != "" {
				s.printf("already running the latest release (v%s)\r\n", config.Version)
				return
			}
			s.errf("no download ready — run `update check --refresh` first")
			return
		}
		s.confirm(fmt.Sprintf("Install v%s? The server restarts [y/N]: ", latest), func(yes bool) {
			if !yes {
				s.printf("cancelled\r\n")
				return
			}
			if err := a.installUpdate(url); err != nil {
				s.errf("%s", err)
				return
			}
			s.printf("update installed — server is restarting\r\n")
			a.restartProcess()
		})
	default:
		s.errf("usage: %s", lookupCommand("update").usage)
	}
}

func cmdVersion(s *consoleSession, args []string) {
	a := s.api
	if hasFlag(args, "--refresh") {
		a.checkGitHubRelease()
	}
	s.printf("TunGuard %s (%s)\r\n", config.Version, goArch())
	versionCache.mu.RLock()
	latest := versionCache.latestVersion
	avail := versionCache.updateAvailable
	versionCache.mu.RUnlock()
	if latest != "" {
		if avail {
			s.printf("update available: v%s — `update install` applies it\r\n", latest)
		} else {
			s.printf("up to date with v%s\r\n", latest)
		}
	}
}

func cmdJump(s *consoleSession, _ []string) {
	a := s.api
	s.printf("This server is an ssh jump host: any TCP target it can reach is one\r\n")
	s.printf("ProxyJump away, using the same login as the dashboard:\r\n\r\n")
	s.printf("  \x1b[1mssh -J %s@%s user@target\x1b[0m\r\n\r\n", s.user, jumpAddr(a.cfg))
	s.printf("Example through the mesh:\r\n\r\n")
	s.printf("  \x1b[1mssh -J %s@%s root@10.100.0.5\x1b[0m\r\n\r\n", s.user, jumpAddr(a.cfg))
	s.printf("Direct sessions to WireGuard peers work too — no -J needed:\r\n\r\n")
	s.printf("  \x1b[1mssh user@10.100.0.5\x1b[0m\r\n")
}

// ─── completions ─────────────────────────────────────────────────────────

func completePeer(s *consoleSession, rest []string) []string {
	if len(rest) == 1 && (rest[0] == "remove" || rest[0] == "config") {
		var names []string
		for _, p := range s.api.store.All() {
			names = append(names, deviceLabel(p))
		}
		return names
	}
	return nil
}

func completeMesh(s *consoleSession, rest []string) []string {
	a := s.api
	if a.hub == nil {
		return nil
	}
	switch {
	case len(rest) == 1 && (rest[0] == "remove" || rest[0] == "reset" || rest[0] == "punch"):
		return a.nodeNames()
	case len(rest) == 2 && rest[0] == "punch":
		return a.nodeNames()
	case len(rest) == 1 && rest[0] == "group":
		var labels []string
		for _, g := range a.hub.ListGroups(false) {
			if g.Label != "" {
				labels = append(labels, g.Label)
			}
		}
		return labels
	case len(rest) == 2 && rest[0] == "group":
		return []string{"on", "off"}
	case len(rest) == 1 && rest[0] == "relay":
		return []string{"join", "leave", "link", "unlink"}
	case len(rest) == 2 && rest[0] == "relay" && (rest[1] == "join" || rest[1] == "leave" || rest[1] == "unlink"):
		return a.nodeNames()
	case len(rest) == 3 && rest[0] == "relay" && rest[1] == "link":
		return a.nodeNames()
	}
	return nil
}

func completeTRP(s *consoleSession, rest []string) []string {
	a := s.api
	if a.hub == nil || a.trp == nil {
		return nil
	}
	switch {
	case len(rest) == 1 && rest[0] == "remove":
		var ids []string
		for _, p := range a.trp.ListProxies() {
			ids = append(ids, fmt.Sprint(p["id"]))
		}
		return ids
	case len(rest) == 1 && rest[0] == "add":
		return a.nodeNames()
	}
	return nil
}

func completePolicy(s *consoleSession, rest []string) []string {
	a := s.api
	if a.policies == nil || len(rest) == 0 {
		return nil
	}
	switch {
	case rest[0] == "show" || rest[0] == "delete" || rest[0] == "update" || rest[0] == "assign":
		if rest[0] != "assign" || len(rest) == 1 {
			var names []string
			for _, g := range a.policies.List() {
				names = append(names, g.Name)
			}
			return names
		}
		fallthrough
	case rest[0] == "assign" && len(rest) > 1, rest[0] == "unassign":
		var names []string
		for _, info := range a.peerPolicyInfo() {
			names = append(names, info.label())
		}
		return names
	}
	return nil
}

// ─── resolution helpers ──────────────────────────────────────────────────

// resolveNode accepts a node id, a node name, or a unique id prefix.
func (a *API) resolveNode(ref string) (string, error) {
	if a.hub == nil {
		return "", fmt.Errorf("mesh control plane is disabled")
	}
	nodes := a.hub.ListNodes(false)
	for _, n := range nodes {
		if n.ID == ref || strings.EqualFold(n.Name, ref) {
			return n.ID, nil
		}
	}
	var prefix []string
	for _, n := range nodes {
		if strings.HasPrefix(strings.ToLower(n.ID), strings.ToLower(ref)) {
			prefix = append(prefix, n.ID)
		}
	}
	switch len(prefix) {
	case 1:
		return prefix[0], nil
	case 0:
		return "", fmt.Errorf("no node matches %q", ref)
	default:
		return "", fmt.Errorf("%q matches several nodes — give the full id", ref)
	}
}

// resolveProxy accepts a proxy id, an id prefix, or "bind:port".
func (a *API) resolveProxy(ref string) (string, error) {
	proxies := a.trp.ListProxies()
	for _, p := range proxies {
		if fmt.Sprint(p["id"]) == ref {
			return ref, nil
		}
		bind := fmt.Sprintf("%v:%v", orDashStr(p["bind_ip"], ""), p["bind_port"])
		if bind == ref {
			return fmt.Sprint(p["id"]), nil
		}
	}
	var prefix []string
	for _, p := range proxies {
		if strings.HasPrefix(strings.ToLower(fmt.Sprint(p["id"])), strings.ToLower(ref)) {
			prefix = append(prefix, fmt.Sprint(p["id"]))
		}
	}
	switch len(prefix) {
	case 1:
		return prefix[0], nil
	case 0:
		return "", fmt.Errorf("no mapping matches %q", ref)
	default:
		return "", fmt.Errorf("%q matches several mappings", ref)
	}
}

func (a *API) nodeNames() []string {
	if a.hub == nil {
		return nil
	}
	var names []string
	for _, n := range a.hub.ListNodes(false) {
		if n.Name != "" {
			names = append(names, n.Name)
		} else {
			names = append(names, shortID(n.ID))
		}
	}
	return names
}

// ─── output helpers ──────────────────────────────────────────────────────

func humanBytes(n int64) string {
	if n < 0 {
		return "—"
	}
	return humanBytesU(uint64(n))
}

func humanBytesU(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	for _, u := range units {
		f /= 1024
		if f < 1024 {
			return fmt.Sprintf("%.1f %s", f, u)
		}
	}
	return fmt.Sprintf("%.1f EiB", f/1024)
}

func loadText(load []float64) string {
	if len(load) == 0 {
		return "—"
	}
	parts := make([]string, len(load))
	for i, v := range load {
		parts[i] = fmt.Sprintf("%.2f", v)
	}
	return strings.Join(parts, " ")
}

func shortPSK(psk string) string {
	if len(psk) <= 12 {
		return psk
	}
	return psk[:12] + "…"
}

// truncateLines caps release notes so `update check` stays readable.
func truncateLines(text string, max int) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) <= max {
		return text
	}
	return strings.Join(append(lines[:max], "…"), "\n")
}

func parseOnOff(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("want on or off, not %q", v)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func orDash(v string) string {
	if v == "" {
		return "—"
	}
	return v
}

// orDashStr returns the first value that carries information, or "—".
func orDashStr(vals ...interface{}) string {
	for _, v := range vals {
		s := fmt.Sprint(v)
		if s != "" && s != "<nil>" && s != "0" {
			return s
		}
	}
	return "—"
}

func nodeAge(lastSeen, connectedFor string) string {
	if lastSeen != "" {
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			return ageText(t.Unix())
		}
		return lastSeen
	}
	return orDash(connectedFor)
}

func ruleFlags(g *policy.PolicyGroup) string {
	var b strings.Builder
	for _, on := range []bool{g.AllowInterDevice, g.AllowP2PMesh, g.AllowTRP, g.AllowWGAccess} {
		if on {
			b.WriteString("y ")
		} else {
			b.WriteString("n ")
		}
	}
	return strings.TrimSpace(b.String())
}

func builtinTag(g *policy.PolicyGroup) string {
	if g.Builtin {
		return " (built-in)"
	}
	return ""
}

// flagValue finds `--name value` in a trailing argument list.
func flagValue(args []string, name string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// resolvePeer turns a peer reference — an exact public key, device id, device
// name or assigned address — into a record. A public-key prefix that matches
// exactly one peer also resolves; anything else is an error.
func (a *API) resolvePeer(ref string) (*peers.PeerRecord, error) {
	ref = strings.TrimSpace(ref)
	if rec := a.store.Get(ref); rec != nil {
		return rec, nil
	}
	if key, ok := a.store.PublicKeyForDeviceID(ref); ok {
		if rec := a.store.Get(key); rec != nil {
			return rec, nil
		}
	}
	for _, rec := range a.store.All() {
		if strings.EqualFold(rec.DeviceName, ref) || rec.AllowedIP == ref || strings.TrimSuffix(rec.AllowedIP, "/32") == ref {
			return rec, nil
		}
	}
	var matches []*peers.PeerRecord
	for _, rec := range a.store.All() {
		if strings.HasPrefix(rec.PublicKey, ref) {
			matches = append(matches, rec)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no peer matches %q", ref)
	default:
		return nil, fmt.Errorf("ambiguous peer reference %q", ref)
	}
}

// peerConfigText renders the WireGuard client file for a peer — the CLI twin
// of the dashboard's peer-config download.
func (a *API) peerConfigText(rec *peers.PeerRecord, host, dns string) string {
	if rec == nil {
		return ""
	}
	if dns == "" {
		dns = "1.1.1.1"
	}
	if host == "" {
		host = a.cfg.APIListen
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		config.HexToBase64(rec.ClientPrivateKey), strings.TrimSuffix(rec.AllowedIP, "/32"), dns, config.HexToBase64(a.wg.PublicKey()), host, a.cfg.ListenPort)
}

// groupRef resolves the "<group>" argument of the policy verbs: an id, a name,
// or a unique name prefix.
func (a *API) groupRef(ref string) (*policy.PolicyGroup, error) {
	ref = strings.TrimSpace(ref)
	if g := a.policies.Group(ref); g != nil {
		return g, nil
	}
	var matches []*policy.PolicyGroup
	for _, g := range a.policies.List() {
		if strings.EqualFold(g.Name, ref) {
			return g, nil
		}
		if strings.HasPrefix(g.Name, ref) {
			matches = append(matches, g)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return nil, fmt.Errorf("no group matches %q", ref)
	default:
		return nil, fmt.Errorf("ambiguous group reference %q", ref)
	}
}

// policyDevices maps a device reference — a peer's key, name or id, or a tun
// client's device id or node name — to the stable token a policy membership
// stores.
func (a *API) policyDevices(ref string) (string, error) {
	if rec, err := a.resolvePeer(ref); err == nil {
		return rec.PublicKey, nil
	}
	if a.hub == nil {
		return "", fmt.Errorf("no device matches %q", ref)
	}
	for _, n := range a.hub.ClientDevices() {
		if n.DeviceID == ref || strings.EqualFold(n.Name, ref) {
			return n.DeviceID, nil
		}
	}
	return "", fmt.Errorf("no device matches %q", ref)
}

// yesNo is the CLI's "yes"/"no" spelling of a truth value.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// toCRLF normalises any line ending to the \r\n a terminal session wants.
func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
