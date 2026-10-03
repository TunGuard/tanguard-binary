package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// version is overridable at build time with
//
//	-ldflags "-X main.version=$(git describe --tags --always)"
//
// so a tagged release reports its own version. Hardcoding it here meant every
// release claimed to be the same build, and the dashboard offered an update
// that could never be installed.
var version = "2.3.0-dev"

func printUsage() {
	fmt.Println("TunGuard - userspace WireGuard engine")
	fmt.Println()
	fmt.Println("Usage: tanguard [flags]")
	fmt.Println()
	fmt.Println("Flags:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  API_LISTEN       HTTP API address (default :9000)")
	fmt.Println("  WG_LISTEN_PORT   WireGuard UDP port (default 13231)")
	fmt.Println("  WEB_ENABLED      Enable web dashboard (default false, or use -web)")
	fmt.Println("  WEB_USERNAME     Web UI username (default admin)")
	fmt.Println("  WEB_PASSWORD     Web UI password (default tanguard)")
	fmt.Println("  SSH_USER         SSH gateway username (default tanguard)")
	fmt.Println("  SSH_PASSWORD     SSH gateway password (default tanguard)")
	fmt.Println()
	fmt.Println("The web dashboard is disabled by default. Enable it with -web or WEB_ENABLED=true.")
	fmt.Println("On first login with the default admin/tanguard password you will be asked to set a new login.")
	fmt.Println("If you forget the new login, run 'tanguard --reset' to restore the defaults.")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sudo tanguard")
	fmt.Println("  sudo tanguard -web")
	fmt.Println("  sudo tanguard -web -ssh")
	fmt.Println("  sudo tanguard -web -ssh -api :8080")
	fmt.Println("  sudo tanguard --reset")
	os.Exit(0)
}

// runMeshOnly serves the tun control plane and the dashboard without touching
// WireGuard. It is the mode used to test and operate P2P and TRP on a host
// that has no tun device, or no privileges to create one.
func runMeshOnly(cfg *Config) {
	log.Printf("[main] mesh-only mode: WireGuard disabled, control plane only")
	creds := NewCredentialStore(cfg.DataDir)
	if err := creds.Load(); err != nil {
		log.Printf("[main] WARNING: could not load web credentials: %v", err)
	}
	apiKeys := NewAPIKeyStore(cfg.DataDir)
	if err := apiKeys.Load(); err != nil {
		log.Printf("[main] WARNING: could not load API key: %v", err)
	}

	hub := StartMesh(cfg)
	if hub == nil {
		log.Fatalf("[main] mesh control plane failed to start (is MESH_ENABLED=false?)")
	}
	log.Printf("[main] tun control plane ready: control=%s relay=%s",
		hub.cfg.ControlListen, hub.cfg.RelayListen)

	// P2P and TRP are still policy-filtered here, so the mesh behaves the same
	// way whether or not WireGuard is running on this host.
	peers := NewPeerStore(cfg.DataDir)
	if err := peers.Load(); err != nil {
		log.Printf("[main] WARNING: could not load peers: %v", err)
	}
	policies := NewPolicyStore(cfg.DataDir)
	if err := policies.Load(); err != nil {
		log.Printf("[main] WARNING: could not load policy groups: %v", err)
	}
	hub.SetPolicy(policies, peers)

	// The API is started with no WireGuard server: the mesh handlers only read
	// the hub, but the routes they share are the normal ones so the dashboard
	// behaves exactly as it does in a full deployment.
	api := NewAPI(nil, peers, cfg, creds, apiKeys, nil)
	api.policies = policies
	go api.Start()
	user := cfg.WebUsername
	if u, ok := creds.Username(); ok {
		user = u
	}
	log.Printf("[main] web dashboard at http://localhost%s  user=%s", cfg.APIListen, user)

	// Relay and TRP run in their own goroutines, so the process just waits.
	select {}
}

func main() {
	webFlag := flag.Bool("web", false, "Enable web dashboard")
	sshFlag := flag.Bool("ssh", false, "Enable SSH gateway")
	resetFlag := flag.Bool("reset", false, "Reset web dashboard credentials to default (admin/tanguard)")
	hFlag := flag.Bool("help", false, "Show usage")
	meshOnlyFlag := flag.Bool("mesh-only", false,
		"Run only the tun control plane (P2P + TRP + dashboard), without WireGuard")
	flag.Parse()

	if *hFlag {
		printUsage()
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[main] TunGuard - userspace WireGuard server")

	cfg := loadConfig()

	creds := NewCredentialStore(cfg.DataDir)
	if *resetFlag {
		if err := creds.Load(); err != nil {
			log.Fatalf("[main] could not load web credentials: %v", err)
		}
		if err := creds.Reset(); err != nil {
			log.Fatalf("[main] could not reset web credentials: %v", err)
		}
		fmt.Println("Web dashboard credentials reset to default login: admin / tanguard")
		fmt.Println("Start the server and log in again to set new credentials.")
		os.Exit(0)
	}
	if err := creds.Load(); err != nil {
		log.Printf("[main] WARNING: could not load web credentials: %v", err)
	}

	apiKeys := NewAPIKeyStore(cfg.DataDir)
	if err := apiKeys.Load(); err != nil {
		log.Printf("[main] WARNING: could not load API key: %v", err)
	}

	if *webFlag {
		cfg.WebEnabled = true
	}
	if *sshFlag {
		cfg.SSHEnabled = true
	}
	if *meshOnlyFlag {
		// P2P and TRP are independent of the WireGuard tunnel: a mesh can be
		// stood up, tested and run on a host that cannot create a tun device.
		// The dashboard is the only way to drive them, so it is implied here.
		cfg.WebEnabled = true
		runMeshOnly(cfg)
		return
	}

	log.Printf("[main] config: iface=%s port=%d addr=%s api=%s web=%v ssh=%v",
		cfg.InterfaceName, cfg.ListenPort, cfg.Address, cfg.APIListen,
		cfg.WebEnabled, cfg.SSHEnabled)
	if cfg.WebEnabled {
		user := cfg.WebUsername
		if u, ok := creds.Username(); ok {
			user = u
		}
		log.Printf("[main] web dashboard at http://localhost%s  user=%s", cfg.APIListen, user)
	}

	store := NewPeerStore(cfg.DataDir)
	if err := store.Load(); err != nil {
		log.Printf("[main] WARNING: could not load peers: %v", err)
	}

	// Policy groups are a pure administrative filter loaded before the tunnel
	// comes up, so the filter is active for the very first packet. A missing
	// file is normal and yields the permissive default group.
	policies := NewPolicyStore(cfg.DataDir)
	if err := policies.Load(); err != nil {
		log.Printf("[main] WARNING: could not load policy groups: %v", err)
	}
	for _, g := range policies.List() {
		if !g.Builtin {
			log.Printf("[main] policy group %q restored: inter_device=%v p2p=%v trp=%v wg_access=%v (%d devices)",
				g.Name, g.AllowInterDevice, g.AllowP2PMesh, g.AllowTRP, g.AllowWGAccess, len(policies.Members(g.ID)))
		}
	}

	wg, err := NewWgServer(cfg, store, policies)
	if err != nil {
		log.Fatalf("[main] failed to create WireGuard server: %v", err)
	}

	privKey, err := wg.LoadSavedPrivateKey()
	if err != nil {
		log.Fatalf("[main] private key: %v", err)
	}

	if err := wg.Configure(privKey, cfg.ListenPort); err != nil {
		log.Fatalf("[main] configure device: %v", err)
	}

	log.Printf("[main] server public key: %s", wg.PublicKey())

	if err := wg.ApplyAllPeers(); err != nil {
		log.Printf("[main] WARNING: failed to apply peers: %v", err)
	}
	for _, rec := range store.All() {
		log.Printf("[main] restored peer %s -> %s (device=%s)",
			rec.PublicKey[:8]+"...", rec.AllowedIP, rec.DeviceID)
	}

	setupNAT(cfg)

	monitor := NewPeerMonitor(wg)
	monitor.Start()

	api := NewAPI(wg, store, cfg, creds, apiKeys, monitor)
	api.policies = policies
	go api.Start()

	// tun control plane: TCP :7000 for node control, UDP :7001 for the P2P
	// rendezvous/relay, plus the TRP reverse-proxy bindings.
	if hub := StartMesh(cfg); hub != nil {
		log.Printf("[main] tun control plane ready: control=%s relay=%s",
			hub.cfg.ControlListen, hub.cfg.RelayListen)
		// Policy groups gate the mesh features as well as the tunnel, so the
		// hub needs the same two stores the filter uses.
		hub.SetPolicy(policies, store)
	}

	if cfg.SSHEnabled {
		sshGW, err := NewSSHGateway(cfg, creds)
		if err != nil {
			log.Printf("[main] WARNING: SSH gateway init failed: %v", err)
		} else {
			go sshGW.Start()
		}
	}

	pubKeyFile := cfg.DataDir + "/server_wg_pubkey.txt"
	if err := writeFile(pubKeyFile, []byte(wg.PublicKey()), 0644); err != nil {
		log.Printf("[main] WARNING: could not save public key file: %v", err)
	} else {
		log.Printf("[main] public key saved to %s", pubKeyFile)
	}

	statusFile := cfg.DataDir + "/wg_status.json"
	statusJSON := fmt.Sprintf(`{"server_public_key":"%s","listen_port":%d,"subnet":"%s","api":"%s","web_enabled":%v,"ssh_enabled":%v}`,
		wg.PublicKey(), cfg.ListenPort, cfg.Subnet, cfg.APIListen, cfg.WebEnabled, cfg.SSHEnabled)
	if err := writeFile(statusFile, []byte(statusJSON), 0644); err != nil {
		log.Printf("[main] WARNING: could not save status: %v", err)
	}

	log.Println("[main] TunGuard is running. Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[main] received %s, shutting down...", sig)

	cleanupNAT(cfg)
	wg.Close()
	store.Save()
	policies.Save()
	log.Println("[main] TunGuard stopped")
}
