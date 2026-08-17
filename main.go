package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const version = "2.1.3"

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

func main() {
	webFlag := flag.Bool("web", false, "Enable web dashboard")
	sshFlag := flag.Bool("ssh", false, "Enable SSH gateway")
	resetFlag := flag.Bool("reset", false, "Reset web dashboard credentials to default (admin/tanguard)")
	hFlag := flag.Bool("help", false, "Show usage")
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

	wg, err := NewWgServer(cfg, store)
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

	api := NewAPI(wg, store, cfg, creds, apiKeys)
	go api.Start()

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
	log.Println("[main] TunGuard stopped")
}
