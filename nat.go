package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

func setupInterface(cfg *Config) {
	// Assign IP address
	runCmd("ip", "addr", "add", cfg.Address, "dev", cfg.InterfaceName)
	// Bring interface up
	runCmd("ip", "link", "set", cfg.InterfaceName, "up")
	// Set MTU
	runCmd("ip", "link", "set", cfg.InterfaceName, "mtu", fmt.Sprintf("%d", cfg.MTU))
	log.Printf("[nat] interface %s configured", cfg.InterfaceName)
}

func setupNAT(cfg *Config) {
	nic := detectExternalNIC(cfg)
	if nic == "" {
		log.Println("[nat] WARNING: no external NIC detected, NAT not configured")
		return
	}
	log.Printf("[nat] using external NIC: %s", nic)

	// Enable IP forwarding
	writeProc("/proc/sys/net/ipv4/ip_forward", "1")

	// MASQUERADE: WireGuard clients → internet via external NIC
	runCmd("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", cfg.Subnet, "-o", nic, "-j", "MASQUERADE")
	runCmd("iptables", "-A", "FORWARD", "-i", cfg.InterfaceName, "-j", "ACCEPT")
	runCmd("iptables", "-A", "FORWARD", "-o", cfg.InterfaceName, "-j", "ACCEPT")

	log.Printf("[nat] iptables MASQUERADE configured: %s → %s", cfg.Subnet, nic)
}

func cleanupNAT(cfg *Config) {
	nic := detectExternalNIC(cfg)
	if nic == "" {
		return
	}
	runCmd("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", cfg.Subnet, "-o", nic, "-j", "MASQUERADE")
	runCmd("iptables", "-D", "FORWARD", "-i", cfg.InterfaceName, "-j", "ACCEPT")
	runCmd("iptables", "-D", "FORWARD", "-o", cfg.InterfaceName, "-j", "ACCEPT")
}

func detectExternalNIC(cfg *Config) string {
	if cfg.ExternalNIC != "" {
		return cfg.ExternalNIC
	}

	// Find the NIC that has the default route
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	// Format: "default via 10.0.2.2 dev eth0 ..."
	parts := strings.Fields(string(out))
	for i, p := range parts {
		if p == "dev" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	// Fallback: find first non-loopback interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "wg") {
			continue
		}
		return iface.Name
	}
	return ""
}

func writeProc(path, value string) {
	cmd := fmt.Sprintf("echo %s > %s", value, path)
	_ = exec.Command("sh", "-c", cmd).Run()
}

func runCmd(name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		log.Printf("[cmd] %s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}
