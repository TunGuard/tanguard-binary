package config

import "testing"

// TestDomainProxyDefaultsOn locks the behaviour that a fresh install shows the
// Domains page live, without anyone setting DOMAIN_ENABLED first.
func TestDomainProxyDefaultsOn(t *testing.T) {
	t.Setenv("DOMAIN_ENABLED", "")
	if cfg := LoadConfig(); !cfg.DomainEnabled {
		t.Fatalf("DOMAIN_ENABLED should default to on")
	}

	t.Setenv("DOMAIN_ENABLED", "false")
	if cfg := LoadConfig(); cfg.DomainEnabled {
		t.Fatalf("DOMAIN_ENABLED=false should disable the proxy")
	}

	t.Setenv("DOMAIN_ENABLED", "true")
	if cfg := LoadConfig(); !cfg.DomainEnabled {
		t.Fatalf("DOMAIN_ENABLED=true should enable the proxy")
	}
}

// TestAdGuardDNSDefaultsToTunnelAddress locks the fix for clients that were
// handed a loopback DNS server: AdGuard must listen on the server's tunnel
// address so the filtered DNS is actually reachable through the VPN.
func TestAdGuardDNSDefaultsToTunnelAddress(t *testing.T) {
	t.Setenv("ADGUARD_DNS_LISTEN", "")
	t.Setenv("WG_ADDRESS", "")

	cfg := LoadConfig()
	if cfg.AdGuardDNSListen != "10.100.0.1:53" {
		t.Fatalf("AdGuard DNS should default to the tunnel address, got %q", cfg.AdGuardDNSListen)
	}

	t.Setenv("WG_ADDRESS", "10.9.0.1/24")
	if got := LoadConfig().AdGuardDNSListen; got != "10.9.0.1:53" {
		t.Fatalf("AdGuard DNS should follow WG_ADDRESS, got %q", got)
	}

	// An explicit setting always wins.
	t.Setenv("ADGUARD_DNS_LISTEN", "127.0.0.1:5353")
	if got := LoadConfig().AdGuardDNSListen; got != "127.0.0.1:5353" {
		t.Fatalf("ADGUARD_DNS_LISTEN should win, got %q", got)
	}
}
