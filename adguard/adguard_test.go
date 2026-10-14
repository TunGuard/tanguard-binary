package adguard

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
	"tanguard/config"
)

// TestDNSForGroupOmitsDefaultPort locks what a client's WireGuard profile is
// handed: a bare tunnel address, not loopback and not a trailing :53.
func TestDNSForGroupOmitsDefaultPort(t *testing.T) {
	m := NewManager(&config.Config{AdGuardEnabled: true, AdGuardDNSListen: "10.100.0.1:53"})
	if got := m.DNSForGroup(true); got != "10.100.0.1" {
		t.Fatalf("DNSForGroup = %q, want 10.100.0.1", got)
	}

	m = NewManager(&config.Config{AdGuardEnabled: true, AdGuardDNSListen: "10.100.0.1:5353"})
	if got := m.DNSForGroup(true); got != "10.100.0.1:5353" {
		t.Fatalf("DNSForGroup = %q, want 10.100.0.1:5353", got)
	}

	if got := m.DNSForGroup(false); got != "" {
		t.Fatalf("DNSForGroup = %q, want empty when the group does not allow AdGuard", got)
	}
}

// TestBindAddrFallsBackWhenTunnelDown keeps mesh-only hosts (no wg0) working:
// a configured tunnel address that is absent falls back to loopback.
func TestBindAddrFallsBackWhenTunnelDown(t *testing.T) {
	m := NewManager(&config.Config{AdGuardDNSListen: "203.0.113.7:53"})
	if got := m.bindAddr(); got != "127.0.0.1:53" {
		t.Fatalf("bindAddr = %q, want 127.0.0.1:53", got)
	}
}

// TestDNSTargetGating locks that a disabled AdGuard yields no redirect target,
// so the tunnel DNS redirect is removed rather than aimed at nothing.
func TestDNSTargetGating(t *testing.T) {
	m := NewManager(&config.Config{AdGuardEnabled: false, AdGuardDNSListen: "10.100.0.1:53"})
	if got := m.DNSTarget(); got != "" {
		t.Fatalf("disabled AdGuard should give no target, got %q", got)
	}
	m = NewManager(&config.Config{AdGuardEnabled: true, AdGuardDNSListen: "10.100.0.1:53"})
	if got := m.DNSTarget(); got == "" {
		t.Fatalf("enabled AdGuard should give a target")
	}
}

// TestEnsureConfigReappliesDNSListener proves an existing AdGuardHome.yaml with
// an old loopback listener is corrected on start, rather than only on first run.
func TestEnsureConfigReappliesDNSListener(t *testing.T) {
	dir := t.TempDir()
	old, _ := yaml.Marshal(map[string]interface{}{
		"dns": map[string]interface{}{
			"bind_hosts": []interface{}{"127.0.0.1"},
			"port":       5353,
		},
	})
	if err := os.WriteFile(filepath.Join(dir, "AdGuardHome.yaml"), old, 0644); err != nil {
		t.Fatal(err)
	}

	m := NewManager(&config.Config{
		AdGuardEnabled:   true,
		AdGuardDataDir:   dir,
		AdGuardDNSListen: "127.0.0.1:53",
		AdGuardUpstream:  "1.1.1.1",
	})
	if err := m.ensureConfig(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "AdGuardHome.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	dns := doc["dns"].(map[string]interface{})
	if dns["port"] != 53 {
		t.Fatalf("dns.port = %v, want 53", dns["port"])
	}
	hosts := dns["bind_hosts"].([]interface{})
	if len(hosts) != 1 || hosts[0] != "127.0.0.1" {
		t.Fatalf("dns.bind_hosts = %v, want [127.0.0.1]", hosts)
	}
}

// TestEnsureConfigDNSPublicFrontDefaults covers the knobs a mapped DNS front
// relies on: plain DoH accepted on the loopback web listener, TLS itself never
// enabled by us, a rate limit placed in the dns block, and an operator-tuned
// rate limit left untouched.
func TestEnsureConfigDNSPublicFrontDefaults(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(&config.Config{
		AdGuardEnabled:   true,
		AdGuardDataDir:   dir,
		AdGuardDNSListen: "127.0.0.1:53",
		AdGuardUpstream:  "1.1.1.1",
	})
	if err := m.ensureConfig(); err != nil {
		t.Fatal(err)
	}

	read := func() map[string]interface{} {
		data, err := os.ReadFile(filepath.Join(dir, "AdGuardHome.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]interface{}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}

	doc := read()
	dns := doc["dns"].(map[string]interface{})
	if dns["ratelimit"] != 20 {
		t.Fatalf("dns.ratelimit = %v, want 20", dns["ratelimit"])
	}
	tls := doc["tls"].(map[string]interface{})
	if tls["enabled"] != false {
		t.Fatalf("tls.enabled = %v, want false", tls["enabled"])
	}
	if tls["allow_unencrypted_doh"] != true {
		t.Fatalf("tls.allow_unencrypted_doh = %v, want true", tls["allow_unencrypted_doh"])
	}
	if _, ok := doc["ratelimit"]; ok {
		t.Fatal("ratelimit must live under the dns block, not at the top level")
	}

	// An operator-set rate limit is preserved across restarts.
	doc["dns"].(map[string]interface{})["ratelimit"] = 0
	data, _ := yaml.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "AdGuardHome.yaml"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := m.ensureConfig(); err != nil {
		t.Fatal(err)
	}
	if got := read()["dns"].(map[string]interface{})["ratelimit"]; got != 0 {
		t.Fatalf("dns.ratelimit = %v after restart, want 0 (operator value kept)", got)
	}
}
