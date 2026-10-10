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
