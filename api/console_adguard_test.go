package api

import (
	"strings"
	"testing"

	"tanguard/adguard"
)

// TestConsoleAdGuardCommand covers the CLI surface: the guard when AdGuard is
// not configured, and the read-only status/config views when it is.
func TestConsoleAdGuardCommand(t *testing.T) {
	a := consoleTestAPI(t)

	out := runConsole(t, a, "adguard status\r")
	if !strings.Contains(out, "ADGUARD_ENABLED") {
		t.Fatalf("unconfigured adguard should explain how to enable it: %q", out)
	}

	a.cfg.AdGuardEnabled = true
	a.cfg.AdGuardDNSListen = "127.0.0.1:5353"
	a.cfg.AdGuardWebListen = "127.0.0.1:1116"
	a.cfg.AdGuardUpstream = "1.1.1.1"
	a.cfg.AdGuardUpstreamFamily = "1.1.1.2"
	a.SetAdGuard(adguard.NewManager(a.cfg))

	out = runConsole(t, a, "adguard status\r")
	for _, want := range []string{"127.0.0.1:5353", "127.0.0.1:1116", "1.1.1.1", "enabled (stopped)"} {
		if !strings.Contains(out, want) {
			t.Errorf("adguard status missing %q: %q", want, out)
		}
	}

	out = runConsole(t, a, "adguard config\r")
	for _, want := range []string{"ADGUARD_", "web listen", "family upstream"} {
		if !strings.Contains(out, want) {
			t.Errorf("adguard config missing %q: %q", want, out)
		}
	}

	out = runConsole(t, a, "adguard bogus\r")
	if !strings.Contains(out, "usage: adguard") {
		t.Errorf("unknown subcommand should print usage: %q", out)
	}
}
