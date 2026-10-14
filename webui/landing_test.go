package webui

import (
	"bytes"
	"strings"
	"testing"
)

// TestDNSLandingRendersEndpoints keeps the public DNS landing page working:
// it must substitute the resolver endpoints and never leak template actions.
func TestDNSLandingRendersEndpoints(t *testing.T) {
	var buf bytes.Buffer
	if err := DNSLanding(&buf, "https://dns.example.com/dns-query", "dns.example.com:853"); err != nil {
		t.Fatalf("DNSLanding: %v", err)
	}
	body := buf.String()

	for _, want := range []string{
		"https://dns.example.com/dns-query",
		"dns.example.com:853",
		"DNS-over-HTTPS",
		"DNS-over-TLS",
		"Frost-bit-star",
		"https://tunguard.github.io/docs/",
		"AdGuard Home",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page missing %q", want)
		}
	}
	if strings.Contains(body, "{{") {
		t.Error("landing page contains an unrendered template action")
	}
}
