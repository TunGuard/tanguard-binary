package wg

import (
	"testing"

	"tanguard/peers"
	"tanguard/policy"
)

// TestDNSRedirectRulesOnlyAdGuardGroup locks the decision that peers are only
// redirected when their policy group actually allows AdGuard, and that each
// gets one udp and one tcp DNAT rule pointing at the AdGuard listener.
func TestDNSRedirectRulesOnlyAdGuardGroup(t *testing.T) {
	ps := policy.NewPolicyStore(t.TempDir())
	if err := ps.Load(); err != nil {
		t.Fatal(err)
	}
	adg, err := ps.Create("Ads", policy.PolicyGroup{Name: "Ads", AllowAdGuard: true})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ps.Create("Plain", policy.PolicyGroup{Name: "Plain"})
	if err != nil {
		t.Fatal(err)
	}

	store := peers.NewPeerStore(t.TempDir())
	store.Add(&peers.PeerRecord{PublicKey: "adgpeer", AllowedIP: "10.100.0.2/32"})
	store.Add(&peers.PeerRecord{PublicKey: "plainpeer", AllowedIP: "10.100.0.3/32"})
	store.Add(&peers.PeerRecord{PublicKey: "defaultpeer", AllowedIP: "10.100.0.4/32"})

	if err := ps.Assign(adg.ID, []string{"adgpeer"}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if err := ps.Assign(plain.ID, []string{"plainpeer"}, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}

	rules := dnsRedirectRules(store, ps, "10.100.0.1", "53")
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (udp+tcp for the AdGuard-group peer)", len(rules))
	}

	protos := map[string]bool{}
	for _, r := range rules {
		// argv layout: iptables -t nat -A TUNGARD_DNS -s <ip> -p <proto> ...
		if r[6] != "10.100.0.2" {
			t.Errorf("rule targets ip %q, want 10.100.0.2", r[6])
		}
		if r[14] != "10.100.0.1:53" {
			t.Errorf("rule DNAT target %q, want 10.100.0.1:53", r[14])
		}
		protos[r[8]] = true
	}
	if !protos["udp"] || !protos["tcp"] {
		t.Errorf("expected udp and tcp rules, got %v", protos)
	}

	// No peer in the plain or default group may get a rule.
	for _, r := range rules {
		for _, unwanted := range []string{"10.100.0.3", "10.100.0.4"} {
			if r[6] == unwanted {
				t.Errorf("without AllowAdGuard the peer %s must never be redirected", unwanted)
			}
		}
	}
}

func TestDNSRedirectRulesEmptyWithoutPeers(t *testing.T) {
	ps := policy.NewPolicyStore(t.TempDir())
	if err := ps.Load(); err != nil {
		t.Fatal(err)
	}
	store := peers.NewPeerStore(t.TempDir())
	if rules := dnsRedirectRules(store, ps, "10.100.0.1", "53"); len(rules) != 0 {
		t.Fatalf("no peers should produce no rules, got %d", len(rules))
	}
	if rules := dnsRedirectRules(store, nil, "10.100.0.1", "53"); len(rules) != 0 {
		t.Fatalf("nil policy store should produce no rules, got %d", len(rules))
	}
}

func TestAllowedIPHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.100.0.2/32", "10.100.0.2"},
		{"10.100.0.3", "10.100.0.3"},
		{"2001:db8::1/128", ""},
		{"junk", ""},
	} {
		got, ok := allowedIPHost(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("allowedIPHost(%q) = %q, want unusable", tc.in, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("allowedIPHost(%q) = %q,%v want %q", tc.in, got, ok, tc.want)
		}
	}
}
