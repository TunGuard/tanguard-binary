package wg

import (
	"log"
	"net"
	"os/exec"
	"strings"

	"tanguard/config"
	"tanguard/peers"
	"tanguard/policy"
)

// dnsChain is the nat-table chain holding one DNAT rule per peer whose policy
// group uses AdGuard. A dedicated chain, referenced once from PREROUTING, lets
// a sync rewrite the whole set without touching rules other parts of the
// server may have added.
const dnsChain = "TUNGARD_DNS"

// DNSRedirect intercepts the DNS (port 53) of tunnel peers and forwards it to
// AdGuard Home, so a peer is protected the moment its policy group allows
// AdGuard — even when the peer's profile still points at another resolver.
// This is what makes a group move take effect without re-importing the client
// configuration: the client's existing DNS server is simply replaced in the
// PREROUTING stage, before the query is routed anywhere.
type DNSRedirect struct {
	cfg *config.Config
}

func NewDNSRedirect(cfg *config.Config) *DNSRedirect {
	return &DNSRedirect{cfg: cfg}
}

// Sync rebuilds the redirect set for the current peers and policy groups.
// An empty target removes every redirect — that is what a stopped AdGuard
// needs, because leaving DNAT rules for a dead service would break DNS for
// those peers rather than merely no longer filtering it.
func (d *DNSRedirect) Sync(policies *policy.PolicyStore, store *peers.PeerStore, target string) {
	if d == nil || d.cfg == nil {
		return
	}
	if !d.ensureHooked() {
		return
	}
	runCmd("iptables", "-t", "nat", "-F", dnsChain)

	if policies == nil || store == nil || target == "" {
		return
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		log.Printf("[dns] invalid AdGuard target %q: %v", target, err)
		return
	}
	for _, rule := range dnsRedirectRules(store, policies, host, port) {
		runCmd(rule[0], rule[1:]...)
	}
}

// Cleanup removes the dedicated chain and its PREROUTING hook.
func (d *DNSRedirect) Cleanup() {
	if d == nil || d.cfg == nil {
		return
	}
	runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-i", d.cfg.InterfaceName, "-j", dnsChain)
	runCmd("iptables", "-t", "nat", "-F", dnsChain)
	runCmd("iptables", "-t", "nat", "-X", dnsChain)
}

// ensureHooked creates the dedicated chain and, if PREROUTING does not already
// reference it, jumps tunnel traffic into it. Returns false when iptables is
// unavailable so a sync can no-op instead of failing.
func (d *DNSRedirect) ensureHooked() bool {
	probe := exec.Command("iptables", "-t", "nat", "-S", dnsChain)
	if err := probe.Run(); err != nil {
		runCmd("iptables", "-t", "nat", "-N", dnsChain)
	}
	out, err := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").CombinedOutput()
	if err != nil {
		return false
	}
	if strings.Contains(string(out), dnsChain) {
		return true
	}
	runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-i", d.cfg.InterfaceName, "-j", dnsChain)
	return true
}

// dnsRedirectRules is the pure decision of which DNAT rules are needed, kept
// apart from Sync so the behavior is testable without touching iptables. It
// returns full argv slices; Sync hands them straight to runCmd.
func dnsRedirectRules(store *peers.PeerStore, policies *policy.PolicyStore, host, port string) [][]string {
	var rules [][]string
	if policies == nil || store == nil {
		return rules
	}
	for _, rec := range store.All() {
		if !policies.Allows(rec.PublicKey, policy.CapAdGuard) {
			continue
		}
		ip, ok := allowedIPHost(rec.AllowedIP)
		if !ok {
			continue
		}
		for _, proto := range []string{"udp", "tcp"} {
			rules = append(rules, []string{
				"iptables", "-t", "nat", "-A", dnsChain,
				"-s", ip, "-p", proto, "--dport", "53",
				"-j", "DNAT", "--to-destination", joinHostPort(host, port),
			})
		}
	}
	return rules
}

// allowedIPHost extracts the bare IPv4 tunnel address from a peer's AllowedIP.
func allowedIPHost(allowedIP string) (string, bool) {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(allowedIP))
	if err != nil {
		ip = net.ParseIP(strings.TrimSpace(allowedIP))
		if ip == nil {
			return "", false
		}
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	return v4.String(), true
}

func joinHostPort(host, port string) string {
	return net.JoinHostPort(host, port)
}
