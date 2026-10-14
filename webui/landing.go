package webui

import (
	"html/template"
	"io"
)

// dnsLanding is the public landing page served at the root of a domain that is
// mapped as a DNS front. It is kept as a template so the resolver endpoints can
// be filled in for whichever domain was mapped.
var dnsLanding = template.Must(template.ParseFS(assets, "dns.html"))

// DNSLanding renders the landing page for a DNS-mapped domain, substituting the
// DNS-over-HTTPS URL and the DNS-over-TLS host (host:port).
func DNSLanding(w io.Writer, dohURL, dotHost string) error {
	return dnsLanding.Execute(w, struct {
		DoHURL  string
		DoTHost string
	}{DoHURL: dohURL, DoTHost: dotHost})
}
