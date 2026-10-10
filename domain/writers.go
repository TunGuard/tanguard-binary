package domain

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// renderRec is one record resolved for template rendering.
type renderRec struct {
	rec      *Record
	addr     string
	certPath string
	keyPath  string
	ssl      bool
}

func (m *Manager) certPaths(domain string) (certPath, keyPath string) {
	base := ""
	if m.iss != nil {
		base = m.iss.dir
	} else {
		base = filepath.Join(m.dir, "certs")
	}
	return filepath.Join(base, domain, "cert.pem"), filepath.Join(base, domain, "key.pem")
}

// writeExternalLocked regenerates the webserver config for every record and
// reloads the server. The caller must hold m.mu.
func (m *Manager) writeExternalLocked(det DetectResult) {
	name := det.Webserver
	confDir := det.ConfDir
	if confDir == "" {
		m.srv.lastErr = "no config directory for " + name
		return
	}

	inputs := make([]renderRec, 0, len(m.records))
	present := map[string]bool{}
	for _, rec := range m.records {
		if !rec.Enabled {
			continue
		}
		addr, _, err := m.backendAddrLocked(rec)
		if err != nil {
			log.Printf("[domain] %s: %v", rec.Domain, err)
			continue
		}
		certPath, keyPath := m.certPaths(rec.Domain)
		rr := renderRec{rec: rec, addr: addr, certPath: certPath, keyPath: keyPath}
		rr.ssl = fileExists(certPath) && fileExists(keyPath)
		inputs = append(inputs, rr)
		present[rec.ID] = true
	}

	var err error
	switch name {
	case "nginx":
		err = writeNginx(confDir, inputs, m.chPort, present)
	case "apache":
		err = writeApache(confDir, inputs, m.chPort, present)
	case "caddy":
		err = writeCaddy(confDir, inputs, m.chPort)
	case "traefik":
		err = writeTraefik(confDir, inputs)
	default:
		err = fmt.Errorf("unsupported webserver %q", name)
	}
	if err != nil {
		m.srv.lastErr = "write config: " + err.Error()
		log.Printf("[domain] write %s config: %v", name, err)
		return
	}

	if err := reload(name, confDir); err != nil {
		m.srv.lastErr = "reload: " + err.Error()
		log.Printf("[domain] reload %s: %v", name, err)
		return
	}
	m.srv.lastErr = ""
}

// cleanStale removes generated files that no longer correspond to an enabled
// record and returns the file names that remain.
func cleanStale(dir, pattern, prefix string, present map[string]bool) []string {
	entries, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil
	}
	var kept []string
	for _, p := range entries {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), prefix), ".conf")
		if present[id] {
			kept = append(kept, p)
			continue
		}
		if err := os.Remove(p); err == nil {
			log.Printf("[domain] removed stale config %s", p)
		}
	}
	return kept
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ─── nginx ───────────────────────────────────────────────────────────────

func nginxFile(dir, id string) string { return filepath.Join(dir, "tanguard-"+id+".conf") }

func writeNginx(dir string, recs []renderRec, chPort int, present map[string]bool) error {
	cleanStale(dir, "tanguard-*.conf", "tanguard-", present)
	for _, rr := range recs {
		if err := writeFile(nginxFile(dir, rr.rec.ID), nginxConf(rr, chPort)); err != nil {
			return err
		}
	}
	return nil
}

func nginxConf(rr renderRec, chPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by TunGuard — do not edit.\n# %s\n\n", rr.rec.Domain)
	fmt.Fprintf(&b, "server {\n\tlisten 80;\n\tserver_name %s;\n", rr.rec.Domain)
	fmt.Fprintf(&b, "\tlocation /.well-known/acme-challenge/ {\n\t\tproxy_pass http://127.0.0.1:%d;\n\t}\n", chPort)
	fmt.Fprintf(&b, "\tlocation / {\n\t\treturn 301 https://$host$request_uri;\n\t}\n}\n\n")
	fmt.Fprintf(&b, "server {\n\tlisten 443 ssl;\n\tserver_name %s;\n", rr.rec.Domain)
	fmt.Fprintf(&b, "\tssl_certificate %s;\n\tssl_certificate_key %s;\n", rr.certPath, rr.keyPath)
	fmt.Fprintf(&b, "\tssl_protocols TLSv1.2 TLSv1.3;\n")
	fmt.Fprintf(&b, "\tlocation / {\n\t\tproxy_pass http://%s;\n", rr.addr)
	fmt.Fprintf(&b, "\t\tproxy_http_version 1.1;\n")
	fmt.Fprintf(&b, "\t\tproxy_set_header Host $host;\n")
	fmt.Fprintf(&b, "\t\tproxy_set_header X-Real-IP $remote_addr;\n")
	fmt.Fprintf(&b, "\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	fmt.Fprintf(&b, "\t\tproxy_set_header X-Forwarded-Proto $scheme;\n\t}\n}\n")
	return b.String()
}

// ─── apache ──────────────────────────────────────────────────────────────

func apacheFile(dir, id string) string { return filepath.Join(dir, "tanguard-"+id+".conf") }

func writeApache(dir string, recs []renderRec, chPort int, present map[string]bool) error {
	cleanStale(dir, "tanguard-*.conf", "tanguard-", present)
	enabledDir := ""
	if filepath.Base(dir) == "sites-available" {
		enabledDir = filepath.Join(filepath.Dir(dir), "sites-enabled")
	}
	for _, rr := range recs {
		path := apacheFile(dir, rr.rec.ID)
		if err := writeFile(path, apacheConf(rr, chPort)); err != nil {
			return err
		}
		if enabledDir != "" {
			link := filepath.Join(enabledDir, filepath.Base(path))
			os.Remove(link)
			if err := os.Symlink(path, link); err != nil {
				log.Printf("[domain] enable apache site: %v", err)
			}
		}
	}
	return nil
}

func apacheConf(rr renderRec, chPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by TunGuard — do not edit.\n# %s\n\n", rr.rec.Domain)
	fmt.Fprintf(&b, "<VirtualHost *:80>\n\tServerName %s\n", rr.rec.Domain)
	fmt.Fprintf(&b, "\tProxyPreserveHost On\n")
	fmt.Fprintf(&b, "\tProxyPass /.well-known/acme-challenge/ http://127.0.0.1:%d/\n", chPort)
	fmt.Fprintf(&b, "\tProxyPassReverse /.well-known/acme-challenge/ http://127.0.0.1:%d/\n", chPort)
	fmt.Fprintf(&b, "\tRedirect permanent / https://%s/\n</VirtualHost>\n\n", rr.rec.Domain)
	fmt.Fprintf(&b, "<VirtualHost *:443>\n\tServerName %s\n", rr.rec.Domain)
	fmt.Fprintf(&b, "\tSSLEngine on\n\tSSLCertificateFile %s\n\tSSLCertificateKeyFile %s\n", rr.certPath, rr.keyPath)
	fmt.Fprintf(&b, "\tProxyPreserveHost On\n")
	fmt.Fprintf(&b, "\tProxyPass / http://%s/\n\tProxyPassReverse / http://%s/\n", rr.addr, rr.addr)
	fmt.Fprintf(&b, "\t<Proxy *>\n\t\tRequire all granted\n\t</Proxy>\n</VirtualHost>\n")
	return b.String()
}

// ─── caddy ───────────────────────────────────────────────────────────────

func writeCaddy(dir string, recs []renderRec, chPort int) error {
	var b strings.Builder
	b.WriteString("# Managed by TunGuard — do not edit.\n")
	b.WriteString("# Imported from the main Caddyfile; see `import tanguard-domains.conf`.\n\n")
	for _, rr := range recs {
		fmt.Fprintf(&b, "%s {\n\treverse_proxy %s\n}\n\n", rr.rec.Domain, rr.addr)
	}
	if err := writeFile(filepath.Join(dir, "tanguard-domains.conf"), b.String()); err != nil {
		return err
	}
	// Make sure the site file is actually imported by the main config.
	caddyfile := filepath.Join(dir, "Caddyfile")
	if data, err := os.ReadFile(caddyfile); err == nil {
		if !strings.Contains(string(data), "tanguard-domains.conf") {
			extra := "\n# Managed by TunGuard\nimport tanguard-domains.conf\n"
			if err := os.WriteFile(caddyfile, append(data, []byte(extra)...), 0644); err != nil {
				log.Printf("[domain] could not add caddy import: %v", err)
			}
		}
	}
	return nil
}

// ─── traefik ─────────────────────────────────────────────────────────────

func writeTraefik(dir string, recs []renderRec) error {
	var b strings.Builder
	b.WriteString("# Managed by TunGuard — do not edit.\n")
	b.WriteString("http:\n  routers:\n")
	for _, rr := range recs {
		name := "tanguard-" + rr.rec.ID
		fmt.Fprintf(&b, "    %s:\n      rule: Host(`%s`)\n      service: %s\n      tls: {}\n", name, rr.rec.Domain, name)
	}
	b.WriteString("  services:\n")
	for _, rr := range recs {
		name := "tanguard-" + rr.rec.ID
		fmt.Fprintf(&b, "    %s:\n      loadBalancer:\n        servers:\n          - url: http://%s\n", name, rr.addr)
	}
	return writeFile(filepath.Join(dir, "tanguard-dynamic.yml"), b.String())
}

// ─── reload ──────────────────────────────────────────────────────────────

func reload(name, confDir string) error {
	var candidates [][]string
	switch name {
	case "nginx":
		candidates = [][]string{{"nginx", "-s", "reload"}, {"systemctl", "reload", "nginx"}}
	case "apache":
		candidates = [][]string{{"apache2ctl", "graceful"}, {"apachectl", "graceful"}, {"systemctl", "reload", "apache2"}, {"systemctl", "reload", "httpd"}}
	case "caddy":
		candidates = [][]string{{"systemctl", "reload", "caddy"}, {"caddy", "reload", "--config", filepath.Join(confDir, "Caddyfile")}}
	case "traefik":
		candidates = [][]string{{"systemctl", "reload", "traefik"}}
	default:
		return fmt.Errorf("no reload command for %q", name)
	}

	var lastErr error
	for _, argv := range candidates {
		if _, err := exec.LookPath(argv[0]); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reload tool found for %s", name)
	}
	return lastErr
}
