package domain

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DetectResult describes what is installed on the host and who currently owns
// the public HTTP/HTTPS ports.
type DetectResult struct {
	// Webserver is "nginx", "apache", "caddy", "traefik" or "" when none of
	// the supported servers is running.
	Webserver string
	// ConfDir is where our vhost files are written for the detected server.
	ConfDir string
	// Owner80 and Owner443 name the process holding the port, when known.
	Owner80  string
	Owner443 string
	// Port80Free reports whether the built-in proxy can bind :80.
	Port80Free  bool
	Port443Free bool
}

// knownWebservers maps a process comm (and cmdline basename) to the canonical
// name and the directory our generated config belongs in.
var knownWebservers = []struct {
	match   []string
	name    string
	confDir string
}{
	{match: []string{"nginx"}, name: "nginx", confDir: "/etc/nginx/conf.d"},
	{match: []string{"apache2", "apache"}, name: "apache", confDir: "/etc/apache2/sites-available"},
	{match: []string{"httpd"}, name: "apache", confDir: "/etc/httpd/conf.d"},
	{match: []string{"caddy"}, name: "caddy", confDir: "/etc/caddy"},
	{match: []string{"traefik"}, name: "traefik", confDir: "/etc/traefik"},
}

// Detect inspects /proc to find a running webserver and the owner of ports 80
// and 443. It never mutates anything.
func Detect() DetectResult {
	var res DetectResult
	res.Owner80 = portOwner(80)
	res.Owner443 = portOwner(443)
	res.Port80Free = res.Owner80 == ""
	res.Port443Free = res.Owner443 == ""

	for _, entry := range knownWebservers {
		if res.Webserver != "" {
			break
		}
		for _, comm := range processComms() {
			for _, m := range entry.match {
				if comm == m {
					res.Webserver = entry.name
					res.ConfDir = entry.confDir
					break
				}
			}
			if res.Webserver != "" {
				break
			}
		}
	}
	return res
}

// processComms returns the comm of every running process, lowercased and
// deduplicated.
func processComms() []string {
	procs, err := filepath.Glob("/proc/[0-9]*/comm")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range procs {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		comm := strings.ToLower(strings.TrimSpace(string(data)))
		if comm == "" || seen[comm] {
			continue
		}
		seen[comm] = true
		out = append(out, comm)
	}
	return out
}

// portOwner returns the comm of the process listening on the given TCP port,
// or "" when the port is free or the owner cannot be determined.
func portOwner(port int) string {
	inodes := listeningInodes(port)
	if len(inodes) == 0 {
		return ""
	}
	fds, err := filepath.Glob("/proc/[0-9]*/fd/*")
	if err != nil {
		return ""
	}
	for _, fd := range fds {
		target, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if !inodes[inode] {
			continue
		}
		pid := fdPID(fd)
		if pid == "" {
			continue
		}
		if data, err := os.ReadFile("/proc/" + pid + "/comm"); err == nil {
			return strings.ToLower(strings.TrimSpace(string(data)))
		}
	}
	return ""
}

func fdPID(fdPath string) string {
	rest := strings.TrimPrefix(fdPath, "/proc/")
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return ""
	}
	return rest[:i]
}

// listeningInodes collects the socket inodes of TCP listeners bound to the
// given port, from both the IPv4 and IPv6 tables.
func listeningInodes(port int) map[string]bool {
	out := map[string]bool{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] { // skip header
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			if f[3] != "0A" { // TCP_LISTEN
				continue
			}
			local := f[1]
			colon := strings.LastIndexByte(local, ':')
			if colon < 0 {
				continue
			}
			p, err := strconv.ParseInt(local[colon+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			out[f[9]] = true
		}
	}
	return out
}

// hostOnly strips a trailing :port from a Host header value.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
