package api

import (
	"fmt"
	"strconv"
	"strings"

	"tanguard/domain"
)

// ─── domain ──────────────────────────────────────────────────────────────

func cmdDomain(s *consoleSession, args []string) {
	a := s.api
	if a.dom == nil {
		s.errf("domain reverse proxy is disabled (set DOMAIN_ENABLED=true)")
		return
	}
	verb := "list"
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}

	switch verb {
	case "list", "":
		items := a.dom.List()
		if len(items) == 0 {
			s.printf("no domain mappings — `domain add app.example.com --trp <ref>` creates one\r\n")
			printDomainStatus(s)
			return
		}
		var rows [][]string
		for _, item := range items {
			stateText := "disabled"
			if en, ok := item["enabled"].(bool); ok && en {
				stateText = "enabled"
			}
			target := fmt.Sprint(item["target"])
			if note, ok := item["target_note"].(string); ok && note != "" {
				target = note
			} else if target == "" {
				target = paint(ansiRed, "unresolved")
			}
			rows = append(rows, []string{
				paint(ansiBold, fmt.Sprint(item["domain"])),
				fmt.Sprint(item["backend"]),
				target,
				stateText,
			})
		}
		s.table([]string{"DOMAIN", "BACKEND", "TARGET", "STATE"}, rows)
		s.notef("state strings are not colored; use the dashboard for live TLS status")
		printDomainStatus(s)

	case "add":
		var pos []string
		backend := domain.Backend("")
		proxyRef, targetIP := "", ""
		targetPort := 0
		enabled := true
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--trp":
				if i+1 >= len(args) {
					s.errf("--trp needs the mapping reference")
					return
				}
				proxyRef = args[i+1]
				backend = domain.BackendTRP
				i++
			case "--wg":
				if i+2 >= len(args) {
					s.errf("--wg needs an IP and a port")
					return
				}
				n, err := strconv.Atoi(args[i+2])
				if err != nil || n < 1 || n > 65535 {
					s.errf("--wg port must be between 1 and 65535")
					return
				}
				targetIP = args[i+1]
				targetPort = n
				backend = domain.BackendWG
				i += 2
			case "--enable":
				enabled = true
			case "--disable":
				enabled = false
			default:
				if strings.HasPrefix(args[i], "--") {
					s.errf("unknown flag %s — usage: %s", args[i], lookupCommand("domain").usage)
					return
				}
				pos = append(pos, args[i])
			}
		}
		if len(pos) != 1 {
			s.errf("usage: domain add <domain> --trp <ref> | --wg <ip> <port> [--disable]")
			return
		}
		rec, err := a.dom.Add(domain.AddRequest{
			Domain:     pos[0],
			Backend:    backend,
			ProxyRef:   proxyRef,
			TargetIP:   targetIP,
			TargetPort: targetPort,
			Enabled:    enabled,
		})
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("%s %s → %s\r\n", paint(ansiGreen, "mapped"), paint(ansiBold, rec.Domain), a.domBackendDesc(rec.ID))
		s.notef("a TLS certificate is requested automatically on first request")

	case "update":
		if len(args) < 2 {
			s.errf("usage: domain update <ref> [--domain name] [--enable on|off] [--trp <ref> | --wg <ip> <port>]")
			return
		}
		id, err := a.resolveDomain(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		rest := args[1:]
		var newDomain string
		var enabled *bool
		in := domain.AddRequest{}
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--domain":
				if i+1 >= len(rest) {
					s.errf("--domain needs a name")
					return
				}
				newDomain = rest[i+1]
				i++
			case "--enable", "--disable":
				v := rest[i] == "--enable"
				enabled = &v
			case "--trp":
				if i+1 >= len(rest) {
					s.errf("--trp needs the mapping reference")
					return
				}
				in.Backend = domain.BackendTRP
				in.ProxyRef = rest[i+1]
				i++
			case "--wg":
				if i+2 >= len(rest) {
					s.errf("--wg needs an IP and a port")
					return
				}
				n, err := strconv.Atoi(rest[i+2])
				if err != nil || n < 1 || n > 65535 {
					s.errf("--wg port must be between 1 and 65535")
					return
				}
				in.Backend = domain.BackendWG
				in.TargetIP = rest[i+1]
				in.TargetPort = n
				i += 2
			default:
				s.errf("unknown flag %s", rest[i])
				return
			}
		}
		rec, err := a.dom.Update(id, newDomain, enabled, in)
		if err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("%s %s → %s (%s)\r\n", paint(ansiGreen, "updated"), paint(ansiBold, rec.Domain), a.domBackendDesc(rec.ID), onOff(rec.Enabled))

	case "remove":
		if len(args) != 1 {
			s.errf("usage: domain remove <ref>")
			return
		}
		id, err := a.resolveDomain(args[0])
		if err != nil {
			s.errf("%s", err)
			return
		}
		if err := a.dom.Remove(id); err != nil {
			s.errf("%s", err)
			return
		}
		s.printf("%s %s\r\n", paint(ansiGreen, "removed"), id)

	default:
		s.errf("usage: %s", lookupCommand("domain").usage)
	}
}

func printDomainStatus(s *consoleSession) {
	st := s.api.dom.Status()
	mode := fmt.Sprint(st["mode"])
	web := fmt.Sprint(st["webserver"])
	switch {
	case web != "":
		s.stat("serving", fmt.Sprintf("%s (writes into %s)", paint(ansiGreen, "external webserver"), paint(ansiBold, web)))
	case mode == "builtin":
		s.stat("serving", fmt.Sprintf("%s on :%v → :%v", paint(ansiGreen, "built-in proxy"), st["http_port"], st["https_port"]))
	case mode == "blocked":
		s.stat("serving", paint(ansiRed, "blocked")+paint(ansiDim, " — "+fmt.Sprint(st["error"])))
	default:
		s.stat("serving", paint(ansiDim, "idle"))
	}
	if e := fmt.Sprint(st["error"]); e != "" {
		s.notef("last error: %s", e)
	}
}

// domBackendDesc resolves a record id to a human description for messages.
func (a *API) domBackendDesc(id string) string {
	for _, item := range a.dom.List() {
		if fmt.Sprint(item["id"]) == id {
			if note, ok := item["target_note"].(string); ok && note != "" {
				return note
			}
			return fmt.Sprint(item["backend"])
		}
	}
	return id
}

// resolveDomain accepts a domain name, a mapping id, or a unique prefix of
// either.
func (a *API) resolveDomain(ref string) (string, error) {
	if a.dom == nil {
		return "", fmt.Errorf("domain reverse proxy is disabled")
	}
	items := a.dom.List()
	matches := map[string]bool{}
	for _, item := range items {
		id := fmt.Sprint(item["id"])
		name := fmt.Sprint(item["domain"])
		if id == ref || strings.EqualFold(name, ref) {
			return id, nil
		}
		if strings.HasPrefix(strings.ToLower(id), strings.ToLower(ref)) ||
			strings.HasPrefix(strings.ToLower(name), strings.ToLower(ref)) {
			matches[id] = true
		}
	}
	switch len(matches) {
	case 1:
		for id := range matches {
			return id, nil
		}
	case 0:
		return "", fmt.Errorf("no domain mapping matches %q", ref)
	}
	return "", fmt.Errorf("%q matches several mappings", ref)
}

func completeDomain(s *consoleSession, rest []string) []string {
	a := s.api
	if a.dom == nil || len(rest) == 0 {
		return nil
	}
	switch {
	case len(rest) == 1 && (rest[0] == "remove" || rest[0] == "update"):
		var names []string
		for _, item := range a.dom.List() {
			names = append(names, fmt.Sprint(item["domain"]))
		}
		return names
	case len(rest) == 1 && rest[0] == "add":
		return nil
	case rest[len(rest)-1] == "--trp" && a.trp != nil:
		var ids []string
		for _, p := range a.trp.ListProxies() {
			ids = append(ids, fmt.Sprint(p["id"]))
		}
		return ids
	}
	return nil
}
