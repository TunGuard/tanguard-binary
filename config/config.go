package config

import (
	"os"
	"strconv"
)

type Config struct {
	InterfaceName string
	ListenPort    int
	Address       string
	Subnet        string
	MTU           int
	APIListen     string
	DataDir       string
	PrivateKey    string
	LogLevel      int
	ExternalNIC   string

	WebEnabled  bool
	WebListen   string
	WebUsername string
	WebPassword string

	SSHEnabled bool
	SSHListen  string
	SSHKeyFile string

	TLSCertFile string
	TLSKeyFile  string

	// Domain reverse proxy: public domain names in front of local services,
	// served by this process directly (built-in proxy) or written into the
	// machine's webserver. DomainHTTPPort/DomainHTTPSPort are the built-in
	// proxy's ports; DomainChallengePort is the loopback port the ACME
	// http-01 challenge is answered on when an external webserver proxies
	// /.well-known/acme-challenge/ to this process.
	DomainEnabled       bool
	DomainHTTPPort      int
	DomainHTTPSPort     int
	DomainChallengePort int

	// AdGuard Home integration: optional DNS filtering service. When enabled,
	// TunGuard will manage an AdGuard Home instance and allow policy groups to
	// opt into its filtered DNS.
	AdGuardEnabled        bool
	AdGuardBinaryPath     string
	AdGuardDataDir        string
	AdGuardDNSListen      string
	AdGuardWebListen      string
	AdGuardUpstream       string
	AdGuardUpstreamFamily string
	AdGuardFilterAdult    bool
}

// LoadConfig builds the server configuration from the environment, applying the
// documented defaults for anything that is not set.
func LoadConfig() *Config {
	return &Config{
		InterfaceName: EnvStr("WG_INTERFACE", "wg0"),
		ListenPort:    EnvInt("WG_LISTEN_PORT", 13231),
		Address:       EnvStr("WG_ADDRESS", "10.100.0.1/24"),
		Subnet:        EnvStr("WG_SUBNET", "10.100.0.0/24"),
		MTU:           EnvInt("WG_MTU", 1420),
		APIListen:     EnvStr("API_LISTEN", ":9000"),
		DataDir:       EnvStr("DATA_DIR", "."),
		PrivateKey:    EnvStr("WG_PRIVATE_KEY", ""),
		LogLevel:      EnvInt("WG_LOG_LEVEL", 2),
		ExternalNIC:   EnvStr("EXTERNAL_NIC", ""),

		WebEnabled:  EnvStr("WEB_ENABLED", "false") == "true",
		WebListen:   EnvStr("WEB_LISTEN", ":8080"),
		WebUsername: EnvStr("WEB_USERNAME", "admin"),
		WebPassword: EnvStr("WEB_PASSWORD", "tanguard"),

		SSHEnabled: EnvStr("SSH_ENABLED", "false") == "true",
		SSHListen:  EnvStr("SSH_LISTEN", ":2222"),
		SSHKeyFile: EnvStr("SSH_KEY_FILE", ""),

		TLSCertFile: EnvStr("TLS_CERT_FILE", ""),
		TLSKeyFile:  EnvStr("TLS_KEY_FILE", ""),

		DomainEnabled:       EnvStr("DOMAIN_ENABLED", "true") == "true",
		DomainHTTPPort:      EnvInt("DOMAIN_HTTP_PORT", 80),
		DomainHTTPSPort:     EnvInt("DOMAIN_HTTPS_PORT", 443),
		DomainChallengePort: EnvInt("DOMAIN_CHALLENGE_PORT", 8100),

		AdGuardEnabled:        EnvStr("ADGUARD_ENABLED", "false") == "true",
		AdGuardBinaryPath:     EnvStr("ADGUARD_BINARY", "adguardhome"),
		AdGuardDataDir:        EnvStr("ADGUARD_DATA_DIR", EnvStr("DATA_DIR", ".")),
		AdGuardDNSListen:      EnvStr("ADGUARD_DNS_LISTEN", "10.100.0.1:53"),
		AdGuardWebListen:      EnvStr("ADGUARD_WEB_LISTEN", "127.0.0.1:3000"),
		AdGuardUpstream:       EnvStr("ADGUARD_UPSTREAM", "1.1.1.1"),
		AdGuardUpstreamFamily: EnvStr("ADGUARD_UPSTREAM_FAMILY", "1.1.1.2"),
		AdGuardFilterAdult:    EnvStr("ADGUARD_FILTER_ADULT", "false") == "true",
	}
}

// EnvStr returns the environment value for key, or def when it is unset or empty.
func EnvStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvInt returns the environment value for key as an integer, falling back to def
// when it is unset or not a number.
func EnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
