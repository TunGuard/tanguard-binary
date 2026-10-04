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
