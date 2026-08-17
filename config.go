package main

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

	SSHEnabled  bool
	SSHListen   string
	SSHKeyFile  string

	TLSCertFile string
	TLSKeyFile  string
}

func loadConfig() *Config {
	return &Config{
		InterfaceName: envStr("WG_INTERFACE", "wg0"),
		ListenPort:    envInt("WG_LISTEN_PORT", 13231),
		Address:       envStr("WG_ADDRESS", "10.100.0.1/24"),
		Subnet:        envStr("WG_SUBNET", "10.100.0.0/24"),
		MTU:           envInt("WG_MTU", 1420),
		APIListen:     envStr("API_LISTEN", ":9000"),
		DataDir:       envStr("DATA_DIR", "."),
		PrivateKey:    envStr("WG_PRIVATE_KEY", ""),
		LogLevel:      envInt("WG_LOG_LEVEL", 2),
		ExternalNIC:   envStr("EXTERNAL_NIC", ""),

		WebEnabled:  envStr("WEB_ENABLED", "false") == "true",
		WebListen:   envStr("WEB_LISTEN", ":8080"),
		WebUsername: envStr("WEB_USERNAME", "admin"),
		WebPassword: envStr("WEB_PASSWORD", "tanguard"),

		SSHEnabled:  envStr("SSH_ENABLED", "false") == "true",
		SSHListen:   envStr("SSH_LISTEN", ":2222"),
		SSHKeyFile:  envStr("SSH_KEY_FILE", ""),

		TLSCertFile: envStr("TLS_CERT_FILE", ""),
		TLSKeyFile:  envStr("TLS_KEY_FILE", ""),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
