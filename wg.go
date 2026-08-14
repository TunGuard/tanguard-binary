package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type WgServer struct {
	dev     *device.Device
	logger  *device.Logger
	cfg     *Config
	privKey string
	pubKey  string
	store   *PeerStore
}

func NewWgServer(cfg *Config, store *PeerStore) (*WgServer, error) {
	runCmd("ip", "link", "del", cfg.InterfaceName)

	tunDevice, err := tun.CreateTUN(cfg.InterfaceName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	log.Printf("[wg] TUN device %s created (MTU %d)", cfg.InterfaceName, cfg.MTU)

	setupInterface(cfg)

	logger := device.NewLogger(cfg.LogLevel, "tanguard: ")
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDevice, bind, logger)
	log.Printf("[wg] device created, listen port %d", cfg.ListenPort)

	return &WgServer{dev: dev, logger: logger, cfg: cfg, store: store}, nil
}

func (s *WgServer) Configure(privateKeyHex string, listenPort int) error {
	pub, err := PrivToPub(privateKeyHex)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	s.privKey = privateKeyHex
	s.pubKey = pub

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privateKeyHex)
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	return s.dev.IpcSet(b.String())
}

func (s *WgServer) ApplyAllPeers() error {
	var b strings.Builder
	fmt.Fprintf(&b, "replace_peers=true\n")

	for _, rec := range s.store.All() {
		fmt.Fprintf(&b, "public_key=%s\n", rec.PublicKey)
		if rec.PreSharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", rec.PreSharedKey)
		}
		fmt.Fprintf(&b, "replace_allowed_ips=true\n")
		fmt.Fprintf(&b, "allowed_ip=%s\n", rec.AllowedIP)
	}

	return s.dev.IpcSet(b.String())
}

func (s *WgServer) AddPeer(publicKeyHex, allowedIP, pskHex string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", publicKeyHex)
	if pskHex != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
	}
	fmt.Fprintf(&b, "allowed_ip=%s\n", allowedIP)
	return s.dev.IpcSet(b.String())
}

func (s *WgServer) RemovePeer(publicKeyHex string) error {
	return s.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", publicKeyHex))
}

type PeerStatus struct {
	PublicKey           string `json:"public_key"`
	AllowedIPs          string `json:"allowed_ips"`
	Endpoint            string `json:"endpoint"`
	LastHandshakeSec    int64  `json:"last_handshake_sec"`
	LastHandshakeNsec   int64  `json:"last_handshake_nsec"`
	TxBytes             int64  `json:"tx_bytes"`
	RxBytes             int64  `json:"rx_bytes"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	ProtocolVersion     int    `json:"protocol_version"`
}

type DeviceStatus struct {
	ServerPublicKey string       `json:"server_public_key"`
	PrivateKeySet   bool         `json:"private_key_set"`
	ListenPort      int          `json:"listen_port"`
	FwMark          int          `json:"fwmark"`
	Peers           []PeerStatus `json:"peers"`
}

func (s *WgServer) GetStatus() (*DeviceStatus, error) {
	raw, err := s.dev.IpcGet()
	if err != nil {
		return nil, fmt.Errorf("ipc get: %w", err)
	}
	status := ParseIpcGet(raw)
	status.ServerPublicKey = s.pubKey
	return status, nil
}

func (s *WgServer) PublicKey() string {
	return s.pubKey
}

func (s *WgServer) Close() {
	s.dev.Close()
}

func (s *WgServer) SetPrivateKey(hexKey string) error {
	pub, err := PrivToPub(hexKey)
	if err != nil {
		return err
	}
	s.privKey = hexKey
	s.pubKey = pub
	return s.dev.IpcSet(fmt.Sprintf("private_key=%s\n", hexKey))
}

func (s *WgServer) LoadSavedPrivateKey() (string, error) {
	privKey := s.cfg.PrivateKey
	keyFile := s.cfg.DataDir + "/server_private.key"
	if privKey == "" {
		data, err := readFile(keyFile)
		if err == nil {
			privKey = strings.TrimSpace(string(data))
		} else if !os.IsNotExist(err) {
			// The key file exists but is unreadable. Never rotate the key on
			// an update/restart in this situation: doing so would invalidate
			// every connected client. Fail loudly instead.
			return "", fmt.Errorf("read saved private key %s: %w", keyFile, err)
		}
	}
	if privKey == "" {
		priv, _, err := GenerateKeyPair()
		if err != nil {
			return "", fmt.Errorf("generate key: %w", err)
		}
		privKey = hex.EncodeToString(priv)
		if err := writeFile(keyFile, []byte(privKey), 0600); err != nil {
			log.Printf("[wg] WARNING: could not save private key: %v", err)
		} else {
			log.Printf("[wg] new server keypair generated and saved")
		}
	}
	return privKey, nil
}

func ParseIpcGet(raw string) *DeviceStatus {
	status := &DeviceStatus{}
	lines := strings.Split(raw, "\n")

	currentPeer := -1
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx < 0 {
			continue
		}
		key := line[:eqIdx]
		val := line[eqIdx+1:]

		switch key {
		case "private_key":
			status.PrivateKeySet = val != strings.Repeat("0", 64)
		case "listen_port":
			status.ListenPort, _ = strconv.Atoi(val)
		case "fwmark":
			status.FwMark, _ = strconv.Atoi(val)
		case "public_key":
			status.Peers = append(status.Peers, PeerStatus{})
			currentPeer = len(status.Peers) - 1
			status.Peers[currentPeer].PublicKey = val
		default:
			if currentPeer >= 0 && currentPeer < len(status.Peers) {
				p := &status.Peers[currentPeer]
				switch key {
				case "endpoint":
					p.Endpoint = val
				case "allowed_ip":
					if p.AllowedIPs != "" {
						p.AllowedIPs += ", " + val
					} else {
						p.AllowedIPs = val
					}
				case "tx_bytes":
					p.TxBytes, _ = strconv.ParseInt(val, 10, 64)
				case "rx_bytes":
					p.RxBytes, _ = strconv.ParseInt(val, 10, 64)
				case "last_handshake_time_sec":
					p.LastHandshakeSec, _ = strconv.ParseInt(val, 10, 64)
				case "last_handshake_time_nsec":
					p.LastHandshakeNsec, _ = strconv.ParseInt(val, 10, 64)
				case "persistent_keepalive_interval":
					p.PersistentKeepalive, _ = strconv.Atoi(val)
				case "protocol_version":
					p.ProtocolVersion, _ = strconv.Atoi(val)
				}
			}
		}
	}
	return status
}

func GeneratePrivateKey() (string, error) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv), nil
}
