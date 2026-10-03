package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type PeerRecord struct {
	PublicKey        string    `json:"public_key"`
	AllowedIP        string    `json:"allowed_ip"`
	DeviceID         string    `json:"device_id,omitempty"`
	DeviceName       string    `json:"device_name,omitempty"`
	PreSharedKey     string    `json:"preshared_key,omitempty"`
	ClientPrivateKey string    `json:"client_private_key,omitempty"`
	AddedAt          time.Time `json:"added_at"`
}

type PeerStore struct {
	mu       sync.RWMutex
	peers    map[string]*PeerRecord
	filePath string
	loaded   bool
	// byIP and byDevice are reverse indexes over peers. The policy packet
	// filter has to resolve a tunnel address back to a peer on every packet,
	// so those lookups cannot afford to walk the whole map.
	byIP     map[uint32]string // tunnel ip -> public key
	byDevice map[string]string // device id -> public key
}

func NewPeerStore(dataDir string) *PeerStore {
	return &PeerStore{
		peers:    make(map[string]*PeerRecord),
		byIP:     make(map[uint32]string),
		byDevice: make(map[string]string),
		filePath: filepath.Join(dataDir, "peers.json"),
	}
}

// indexLocked records a peer's address mappings. Callers must hold ps.mu.
func (ps *PeerStore) indexLocked(r *PeerRecord) {
	if ip, ok := allowedIPToUint32(r.AllowedIP); ok {
		ps.byIP[ip] = r.PublicKey
	}
	if r.DeviceID != "" {
		ps.byDevice[r.DeviceID] = r.PublicKey
	}
}

// unindexLocked clears a peer's address mappings. Callers must hold ps.mu.
func (ps *PeerStore) unindexLocked(r *PeerRecord) {
	if ip, ok := allowedIPToUint32(r.AllowedIP); ok {
		if ps.byIP[ip] == r.PublicKey {
			delete(ps.byIP, ip)
		}
	}
	if r.DeviceID != "" {
		if ps.byDevice[r.DeviceID] == r.PublicKey {
			delete(ps.byDevice, r.DeviceID)
		}
	}
}

// allowedIPToUint32 turns a peer's AllowedIP CIDR into the bare tunnel address.
// The prefix length is ignored on purpose: WireGuard peers hold a single /32
// here, and the policy filter matches on the address a packet carries.
func allowedIPToUint32(allowedIP string) (uint32, bool) {
	ip, _, err := net.ParseCIDR(strings.TrimSpace(allowedIP))
	if err != nil {
		ip = net.ParseIP(strings.TrimSpace(allowedIP))
		if ip == nil {
			return 0, false
		}
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

func (ps *PeerStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.loaded = false
	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			ps.loaded = true
			return nil
		}
		return fmt.Errorf("read peers file: %w", err)
	}

	var records []*PeerRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("parse peers file: %w", err)
	}

	ps.peers = make(map[string]*PeerRecord, len(records))
	ps.byIP = make(map[uint32]string, len(records))
	ps.byDevice = make(map[string]string, len(records))
	for _, r := range records {
		ps.peers[r.PublicKey] = r
		ps.indexLocked(r)
	}
	ps.loaded = true
	return nil
}

func (ps *PeerStore) Save() error {
	ps.mu.RLock()
	// Never overwrite an existing peers.json that we failed to load.
	// This protects user state when the file is unreadable or corrupt.
	if !ps.loaded {
		ps.mu.RUnlock()
		return nil
	}
	var records []*PeerRecord
	for _, r := range ps.peers {
		records = append(records, r)
	}
	ps.mu.RUnlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal peers: %w", err)
	}

	tmp := ps.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write peers file: %w", err)
	}
	return os.Rename(tmp, ps.filePath)
}

// Add inserts a peer record, preserving the existing record untouched if a
// peer with the same public key already exists. Never overwrites or regresses
// existing peers (their AllowedIP, keys and timestamps stay intact).
func (ps *PeerStore) Add(rec *PeerRecord) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, ok := ps.peers[rec.PublicKey]; ok {
		return
	}
	ps.peers[rec.PublicKey] = rec
	ps.indexLocked(rec)
}

func (ps *PeerStore) Remove(publicKey string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if r, ok := ps.peers[publicKey]; ok {
		ps.unindexLocked(r)
	}
	delete(ps.peers, publicKey)
}

func (ps *PeerStore) Get(publicKey string) *PeerRecord {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.peers[publicKey]
}

// PublicKeyForIP resolves a tunnel address to the peer that owns it. The policy
// packet filter calls this on every packet it evaluates.
func (ps *PeerStore) PublicKeyForIP(ip uint32) (string, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	key, ok := ps.byIP[ip]
	return key, ok
}

// PublicKeyForDeviceID resolves a device id to its peer. The mesh control plane
// uses it to work out which policy group a tun node belongs to.
func (ps *PeerStore) PublicKeyForDeviceID(deviceID string) (string, bool) {
	if deviceID == "" {
		return "", false
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	key, ok := ps.byDevice[deviceID]
	return key, ok
}

func (ps *PeerStore) AllowedIPInUse(allowedIP string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	needle := strings.Split(allowedIP, "/")[0]
	for _, r := range ps.peers {
		if strings.Split(r.AllowedIP, "/")[0] == needle {
			return true
		}
	}
	return false
}

func (ps *PeerStore) All() []*PeerRecord {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	var out []*PeerRecord
	for _, r := range ps.peers {
		out = append(out, r)
	}
	return out
}
