package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PeerRecord struct {
	PublicKey    string    `json:"public_key"`
	AllowedIP    string   `json:"allowed_ip"`
	DeviceID     string   `json:"device_id,omitempty"`
	DeviceName   string   `json:"device_name,omitempty"`
	PreSharedKey string   `json:"preshared_key,omitempty"`
	AddedAt      time.Time `json:"added_at"`
}

type PeerStore struct {
	mu      sync.RWMutex
	peers   map[string]*PeerRecord
	filePath string
}

func NewPeerStore(dataDir string) *PeerStore {
	return &PeerStore{
		peers:    make(map[string]*PeerRecord),
		filePath: filepath.Join(dataDir, "peers.json"),
	}
}

func (ps *PeerStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read peers file: %w", err)
	}

	var records []*PeerRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("parse peers file: %w", err)
	}

	for _, r := range records {
		ps.peers[r.PublicKey] = r
	}
	return nil
}

func (ps *PeerStore) Save() error {
	ps.mu.RLock()
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

func (ps *PeerStore) Add(rec *PeerRecord) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.peers[rec.PublicKey] = rec
}

func (ps *PeerStore) Remove(publicKey string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.peers, publicKey)
}

func (ps *PeerStore) Get(publicKey string) *PeerRecord {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.peers[publicKey]
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
