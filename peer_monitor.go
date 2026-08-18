package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

type peerMonitorEvent struct {
	Timestamp time.Time `json:"t"`
	Peer      string    `json:"peer"`
	Event     string    `json:"event"`
	Detail    string    `json:"detail,omitempty"`
}

type peerSnapshot struct {
	handshake int64
	endpoint  string
	txBytes   int64
	rxBytes   int64
}

type PeerMonitor struct {
	mu        sync.Mutex
	wg        *WgServer
	events    []peerMonitorEvent
	snapshots map[string]peerSnapshot
	pollInt   time.Duration
	maxEvents int
}

func NewPeerMonitor(wg *WgServer) *PeerMonitor {
	return &PeerMonitor{
		wg:        wg,
		events:    make([]peerMonitorEvent, 0, 512),
		snapshots: make(map[string]peerSnapshot),
		pollInt:   2 * time.Second,
		maxEvents: 1000,
	}
}

func (pm *PeerMonitor) Start() {
	go pm.loop()
	log.Printf("[monitor] started (poll=%s, buffer=%d)", pm.pollInt, pm.maxEvents)
}

func (pm *PeerMonitor) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.events = nil
}

func peerShortKey(pubKey string) string {
	if len(pubKey) >= 8 {
		return pubKey[:8]
	}
	return pubKey
}

func (pm *PeerMonitor) emit(peer, event, detail string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	e := peerMonitorEvent{
		Timestamp: time.Now(),
		Peer:      peerShortKey(peer),
		Event:     event,
		Detail:    detail,
	}
	pm.events = append(pm.events, e)
	if len(pm.events) > pm.maxEvents {
		pm.events = pm.events[len(pm.events)-pm.maxEvents:]
	}
	log.Printf("[monitor] %s %s %s", e.Peer, e.Event, e.Detail)
}

func (pm *PeerMonitor) poll() {
	status, err := pm.wg.GetStatus()
	if err != nil {
		log.Printf("[monitor] poll error: %v", err)
		return
	}

	now := time.Now()
	seen := make(map[string]bool)

	for _, p := range status.Peers {
		key := p.PublicKey
		seen[key] = true
		prev, existed := pm.snapshots[key]

		pm.mu.Lock()
		pm.snapshots[key] = peerSnapshot{
			handshake: p.LastHandshakeSec,
			endpoint:  p.Endpoint,
			txBytes:   p.TxBytes,
			rxBytes:   p.RxBytes,
		}
		pm.mu.Unlock()

		if !existed {
			pm.emit(key, "DISCOVERED", fmt.Sprintf("ip=%s endpoint=%s", p.AllowedIPs, p.Endpoint))
			continue
		}

		if p.LastHandshakeSec != prev.handshake {
			if prev.handshake == 0 && p.LastHandshakeSec != 0 {
				pm.emit(key, "HANDSHAKE_NEW", fmt.Sprintf("hs=%d endpoint=%s tx=%d rx=%d", p.LastHandshakeSec, p.Endpoint, p.TxBytes, p.RxBytes))
			} else if p.LastHandshakeSec != 0 {
				delta := p.LastHandshakeSec - prev.handshake
				pm.emit(key, "HANDSHAKE_REFRESH", fmt.Sprintf("delta=%ds endpoint=%s", delta, p.Endpoint))
			}
		}

		if p.Endpoint != prev.endpoint {
			pm.emit(key, "ENDPOINT_CHANGE", fmt.Sprintf("old=%s new=%s", prev.endpoint, p.Endpoint))
		}

		txDelta := p.TxBytes - prev.txBytes
		rxDelta := p.RxBytes - prev.rxBytes
		if txDelta != 0 || rxDelta != 0 {
			pm.emit(key, "TRAFFIC", fmt.Sprintf("tx_delta=%d rx_delta=%d tx_total=%d rx_total=%d", txDelta, rxDelta, p.TxBytes, p.RxBytes))
		}

		if prev.handshake != 0 && p.LastHandshakeSec == 0 {
			pm.emit(key, "HANDSHAKE_CLEARED", "handshake reset to zero")
		}

		secsSinceHandshake := now.Unix() - p.LastHandshakeSec
		if p.LastHandshakeSec != 0 && secsSinceHandshake > 0 && math.Abs(float64(secsSinceHandshake-97)) < 5 {
			pm.emit(key, "STALE_97S", fmt.Sprintf("handshake_age=%ds endpoint=%s", secsSinceHandshake, p.Endpoint))
		}
	}

	pm.mu.Lock()
	for key, snap := range pm.snapshots {
		if !seen[key] {
			pm.events = append(pm.events, peerMonitorEvent{
				Timestamp: now,
				Peer:      shortKey(key),
				Event:     "GONE",
				Detail:    fmt.Sprintf("last_hs=%d", snap.handshake),
			})
			delete(pm.snapshots, key)
		}
	}
	pm.mu.Unlock()
}

func (pm *PeerMonitor) loop() {
	pm.poll()
	ticker := time.NewTicker(pm.pollInt)
	defer ticker.Stop()
	for range ticker.C {
		pm.poll()
	}
}

func (pm *PeerMonitor) HandleEvents(w http.ResponseWriter, r *http.Request) {
	pm.mu.Lock()
	events := make([]peerMonitorEvent, len(pm.events))
	copy(events, pm.events)
	pm.mu.Unlock()

	since := r.URL.Query().Get("since")
	if since != "" {
		sinceTime, err := time.Parse(time.RFC3339Nano, since)
		if err == nil {
			filtered := make([]peerMonitorEvent, 0)
			for _, e := range events {
				if e.Timestamp.After(sinceTime) {
					filtered = append(filtered, e)
				}
			}
			events = filtered
		}
	}

	peer := r.URL.Query().Get("peer")
	if peer != "" {
		filtered := make([]peerMonitorEvent, 0)
		for _, e := range events {
			if strings.HasPrefix(e.Peer, peer) {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (pm *PeerMonitor) HandleState(w http.ResponseWriter, r *http.Request) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	snapshots := make(map[string]peerSnapshot)
	for k, v := range pm.snapshots {
		snapshots[shortKey(k)] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}
