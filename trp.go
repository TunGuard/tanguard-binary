package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TRProxy is a persisted reverse-proxy binding: a public port on the VPS that
// is pulled through a registered tun node to a service on the node side.
type TRProxy struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	Name       string    `json:"name,omitempty"`
	BindIP     string    `json:"bind_ip,omitempty"`
	BindPort   int       `json:"bind_port"`
	TargetIP   string    `json:"target_ip,omitempty"`
	TargetPort int       `json:"target_port"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// TRPManager owns all reverse-proxy bindings.
type TRPManager struct {
	mu       sync.Mutex
	hub      *MeshHub
	path     string
	proxies  []*TRProxy
	byID     map[string]*TRProxy
	bindings map[string]*trpBinding
	active   map[string]int64
}

type trpBinding struct {
	id    string
	proxy *TRProxy
	ln    net.Listener
	stop  chan struct{}
}

func NewTRPManager(h *MeshHub, path string) *TRPManager {
	return &TRPManager{
		hub:      h,
		path:     path,
		byID:     make(map[string]*TRProxy),
		bindings: make(map[string]*trpBinding),
		active:   make(map[string]int64),
	}
}

// Restore re-binds every persisted, enabled proxy after startup.
func (tm *TRPManager) Restore() error {
	data, err := os.ReadFile(tm.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read proxies file: %w", err)
	}
	var recs []*TRProxy
	if err := json.Unmarshal(data, &recs); err != nil {
		return fmt.Errorf("parse proxies file: %w", err)
	}
	for _, p := range recs {
		if p.ID == "" || !p.Enabled {
			continue
		}
		if err := tm.bind(p, false); err != nil {
			log.Printf("[trp] restore %s (%s:%d): %v", p.ID, p.BindIP, p.BindPort, err)
			continue
		}
		log.Printf("[trp] restored binding %s -> %s:%d source %s:%d", p.ID, p.NodeID, p.TargetPort, p.BindIP, p.BindPort)
	}
	return nil
}

func (tm *TRPManager) save() error {
	tm.mu.Lock()
	proxies := make([]*TRProxy, len(tm.proxies))
	copy(proxies, tm.proxies)
	tm.mu.Unlock()
	return tm.writeFile(proxies)
}

// writeFile persists a snapshot of the registry. The caller must not hold
// tm.mu — saveLocked is the variant for when it is already held.
func (tm *TRPManager) writeFile(proxies []*TRProxy) error {
	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return err
	}
	tmp := tm.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, tm.path)
}

// CreateProxy validates, binds and registers a new reverse proxy.
func (tm *TRPManager) CreateProxy(nodeID, bindIP string, bindPort, targetPort int, targetIP string) (*TRProxy, error) {
	if tm.hub.getNode(nodeID) == nil {
		return nil, fmt.Errorf("unknown node")
	}
	if !tm.hub.trpAllowed(nodeID) {
		return nil, fmt.Errorf("the device's policy group does not allow TRP port mapping")
	}
	rec := &TRProxy{
		ID:         meshShortID(),
		NodeID:     nodeID,
		BindIP:     strings.TrimSpace(bindIP),
		BindPort:   bindPort,
		TargetIP:   strings.TrimSpace(targetIP),
		TargetPort: targetPort,
		Enabled:    true,
		CreatedAt:  time.Now(),
	}
	if rec.BindIP == "" {
		rec.BindIP = "0.0.0.0"
	}
	if rec.TargetIP == "" {
		rec.TargetIP = "127.0.0.1"
	}
	if err := tm.bind(rec, true); err != nil {
		return nil, err
	}
	log.Printf("[trp] bound %s on %s:%d -> node %s %s:%d", rec.ID, rec.BindIP, rec.BindPort, rec.NodeID, rec.TargetIP, rec.TargetPort)
	return rec, nil
}

// bind attaches a listener for the proxy and starts accepting. duplicate=true
// appends it to the persistent registry.
//
// The port-conflict check runs *before* net.Listen so a clash reports the
// binding that already owns the port instead of a raw syscall error, and the
// snapshot for persistence is taken before the lock is taken so saving never
// re-enters tm.mu.
func (tm *TRPManager) bind(rec *TRProxy, duplicate bool) error {
	if rec.BindPort < 0 || rec.BindPort > 65535 {
		return fmt.Errorf("port %d out of range", rec.BindPort)
	}
	if rec.TargetPort < 1 || rec.TargetPort > 65535 {
		return fmt.Errorf("target port %d out of range", rec.TargetPort)
	}

	if duplicate {
		tm.mu.Lock()
		for _, p := range tm.proxies {
			if p.BindPort == rec.BindPort && p.BindIP == rec.BindIP {
				tm.mu.Unlock()
				return fmt.Errorf("port %s:%d already bound", rec.BindIP, rec.BindPort)
			}
		}
		tm.mu.Unlock()
	}

	addr := net.JoinHostPort(rec.BindIP, strconv.Itoa(rec.BindPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	if rec.BindPort == 0 {
		rec.BindPort = ln.Addr().(*net.TCPAddr).Port
	}
	b := &trpBinding{
		id:    rec.ID,
		proxy: rec,
		ln:    ln,
		stop:  make(chan struct{}),
	}

	tm.mu.Lock()
	if duplicate {
		tm.proxies = append(tm.proxies, rec)
		tm.byID[rec.ID] = rec
		snapshot := make([]*TRProxy, len(tm.proxies))
		copy(snapshot, tm.proxies)
		tm.bindings[rec.ID] = b
		tm.mu.Unlock()
		if err := tm.writeFile(snapshot); err != nil {
			log.Printf("[trp] WARNING: failed to persist proxy: %v", err)
		}
	} else {
		tm.bindings[rec.ID] = b
		tm.mu.Unlock()
	}
	go tm.bindingLoop(b)
	return nil
}

// RemoveProxy closes a binding's listener and drops it from the registry.
func (tm *TRPManager) RemoveProxy(id string) error {
	tm.mu.Lock()
	b := tm.bindings[id]
	rec := tm.byID[id]
	if b != nil {
		close(b.stop)
		b.ln.Close()
		delete(tm.bindings, id)
	}
	if rec != nil {
		delete(tm.byID, id)
		for i, p := range tm.proxies {
			if p.ID == id {
				tm.proxies = append(tm.proxies[:i], tm.proxies[i+1:]...)
				break
			}
		}
	}
	tm.mu.Unlock()
	if rec == nil {
		return fmt.Errorf("binding not found")
	}
	log.Printf("[trp] unbound %s from %s:%d", id, rec.BindIP, rec.BindPort)
	return tm.save()
}

func (tm *TRPManager) bindingLoop(b *trpBinding) {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			select {
			case <-b.stop:
				return
			default:
			}
			if isTemporary(err) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go tm.servePublic(b, c)
	}
}

// servePublic bridges one public connection to a fresh dial-back from the
// node. It binds a short-lived ephemeral listener and tells the node to dial
// that exact port, so the dial-back can never be confused with a new public
// connection.
func (tm *TRPManager) servePublic(b *trpBinding, pub net.Conn) {
	defer pub.Close()

	// Checked here as well as at bind time so moving a device into a
	// restrictive group takes effect on proxies that are already listening:
	// the connection is simply closed, exactly like a device that is offline.
	if !tm.hub.trpAllowed(b.proxy.NodeID) {
		log.Printf("[trp] %s denied by policy group, dropping connection to %s:%d",
			b.proxy.NodeID, b.proxy.BindIP, b.proxy.BindPort)
		return
	}

	node := tm.hub.getConn(b.proxy.NodeID)
	if node == nil {
		log.Printf("[trp] %s->%s:%d: node offline, dropping connection", b.proxy.NodeID, b.proxy.BindIP, b.proxy.BindPort)
		return
	}

	hook, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer hook.Close()
	tmpPort := hook.Addr().(*net.TCPAddr).Port

	ip4 := net.ParseIP(b.proxy.TargetIP)
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	v4 := ip4.To4()
	if v4 == nil {
		v4 = net.IPv4(127, 0, 0, 1).To4()
	}
	var payload [8]byte
	copy(payload[0:4], v4)
	binary.BigEndian.PutUint16(payload[4:6], uint16(b.proxy.TargetPort))
	binary.BigEndian.PutUint16(payload[6:8], uint16(tmpPort))

	if err := node.sendCommand(cmdTRP, payload); err != nil {
		log.Printf("[trp] %s command failed: %v", b.proxy.NodeID, err)
		return
	}

	hook.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second))
	back, err := hook.Accept()
	if err != nil {
		return
	}

	tm.mu.Lock()
	tm.active[b.id]++
	tm.mu.Unlock()
	defer func() {
		back.Close()
		tm.mu.Lock()
		tm.active[b.id]--
		tm.mu.Unlock()
	}()

	bridgeConns(pub, back)
}

func bridgeConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, a); done <- struct{}{} }()
	go func() { io.Copy(a, b); done <- struct{}{} }()
	<-done
}

func isTemporary(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Temporary() && !ne.Timeout()
	}
	return false
}

// listProxies returns the bindings with live status attached.
func (tm *TRPManager) listProxies() []map[string]interface{} {
	tm.mu.Lock()
	proxies := make([]*TRProxy, len(tm.proxies))
	copy(proxies, tm.proxies)
	active := make(map[string]int64, len(tm.active))
	for k, v := range tm.active {
		active[k] = v
	}
	tm.mu.Unlock()

	// Empty slice, not nil, so the dashboard gets [] and can render it directly.
	out := []map[string]interface{}{}
	for _, p := range proxies {
		nodeName := p.NodeID
		if rec := tm.hub.getNode(p.NodeID); rec != nil {
			nodeName = rec.Name
		}
		out = append(out, map[string]interface{}{
			"id":          p.ID,
			"node_id":     p.NodeID,
			"node_name":   nodeName,
			"online":      tm.hub.getConn(p.NodeID) != nil,
			"bind_ip":     p.BindIP,
			"bind_port":   p.BindPort,
			"public_url":  fmt.Sprintf("%s:%d", p.BindIP, p.BindPort),
			"target_ip":   p.TargetIP,
			"target_port": p.TargetPort,
			"active":      active[p.ID],
			"created_at":  p.CreatedAt.Format(time.RFC3339),
		})
	}
	return out
}
