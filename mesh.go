package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TUN control protocol command bytes.
const (
	cmdReset = 0x00
	cmdFRP   = 0x01
	cmdP2P   = 0x02
	cmdTRP   = 0x03
	// cmdP2PAdd / cmdP2PDel / cmdP2PClear manage a node's peer set. A node can
	// hold many simultaneous P2P peers, each in its own entry, and peers are
	// addressed by node id rather than by a server-assigned slot so both ends
	// agree on identity without extra bookkeeping.
	cmdP2PAdd   = 0x04
	cmdP2PDel   = 0x05
	cmdP2PClear = 0x06
	// cmdP2PHub points a node at the rendezvous socket. The payload is the hub
	// address; the node-id field carries the node's *own* id, which is how a
	// client learns the identity it must stamp on its hub traffic.
	cmdP2PHub = 0x07
	// cmdHubStop ends the rendezvous socket only. cmdReset would be wrong here
	// because it also tears down the node's TRP and FRP sessions.
	cmdHubStop = 0x08
)

// ctrlFrameSize is the fixed size of a server -> client command frame:
// 1 command byte, 8 payload bytes, 8 node-id bytes.
const ctrlFrameSize = 17

// ctrlStatusByte is the first byte of a client -> server status report. The
// server never sends this value, so a leading 0xFE is unambiguous.
const ctrlStatusByte = 0xFE

// ctrlStatusRecordSize is one peer's worth of status: 8 node-id bytes + flags.
const ctrlStatusRecordSize = 9

// maxP2PPerNode caps how many simultaneous peers one node keeps punched.
const maxP2PPerNode = 8

// MRPConfig configures the tun control plane. It is read from environment
// variables inside this package so the shared config.go stays untouched.
type MeshConfig struct {
	Enabled        bool
	ControlListen  string
	RelayListen    string
	ControlTimeout time.Duration
	DataDir        string
}

func meshConfigFromEnv(cfg *Config) MeshConfig {
	// MESH_DATA_DIR is the mesh subsystem's own knob, so an explicit value for
	// it wins; the server config is only the fallback. Accepting nil keeps
	// StartMesh usable on its own rather than panicking on a nil config.
	dataDir := envStr("MESH_DATA_DIR", "")
	if dataDir == "" && cfg != nil {
		dataDir = cfg.DataDir
	}
	return MeshConfig{
		Enabled:        envStr("MESH_ENABLED", "true") == "true",
		ControlListen:  envStr("CONTROL_LISTEN", ":7000"),
		RelayListen:    envStr("RELAY_LISTEN", ":7001"),
		ControlTimeout: time.Duration(envInt("CONTROL_TIMEOUT_S", 10)) * time.Second,
		DataDir:        dataDir,
	}
}

// NodeRecord is the persistent registration of a tun client node. Several
// nodes normally share one PSK: the PSK is the *group* key that devices use to
// discover each other, and DeviceID is the stable per-device identity that lets
// a reconnecting node reclaim its own record instead of registering again.
type NodeRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PSK       string    `json:"psk"`
	DeviceID  string    `json:"device_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// P2PPeer is one hole-punch target held by a node. A node can hold several at
// once; the client's identity for the peer is the node id, which is what the
// status report echoes back.
type P2PPeer struct {
	NodeID   string
	Endpoint string
	// Direct is set once the node reports it has seen a reply from the peer,
	// which means the NAT mapping is open and traffic no longer needs the hub.
	Direct     bool
	DirectAt   time.Time
	LastReport time.Time
}

// NodeConn is a live control channel to one tun client.
type NodeConn struct {
	mu        sync.Mutex
	nodeID    string
	deviceID  string
	conn      net.Conn
	controlIP string
	localIP   string
	relayEP   string
	relayEPAt time.Time
	lastSeen  time.Time
	connected bool
	startedAt time.Time
	peers     map[string]*P2PPeer
}

// MeshHub ties together the control listener, the P2P relay and the TRP
// reverse-proxy manager for the tun control plane.
type MeshHub struct {
	mu          sync.RWMutex
	cfg         MeshConfig
	nodes       map[string]*NodeRecord
	byPSK       map[string]map[string]bool // psk -> set of node ids
	byDevice    map[string]string          // device id -> node id
	conns       map[string]*NodeConn
	relay       *P2PRelay
	trp         *TRPManager
	nodesPath   string
	proxiesPath string
	// listener is kept so the control plane can be shut down; tests use it to
	// release the port between cases.
	listener net.Listener
}

// Close shuts the mesh control plane down and releases its sockets, so a hub
// can be restarted on the same addresses.
func (h *MeshHub) Close() {
	if h == nil {
		return
	}
	if h.listener != nil {
		h.listener.Close()
		h.listener = nil
	}
	if h.relay != nil {
		h.relay.Stop()
	}
}

// meshHub is the running instance; package-level so the API handlers in the
// other mesh files can reach it without touching the existing API struct.
var meshHub *MeshHub

// StartMesh boots the whole tun control plane. It returns the hub (or nil when
// disabled) and stores it in meshHub for the dashboard handlers.
func StartMesh(cfg *Config) *MeshHub {
	mcfg := meshConfigFromEnv(cfg)
	if !mcfg.Enabled {
		log.Println("[mesh] disabled (MESH_ENABLED=false)")
		return nil
	}

	h := &MeshHub{
		cfg:         mcfg,
		nodes:       make(map[string]*NodeRecord),
		byPSK:       make(map[string]map[string]bool),
		byDevice:    make(map[string]string),
		conns:       make(map[string]*NodeConn),
		nodesPath:   filepath.Join(mcfg.DataDir, "nodes.json"),
		proxiesPath: filepath.Join(mcfg.DataDir, "proxies.json"),
	}
	if err := h.loadNodes(); err != nil {
		log.Printf("[mesh] WARNING: could not load nodes: %v", err)
	}

	h.relay = NewP2PRelay(h, mcfg.RelayListen)
	go h.relay.Run()

	h.trp = NewTRPManager(h, h.proxiesPath)
	if err := h.trp.Restore(); err != nil {
		log.Printf("[mesh] WARNING: could not restore reverse proxies: %v", err)
	}

	ln, err := net.Listen("tcp", mcfg.ControlListen)
	if err != nil {
		log.Printf("[mesh] control listener on %s failed: %v", mcfg.ControlListen, err)
		return h
	}
	h.listener = ln
	go h.acceptLoop(ln)
	log.Printf("[mesh] tun control plane listening on %s (relay=%s)", mcfg.ControlListen, mcfg.RelayListen)

	meshHub = h
	return h
}

// ---- Node registry persistence -------------------------------------------

func (h *MeshHub) loadNodes() error {
	data, err := os.ReadFile(h.nodesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var recs []*NodeRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return fmt.Errorf("parse nodes file: %w", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range recs {
		if r.ID == "" || r.PSK == "" {
			continue
		}
		h.nodes[r.ID] = r
		h.indexLocked(r)
	}
	return nil
}

func (h *MeshHub) saveNodes() error {
	h.mu.RLock()
	var recs []*NodeRecord
	for _, r := range h.nodes {
		recs = append(recs, r)
	}
	h.mu.RUnlock()
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := h.nodesPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, h.nodesPath)
}

// ---- Registry access ------------------------------------------------------

// indexLocked adds r to the PSK and device indexes. Callers hold h.mu.
func (h *MeshHub) indexLocked(r *NodeRecord) {
	group, ok := h.byPSK[r.PSK]
	if !ok {
		group = make(map[string]bool)
		h.byPSK[r.PSK] = group
	}
	group[r.ID] = true
	if r.DeviceID != "" {
		h.byDevice[r.DeviceID] = r.ID
	}
}

func (h *MeshHub) unindexLocked(r *NodeRecord) {
	if group, ok := h.byPSK[r.PSK]; ok {
		delete(group, r.ID)
		if len(group) == 0 {
			delete(h.byPSK, r.PSK)
		}
	}
	if r.DeviceID != "" && h.byDevice[r.DeviceID] == r.ID {
		delete(h.byDevice, r.DeviceID)
	}
}

func (h *MeshHub) getNode(id string) *NodeRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.nodes[id]
}

// groupOf returns the PSK group a node belongs to ("" when the node is gone).
func (h *MeshHub) groupOf(id string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if rec := h.nodes[id]; rec != nil {
		return rec.PSK
	}
	return ""
}

// membersOf lists the node ids sharing a node's PSK group, excluding the node
// itself. This is the automatic discovery set for the P2P page.
func (h *MeshHub) membersOf(id string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	rec := h.nodes[id]
	if rec == nil {
		return nil
	}
	group := h.byPSK[rec.PSK]
	out := make([]string, 0, len(group))
	for other := range group {
		if other != id {
			out = append(out, other)
		}
	}
	return out
}

func (h *MeshHub) getConn(id string) *NodeConn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conns[id]
}

// onlineNodes returns every node id with a live control channel.
func (h *MeshHub) onlineNodes() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.conns))
	for id, nc := range h.conns {
		// connected is only cleared from the channel's own goroutine; read it
		// through the snapshot so this cannot race with that.
		if nc.snapshot().connected {
			out = append(out, id)
		}
	}
	return out
}

// identify resolves a control handshake to a NodeRecord, registering a new one
// when needed. deviceID is the node's stable self-reported identity; it is
// optional so older clients that only send a PSK still work (they fall back to
// IP-derived identity).
//
// Because the PSK is a shared group key, an unknown PSK is enrolled
// automatically rather than rejected: that is what makes "run the client with
// the shared PSK" the whole onboarding flow.
func (h *MeshHub) identify(psk, deviceID, remoteIP string) *NodeRecord {
	psk = strings.TrimSpace(psk)
	deviceID = strings.TrimSpace(deviceID)
	if psk == "" {
		return nil
	}

	var created bool
	h.mu.Lock()
	// 1. A known device id always wins: it is the same physical node coming
	//    back, even if its address changed.
	if deviceID != "" {
		if id, ok := h.byDevice[deviceID]; ok {
			if rec := h.nodes[id]; rec != nil {
				h.mu.Unlock()
				return rec
			}
			delete(h.byDevice, deviceID)
		}
	}
	rec := h.newNodeLocked(psk, deviceID, remoteIP)
	created = true
	// The lock must be dropped before persisting: saveNodes takes a read lock
	// and sync.RWMutex is not reentrant, so saving under the write lock
	// deadlocks the whole control plane on the first new device.
	h.mu.Unlock()

	if created {
		if err := h.saveNodes(); err != nil {
			log.Printf("[mesh] WARNING: failed to persist nodes: %v", err)
		}
	}
	return rec
}

// newNodeLocked creates, registers and indexes a node. Callers hold h.mu.
func (h *MeshHub) newNodeLocked(psk, deviceID, remoteIP string) *NodeRecord {
	id := meshShortID()
	for h.nodes[id] != nil {
		id = meshShortID()
	}
	name := "node-" + id
	if deviceID != "" {
		name = "dev-" + deviceID[:min(6, len(deviceID))]
	} else if remoteIP != "" {
		name = "node-" + remoteIP
	}
	rec := &NodeRecord{
		ID:        id,
		Name:      name,
		PSK:       psk,
		DeviceID:  deviceID,
		CreatedAt: time.Now(),
	}
	h.nodes[id] = rec
	h.indexLocked(rec)
	log.Printf("[mesh] registered %s (%s) in psk group %.8s… device=%q from %s",
		rec.ID, rec.Name, psk, deviceID, remoteIP)
	return rec
}

// addNode registers a node explicitly from the dashboard. A PSK already in use
// joins that group rather than creating a new one.
func (h *MeshHub) addNode(name, psk string) (*NodeRecord, error) {
	h.mu.Lock()
	if psk = strings.TrimSpace(psk); psk == "" {
		psk = meshRandomPSK()
	}
	id := meshShortID()
	for h.nodes[id] != nil {
		id = meshShortID()
	}
	rec := &NodeRecord{
		ID:        id,
		Name:      strings.TrimSpace(name),
		PSK:       psk,
		CreatedAt: time.Now(),
	}
	if rec.Name == "" {
		rec.Name = id
	}
	h.nodes[id] = rec
	h.indexLocked(rec)
	h.mu.Unlock()
	if err := h.saveNodes(); err != nil {
		log.Printf("[mesh] WARNING: failed to persist nodes: %v", err)
	}
	return rec, nil
}

func (h *MeshHub) removeNode(id string) error {
	h.mu.Lock()
	rec := h.nodes[id]
	if rec == nil {
		h.mu.Unlock()
		return fmt.Errorf("node not found")
	}
	delete(h.nodes, id)
	h.unindexLocked(rec)
	if nc := h.conns[id]; nc != nil {
		nc.conn.Close()
		delete(h.conns, id)
	}
	h.mu.Unlock()
	return h.saveNodes()
}

// setDeviceID pins a node to the identity a client reported on connect so
// subsequent reconnects reclaim the same record.
func (h *MeshHub) setDeviceID(id, deviceID string) {
	if deviceID == "" {
		return
	}
	h.mu.Lock()
	rec := h.nodes[id]
	if rec == nil {
		h.mu.Unlock()
		return
	}
	if rec.DeviceID == deviceID {
		h.mu.Unlock()
		return
	}
	h.unindexLocked(rec)
	rec.DeviceID = deviceID
	h.indexLocked(rec)
	h.mu.Unlock()
	if err := h.saveNodes(); err != nil {
		log.Printf("[mesh] WARNING: failed to persist nodes: %v", err)
	}
}

func (h *MeshHub) resetNode(id string) {
	if nc := h.getConn(id); nc != nil {
		nc.sendCommand(cmdReset, [8]byte{})
	}
}

// ---- Control connection handling -----------------------------------------

func (h *MeshHub) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			log.Printf("[mesh] control accept ended: %v", err)
			return
		}
		go h.handleControlConn(c)
	}
}

func (h *MeshHub) handleControlConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(45 * time.Second)
	}
	defer c.Close()

	remoteIP := ""
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
		remoteIP = ra.IP.String()
	}
	localIP := "127.0.0.1"
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok && la.IP != nil {
		localIP = la.IP.String()
	}

	// Handshake: "<psk>\n<device_id>\n". The device id is optional so older
	// clients that send only the PSK still connect (they get IP-derived identity).
	if h.cfg.ControlTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(h.cfg.ControlTimeout))
	}
	rd := bufio.NewReaderSize(c, 512)
	line, err := rd.ReadString('\n')
	if err != nil {
		log.Printf("[mesh] psk read failed from %s: %v", remoteIP, err)
		return
	}
	psk := strings.TrimRight(line, "\r\n")

	deviceID := ""
	if peeked, perr := rd.Peek(1); perr == nil && len(peeked) == 1 && peeked[0] != '\n' && peeked[0] != '\r' {
		if dline, derr := rd.ReadString('\n'); derr == nil {
			deviceID = sanitizeDeviceID(dline)
		}
	} else {
		// Consume the blank line so the command stream starts aligned.
		rd.ReadString('\n')
	}

	rec := h.identify(psk, deviceID, remoteIP)
	if rec == nil {
		log.Printf("[mesh] rejected control connection from %s (empty psk)", remoteIP)
		return
	}
	if deviceID != "" {
		h.setDeviceID(rec.ID, deviceID)
	}
	c.SetReadDeadline(time.Time{})

	h.mu.Lock()
	// Only one live control channel per node: boot the previous one.
	if old := h.conns[rec.ID]; old != nil {
		old.conn.Close()
	}
	nc := &NodeConn{
		nodeID:    rec.ID,
		deviceID:  deviceID,
		conn:      c,
		controlIP: remoteIP,
		localIP:   localIP,
		lastSeen:  time.Now(),
		connected: true,
		startedAt: time.Now(),
		peers:     make(map[string]*P2PPeer),
	}
	h.conns[rec.ID] = nc
	// A reconnect keeps the node's group so auto-mesh can re-establish it.
	group := rec.PSK
	h.mu.Unlock()
	log.Printf("[mesh] node %s (%s) online, control=%s device=%q", rec.ID, rec.Name, remoteIP, deviceID)

	// Register with the rendezvous hub first: until the node has an endpoint
	// registered there is nothing to hand its peers as a punch target.
	h.sendHubTarget(nc)

	// Keep punching while this channel lives, so a device that reboots or drops
	// its NAT comes back into the group mesh without operator action.
	stopMesh := make(chan struct{})
	defer close(stopMesh)
	go h.maintainGroupMesh(group, rec.ID, stopMesh)

	h.readControlLoop(rec, nc, rd)

	h.mu.Lock()
	if h.conns[rec.ID] == nc {
		delete(h.conns, rec.ID)
	}
	h.mu.Unlock()
	log.Printf("[mesh] node %s (%s) offline", rec.ID, rec.Name)
}

// readControlLoop consumes the node's control stream. The only thing a tun
// client sends is a periodic P2P status report; everything else is a protocol
// error and ends the channel.
func (h *MeshHub) readControlLoop(rec *NodeRecord, nc *NodeConn, rd *bufio.Reader) {
	var pending []byte
	buf := make([]byte, 512)
	for {
		n, err := rd.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			for len(pending) > 0 {
				if pending[0] == ctrlStatusByte {
					// [0xFE][count][ (node_id:8, flags:1) * count ]
					total := 2 + ctrlStatusRecordSize*int(pending[1])
					if total > len(pending) {
						break
					}
					nc.applyPeerStatus(pending[2:total])
					pending = pending[total:]
					continue
				}
				if len(pending) < ctrlFrameSize {
					break
				}
				log.Printf("[mesh] node %s sent unexpected control data (%d bytes ignored)", rec.ID, ctrlFrameSize)
				pending = pending[ctrlFrameSize:]
			}
		}
		if err != nil {
			return
		}
	}
}

// applyPeerStatus folds a client's P2P status report into its peer table. It is
// a method on the connection so the tests can drive it without a socket.
func (nc *NodeConn) applyPeerStatus(body []byte) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.lastSeen = time.Now()
	now := time.Now()
	for i := 0; i+ctrlStatusRecordSize <= len(body); i += ctrlStatusRecordSize {
		id := sanitizeDeviceID(string(body[i : i+8]))
		flags := body[i+8]
		if id == "" {
			continue
		}
		peer := nc.peers[id]
		if peer == nil {
			continue
		}
		peer.LastReport = now
		direct := flags&0x01 != 0
		switch {
		case direct && !peer.Direct:
			log.Printf("[p2p] node %s reached %s directly (hole punch complete)", nc.nodeID, id)
		case !direct && peer.Direct:
			log.Printf("[p2p] node %s lost the direct path to %s", nc.nodeID, id)
		}
		peer.Direct = direct
		if direct {
			peer.DirectAt = now
		}
	}
}

// sendCommand writes one command frame to the node's control channel. peer is
// the node id of a P2P peer the command is about, or "" when unused.
func (nc *NodeConn) sendCommand(cmd byte, payload [8]byte) error {
	return nc.sendCommandTo(cmd, payload, "")
}

func (nc *NodeConn) sendCommandTo(cmd byte, payload [8]byte, peer string) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if nc.conn == nil {
		return fmt.Errorf("control channel closed")
	}
	nc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	var frame [ctrlFrameSize]byte
	frame[0] = cmd
	copy(frame[1:9], payload[:])
	// The node id field is always 8 characters on the wire. Commands that
	// name no peer (reset, proxy add, P2P clear) send '0' as the placeholder,
	// so only a peer id that is present but malformed is an error.
	var id [8]byte
	for i := range id {
		id[i] = '0'
	}
	if peer != "" {
		peer = sanitizeDeviceID(peer)
		if len(peer) != 8 {
			nc.conn.SetWriteDeadline(time.Time{})
			return fmt.Errorf("invalid peer id %q", peer)
		}
		copy(id[:], peer)
	}
	copy(frame[9:17], id[:])
	if _, err := nc.conn.Write(frame[:]); err != nil {
		nc.conn.SetWriteDeadline(time.Time{})
		return err
	}
	nc.conn.SetWriteDeadline(time.Time{})
	nc.lastSeen = time.Now()
	return nil
}

func (nc *NodeConn) info() (string, string, string, bool) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.controlIP, nc.localIP, nc.relayEP, nc.relayEPAt.Before(time.Now().Add(-15 * time.Second))
}

// nodeSnapshot is a consistent copy of the mutable fields of a control
// connection. Reading them without the lock races with the relay, which writes
// relayEP from a different goroutine on every probe.
type nodeSnapshot struct {
	nodeID    string
	deviceID  string
	controlIP string
	localIP   string
	relayEP   string
	relayEPAt time.Time
	connected bool
	lastSeen  time.Time
	startedAt time.Time
	peers     map[string]*P2PPeer
}

func (nc *NodeConn) snapshot() nodeSnapshot {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	s := nodeSnapshot{
		nodeID:    nc.nodeID,
		deviceID:  nc.deviceID,
		controlIP: nc.controlIP,
		localIP:   nc.localIP,
		relayEP:   nc.relayEP,
		relayEPAt: nc.relayEPAt,
		connected: nc.connected,
		lastSeen:  nc.lastSeen,
		startedAt: nc.startedAt,
		peers:     make(map[string]*P2PPeer, len(nc.peers)),
	}
	for id, p := range nc.peers {
		cp := *p
		s.peers[id] = &cp
	}
	return s
}

func (h *MeshHub) sendRaw(id string, cmd byte, payload [8]byte) error {
	nc := h.getConn(id)
	if nc == nil {
		return fmt.Errorf("node offline")
	}
	return nc.sendCommand(cmd, payload)
}

// ---- Helpers --------------------------------------------------------------

// sanitizeDeviceID keeps a client-supplied identity to a short, safe token so
// it can be echoed in the API and used in log lines.
func sanitizeDeviceID(s string) string {
	s = strings.TrimRight(s, "\r\n")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

func meshRandomPSK() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "psk-" + fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func meshShortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
