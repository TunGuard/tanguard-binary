package p2p

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
	"sort"
	"strings"
	"sync"
	"time"

	"tanguard/config"
	"tanguard/peers"
	"tanguard/policy"
)

// TUN control protocol command bytes.
const (
	cmdReset = 0x00
	cmdFRP   = 0x01
	cmdP2P   = 0x02
	CmdTRP   = 0x03
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

func meshConfigFromEnv(cfg *config.Config) MeshConfig {
	// MESH_DATA_DIR is the mesh subsystem's own knob, so an explicit value for
	// it wins; the server config is only the fallback. Accepting nil keeps
	// StartMesh usable on its own rather than panicking on a nil config.
	dataDir := config.EnvStr("MESH_DATA_DIR", "")
	if dataDir == "" && cfg != nil {
		dataDir = cfg.DataDir
	}
	return MeshConfig{
		Enabled:        config.EnvStr("MESH_ENABLED", "true") == "true",
		ControlListen:  config.EnvStr("CONTROL_LISTEN", ":7000"),
		RelayListen:    config.EnvStr("RELAY_LISTEN", ":7001"),
		ControlTimeout: time.Duration(config.EnvInt("CONTROL_TIMEOUT_S", 10)) * time.Second,
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
	// Tested and RTTMS come from the client's own link test: a small packet the
	// peer echoes back, timed end to end. Direct only says a punch landed at
	// some point, which a path the far end has since lost still satisfies, so
	// this is the claim that the two devices can actually talk right now.
	Tested   bool
	RTTMS    int
	RTTKnown bool
}

// status flag bits in a client -> server P2P status report. Each is a bit inside
// the one flags byte per peer, so a client that predates the link test reports
// Tested false and nothing here can be misread as a result.
const (
	statusFlagDirect   = 0x01
	statusFlagTested   = 0x02
	statusFlagRTTMask  = 0x0C
	statusFlagRTTShift = 2
)

// rttBucketMS maps the client's 4-bit latency bucket onto a millisecond figure.
// The buckets are geometric because the interesting range is short: a direct
// path is single-digit milliseconds, and anything past a second is only ever
// reported as slow.
var rttBucketMS = [16]int{0, 1, 4, 16, 64, 256, 1000, 4000, 16000, 60000,
	60000, 60000, 60000, 60000, 60000, 60000}

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
	nodesPath   string
	proxiesPath string
	// policies gates the mesh features per device. It is nil when no policy
	// store was attached, which means no gating at all.
	policies *policy.PolicyStore
	peers    *peers.PeerStore
	// listener is kept so the control plane can be shut down; tests use it to
	// release the port between cases.
	listener net.Listener
	// proxyReleaser is the TRP manager, attached by the caller once both sides
	// exist.
	proxyReleaser ProxyReleaser
}

// ProxyReleaser is the part of the TRP manager that the control plane needs.
// Keeping it behind an interface is what stops the two packages from needing
// each other: the manager depends on the hub, and the hub only has to be able
// to release the mappings of a node that is going away.
type ProxyReleaser interface {
	// RemoveProxiesForNode drops every mapping that targets nodeID and reports
	// how many were released.
	RemoveProxiesForNode(nodeID string) int
}

// SetProxyReleaser attaches the TRP manager to the control plane. It is called
// once at startup, after both sides exist.
func (h *MeshHub) SetProxyReleaser(r ProxyReleaser) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.proxyReleaser = r
	h.mu.Unlock()
}

// releaseNodeProxies drops the TRP mappings that pointed at nodeID. It runs
// after the hub lock has been dropped, because the TRP manager shares it.
func (h *MeshHub) releaseNodeProxies(nodeID string) int {
	h.mu.RLock()
	r := h.proxyReleaser
	h.mu.RUnlock()
	if r == nil {
		return 0
	}
	return r.RemoveProxiesForNode(nodeID)
}

// SetPolicy attaches the policy layer to the control plane. It is called once
// at startup, after the stores have been loaded. Passing nil leaves every mesh
// feature open, which is what an untouched deployment sees.
func (h *MeshHub) SetPolicy(policies *policy.PolicyStore, peerStore *peers.PeerStore) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.policies = policies
	h.peers = peerStore
	h.mu.Unlock()
}

// ClientDevices lists the tun-client devices the hub knows about, oldest first.
// These are the devices that have no WireGuard peer to name them by, so they
// are the ones the policy layer has to identify by device id. A node whose
// device id is empty has not reported an identity yet, so there is nothing to
// group it by and it is left out.
func (h *MeshHub) ClientDevices() []*NodeRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]*NodeRecord, 0, len(h.nodes))
	for _, rec := range h.nodes {
		if rec.DeviceID == "" {
			continue
		}
		cp := *rec
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// HasDeviceID reports whether any node reports this device id.
func (h *MeshHub) HasDeviceID(deviceID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, rec := range h.nodes {
		if rec.DeviceID == deviceID {
			return true
		}
	}
	return false
}

// nodePolicyDevice returns the device id behind a mesh node, plus the stores
// policy decisions are made against. Taking the fields under one read lock and
// releasing it before the caller touches the stores keeps this safe to call
// from code that already holds the hub lock elsewhere.
func (h *MeshHub) nodePolicyDevice(nodeID string) (*policy.PolicyStore, *peers.PeerStore, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	deviceID := ""
	if rec := h.nodes[nodeID]; rec != nil {
		deviceID = rec.DeviceID
	}
	return h.policies, h.peers, deviceID
}

// p2pAllowed reports whether a mesh node may take part in the automatic P2P
// mesh. A node with no policy group of its own is always allowed, so P2P keeps
// working exactly as before for anyone who has not used policy groups.
func (h *MeshHub) p2pAllowed(nodeID string) bool {
	policies, peers, deviceID := h.nodePolicyDevice(nodeID)
	return policies.AllowP2PMeshForNode(peers, deviceID)
}

// TRPAllowed reports whether a mesh node may terminate TRP reverse proxies.
func (h *MeshHub) TRPAllowed(nodeID string) bool {
	policies, peers, deviceID := h.nodePolicyDevice(nodeID)
	return policies.AllowTRPForNode(peers, deviceID)
}

// interDeviceAllowed reports whether two nodes may hold a direct P2P link to
// each other.
//
// A direct link is established between the two clients and never passes through
// the server, so the packet filter cannot police the traffic that flows over it.
// The same-group rule the filter applies therefore has to be applied here too,
// or two devices in different policy groups would still find each other through
// the automatic mesh even though the server drops their relayed traffic.
func (h *MeshHub) interDeviceAllowed(a, b string) bool {
	policies, peers, aDevice := h.nodePolicyDevice(a)
	_, _, bDevice := h.nodePolicyDevice(b)
	return policies.InterDeviceAllowedBetweenNodes(peers, aDevice, bDevice)
}

// ControlAddr is the address the node control listener is bound to.
func (h *MeshHub) ControlAddr() string {
	if h == nil {
		return ""
	}
	return h.cfg.ControlListen
}

// RelayAddr is the address the P2P rendezvous/relay socket is bound to.
func (h *MeshHub) RelayAddr() string {
	if h == nil {
		return ""
	}
	return h.cfg.RelayListen
}

// Relay is the P2P relay, for callers that drive it directly: the dashboard's
// manual link, punch and group endpoints.
func (h *MeshHub) Relay() *P2PRelay {
	if h == nil {
		return nil
	}
	return h.relay
}

// ProxiesPath is where the TRP registry is persisted. The mesh data dir wins
// over the server one, so this is the reliable way to hand the path to the TRP
// manager.
func (h *MeshHub) ProxiesPath() string {
	if h == nil {
		return ""
	}
	return h.proxiesPath
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

// StartMesh boots the whole tun control plane: the control listener and the P2P
// relay. It returns the hub, or nil when the control plane is disabled. The
// TRP reverse-proxy manager is wired in by the caller, because the hub has to
// be able to reach it while the manager depends on the hub.
func StartMesh(cfg *config.Config) *MeshHub {
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

	ln, err := net.Listen("tcp", mcfg.ControlListen)
	if err != nil {
		log.Printf("[mesh] control listener on %s failed: %v", mcfg.ControlListen, err)
		return h
	}
	h.listener = ln
	go h.acceptLoop(ln)
	log.Printf("[mesh] tun control plane listening on %s (relay=%s)", mcfg.ControlListen, mcfg.RelayListen)

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
	// A fixed ".tmp" name would let two concurrent saves race: both write the
	// same path and the loser's rename fails with ENOENT once the winner has
	// already moved it. A unique name keeps the write atomic and private to
	// this call.
	tmp, err := os.CreateTemp(filepath.Dir(h.nodesPath), filepath.Base(h.nodesPath)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), h.nodesPath)
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

func (h *MeshHub) GetNode(id string) *NodeRecord {
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

func (h *MeshHub) GetConn(id string) *NodeConn {
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
	id := config.RandomID()
	for h.nodes[id] != nil {
		id = config.RandomID()
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

// AddNode registers a node explicitly from the dashboard. A PSK already in use
// joins that group rather than creating a new one.
func (h *MeshHub) AddNode(name, psk string) (*NodeRecord, error) {
	h.mu.Lock()
	if psk = strings.TrimSpace(psk); psk == "" {
		psk = meshRandomPSK()
	}
	id := config.RandomID()
	for h.nodes[id] != nil {
		id = config.RandomID()
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

func (h *MeshHub) RemoveNode(id string) error {
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

	// Release any TRP mappings that pointed at this node. Done after dropping
	// the hub lock, because the TRP manager shares it, and it has to happen at
	// all: a mapping whose node is gone can never forward again, so leaving it
	// behind would strand its listening port with no way to free it from the UI.
	if n := h.releaseNodeProxies(id); n > 0 {
		log.Printf("[mesh] released %d TRP mapping(s) for removed node %s", n, id)
	}
	return h.saveNodes()
}

// SetDeviceID pins a node to the identity a client reported on connect so
// subsequent reconnects reclaim the same record.
func (h *MeshHub) SetDeviceID(id, deviceID string) {
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

func (h *MeshHub) ResetNode(id string) {
	if nc := h.GetConn(id); nc != nil {
		nc.SendCommand(cmdReset, [8]byte{})
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
	ls := strings.ToLower(strings.TrimRight(line, "\r\n"))
	if strings.HasPrefix(ls, "get ") || strings.HasPrefix(ls, "post ") || strings.HasPrefix(ls, "head ") || strings.HasPrefix(ls, "put ") || strings.HasPrefix(ls, "delete ") || strings.HasPrefix(ls, "options ") || strings.HasPrefix(ls, "connect ") || strings.Contains(ls, "http/") {
		// Looks like an HTTP request probing the control port; drop it silently
		return
	}
	psk := strings.TrimRight(line, "\r\n")

	deviceID := ""
	if peeked, perr := rd.Peek(1); perr == nil && len(peeked) == 1 && peeked[0] != '\n' && peeked[0] != '\r' {
		if dline, derr := rd.ReadString('\n'); derr == nil {
			dls := strings.ToLower(strings.TrimRight(dline, "\r\n"))
			if strings.HasPrefix(dls, "host:") || strings.HasPrefix(dls, "user-agent:") || strings.HasPrefix(dls, "accept") || strings.HasPrefix(dls, "connection:") || strings.HasPrefix(dls, "authorization:") || strings.HasPrefix(dls, "x-") || strings.Contains(dls, "http/") {
				return
			}
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
		h.SetDeviceID(rec.ID, deviceID)
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
		direct := flags&statusFlagDirect != 0
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

		// The link test is the node's own round trip to this peer, so it is only
		// meaningful while the node is reporting the peer at all. A report that
		// omits the tested bit means the test is not in flight or no echo came
		// back, which is a lost link, not a stale measurement to keep showing.
		tested := flags&statusFlagTested != 0
		if tested != peer.Tested {
			if tested {
				log.Printf("[p2p] node %s verified a link to %s (%dms round trip)",
					nc.nodeID, id, rttBucketMS[(flags&statusFlagRTTMask)>>statusFlagRTTShift])
			} else {
				log.Printf("[p2p] node %s lost its verified link to %s", nc.nodeID, id)
			}
		}
		peer.Tested = tested
		peer.RTTKnown = tested
		peer.RTTMS = 0
		if tested {
			peer.RTTMS = rttBucketMS[(flags&statusFlagRTTMask)>>statusFlagRTTShift]
		}
	}
}

// SendCommand writes one command frame to the node's control channel. peer is
// the node id of a P2P peer the command is about, or "" when unused.
func (nc *NodeConn) SendCommand(cmd byte, payload [8]byte) error {
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
	nc := h.GetConn(id)
	if nc == nil {
		return fmt.Errorf("node offline")
	}
	return nc.SendCommand(cmd, payload)
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
