package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPolicyGroupID is the group every peer belongs to until an operator
// moves it somewhere else. Its rules are all enabled, which is what makes the
// policy layer a pure administrative filter: an untouched deployment behaves
// exactly as it did before policy groups existed.
const DefaultPolicyGroupID = "default"

// Capability is one of the four things a policy group can allow or deny.
type Capability int

const (
	// CapInterDevice lets devices in the group reach other devices through the
	// server, both inside the group and across groups.
	CapInterDevice Capability = iota
	// CapP2PMesh lets devices in the group join the automatic P2P mesh, and
	// lets the relay hand them each other's endpoints.
	CapP2PMesh
	// CapTRP lets devices in the group terminate TRP reverse-proxy bindings.
	CapTRP
	// CapWGAccess lets devices in the group use the tunnel as ordinary
	// WireGuard internet access.
	CapWGAccess
)

// capabilityCount is the number of rule bits stored per group.
const capabilityCount = 4

// PolicyGroup is a named set of rule switches plus the peers assigned to it.
// Rules are set when the group is created and can be edited later; membership
// only ever changes which group a peer is evaluated against.
type PolicyGroup struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	AllowInterDevice bool      `json:"allow_inter_device"`
	AllowP2PMesh     bool      `json:"allow_p2p_mesh"`
	AllowTRP         bool      `json:"allow_trp"`
	AllowWGAccess    bool      `json:"allow_wg_access"`
	Builtin          bool      `json:"builtin,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// Allows reports whether the group permits one capability.
func (g *PolicyGroup) Allows(c Capability) bool {
	if g == nil {
		return false
	}
	switch c {
	case CapInterDevice:
		return g.AllowInterDevice
	case CapP2PMesh:
		return g.AllowP2PMesh
	case CapTRP:
		return g.AllowTRP
	case CapWGAccess:
		return g.AllowWGAccess
	}
	return false
}

// PolicyFile is the on-disk shape: the groups plus the peer-public-key to
// group-id map. Keeping both in one file means a restore can never pair a
// membership with a group that no longer exists.
type PolicyFile struct {
	Groups    []*PolicyGroup    `json:"groups"`
	Assign    map[string]string `json:"assign,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// PolicyStore holds every policy group and the peer to group mapping.
//
// It is a pure administrative filter: nothing here changes how a device is
// configured or how it connects. A peer that is in no group evaluates against
// the default group, so leaving the feature alone is indistinguishable from
// not having it.
type PolicyStore struct {
	mu       sync.RWMutex
	groups   map[string]*PolicyGroup
	assign   map[string]string // peer public key -> group id
	filePath string
	loaded   bool
	// active reports whether any custom group exists. While it is false no peer
	// can be in anything but the default group, so every policy decision is
	// "allow" and the packet filter short-circuits on one atomic load instead
	// of taking any locks. This is what makes the feature free of effect for a
	// deployment that never configures it.
	active atomic.Bool
}

func NewPolicyStore(dataDir string) *PolicyStore {
	return &PolicyStore{
		groups:   make(map[string]*PolicyGroup),
		assign:   make(map[string]string),
		filePath: filepath.Join(dataDir, "policy_groups.json"),
	}
}

// refreshActiveLocked recomputes the fast-path flag. Callers must hold ps.mu.
func (ps *PolicyStore) refreshActiveLocked() {
	for id := range ps.groups {
		if id != DefaultPolicyGroupID {
			ps.active.Store(true)
			return
		}
	}
	ps.active.Store(false)
}

// IsActive reports whether any custom policy group exists. False means the
// policy layer cannot deny anything, because every peer is in the default group.
func (ps *PolicyStore) IsActive() bool {
	if ps == nil {
		return false
	}
	return ps.active.Load()
}

// defaultGroup is the permissive built-in group. It is reconstructed rather
// than persisted so a deleted or corrupted file can never lock operators out
// of their own network.
func defaultGroup() *PolicyGroup {
	return &PolicyGroup{
		ID:               DefaultPolicyGroupID,
		Name:             "Default Global Group",
		AllowInterDevice: true,
		AllowP2PMesh:     true,
		AllowTRP:         true,
		AllowWGAccess:    true,
		Builtin:          true,
	}
}

// Load reads the policy file, creating the default group in memory when the
// file is absent. A missing file is the normal state of a fresh install and is
// not an error; an unreadable one is reported and leaves the store empty so
// Save will not clobber it.
func (ps *PolicyStore) Load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.loaded = false
	data, err := os.ReadFile(ps.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			ps.groups[DefaultPolicyGroupID] = defaultGroup()
			ps.refreshActiveLocked()
			ps.loaded = true
			return nil
		}
		return fmt.Errorf("read policy file: %w", err)
	}

	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parse policy file: %w", err)
	}

	groups := make(map[string]*PolicyGroup, len(pf.Groups))
	for _, g := range pf.Groups {
		if g == nil || g.ID == "" {
			continue
		}
		// A persisted group may never claim to be the built-in one with
		// different rules: that would silently change the default posture.
		if g.ID == DefaultPolicyGroupID {
			continue
		}
		groups[g.ID] = g
	}
	groups[DefaultPolicyGroupID] = defaultGroup()

	// Drop memberships that point at a group this file does not contain, so a
	// truncated file cannot leave peers assigned to nothing.
	assign := make(map[string]string, len(pf.Assign))
	for pubKey, id := range pf.Assign {
		if _, ok := groups[id]; ok {
			assign[pubKey] = id
		} else if id != DefaultPolicyGroupID {
			assign[pubKey] = DefaultPolicyGroupID
		}
	}

	ps.groups = groups
	ps.assign = assign
	ps.refreshActiveLocked()
	ps.loaded = true
	return nil
}

// Save persists a snapshot atomically. It mirrors PeerStore.Save: a file we
// failed to load is never overwritten.
func (ps *PolicyStore) Save() error {
	ps.mu.RLock()
	if !ps.loaded {
		ps.mu.RUnlock()
		return nil
	}
	pf := PolicyFile{
		Groups:    make([]*PolicyGroup, 0, len(ps.groups)),
		Assign:    make(map[string]string, len(ps.assign)),
		UpdatedAt: time.Now(),
	}
	for _, g := range ps.groups {
		if g.ID != DefaultPolicyGroupID {
			pf.Groups = append(pf.Groups, g)
		}
	}
	for pubKey, id := range ps.assign {
		pf.Assign[pubKey] = id
	}
	ps.mu.RUnlock()

	data, err := json.MarshalIndent(&pf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policies: %w", err)
	}
	tmp := ps.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}
	return os.Rename(tmp, ps.filePath)
}

// groupLocked resolves a peer's group. Callers must hold ps.mu.
func (ps *PolicyStore) groupLocked(publicKey string) *PolicyGroup {
	if id, ok := ps.assign[publicKey]; ok {
		if g, ok := ps.groups[id]; ok {
			return g
		}
	}
	return ps.groups[DefaultPolicyGroupID]
}

// GroupForPeer returns the group a peer is evaluated against. Every peer has
// exactly one group, and the default group is the answer whenever a peer has
// not been explicitly moved.
func (ps *PolicyStore) GroupForPeer(publicKey string) *PolicyGroup {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.groupLocked(publicKey)
}

// Allows reports whether a peer may use a capability. Unknown peers fall
// through to the default group, so an unassigned device is never locked out.
func (ps *PolicyStore) Allows(publicKey string, c Capability) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.groupLocked(publicKey).Allows(c)
}

// List returns every group ordered default-first then by creation time.
func (ps *PolicyStore) List() []*PolicyGroup {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	out := make([]*PolicyGroup, 0, len(ps.groups))
	for _, g := range ps.groups {
		cp := *g
		out = append(out, &cp)
	}
	// Rank rather than a pair of early returns: a comparator that returns true
	// for two default groups at once is not a strict weak ordering, and
	// sort.Slice is free to call it on any pair.
	rank := func(g *PolicyGroup) int {
		if g.ID == DefaultPolicyGroupID {
			return 0
		}
		return 1
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i]) != rank(out[j]) {
			return rank(out[i]) < rank(out[j])
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Members lists the public keys explicitly assigned to a group.
//
// For the default group this is *not* the set of devices that belong to it: a
// device belongs to the default group precisely because it has no assignment,
// so its membership is the complement of every other group. Callers that need
// the real default membership must compute that complement, which needs the
// peer list this store deliberately does not hold.
func (ps *PolicyStore) Members(groupID string) []string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var out []string
	for key, id := range ps.assign {
		if id == groupID {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// Group returns one group by id.
func (ps *PolicyStore) Group(id string) *PolicyGroup {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	g, ok := ps.groups[id]
	if !ok {
		return nil
	}
	cp := *g
	return &cp
}

// Create adds a new group. New groups deny everything by default: a group
// exists to restrict, so the operator opts into each capability explicitly.
func (ps *PolicyStore) Create(name string, rules PolicyGroup) (*PolicyGroup, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name required")
	}
	ps.mu.Lock()
	if err := ps.uniqueNameLocked(name, ""); err != nil {
		ps.mu.Unlock()
		return nil, err
	}
	g := &PolicyGroup{
		ID:               meshShortID(),
		Name:             name,
		AllowInterDevice: rules.AllowInterDevice,
		AllowP2PMesh:     rules.AllowP2PMesh,
		AllowTRP:         rules.AllowTRP,
		AllowWGAccess:    rules.AllowWGAccess,
		CreatedAt:        time.Now(),
	}
	ps.groups[g.ID] = g
	ps.refreshActiveLocked()
	ps.mu.Unlock()

	if err := ps.Save(); err != nil {
		return nil, err
	}
	cp := *g
	return &cp, nil
}

func (ps *PolicyStore) uniqueNameLocked(name, exceptID string) error {
	for _, g := range ps.groups {
		if g.ID != exceptID && strings.EqualFold(g.Name, name) {
			return fmt.Errorf("a group named %q already exists", name)
		}
	}
	return nil
}

// Update replaces a group's rule switches. Membership is untouched, and the
// built-in default group is read-only so the escape hatch can never be lost.
func (ps *PolicyStore) Update(id string, rules PolicyGroup) (*PolicyGroup, error) {
	ps.mu.Lock()
	g, ok := ps.groups[id]
	if !ok {
		ps.mu.Unlock()
		return nil, fmt.Errorf("group not found")
	}
	if g.Builtin {
		ps.mu.Unlock()
		return nil, fmt.Errorf("the default group cannot be edited")
	}
	g.AllowInterDevice = rules.AllowInterDevice
	g.AllowP2PMesh = rules.AllowP2PMesh
	g.AllowTRP = rules.AllowTRP
	g.AllowWGAccess = rules.AllowWGAccess
	if name := strings.TrimSpace(rules.Name); name != "" {
		if err := ps.uniqueNameLocked(name, id); err != nil {
			ps.mu.Unlock()
			return nil, err
		}
		g.Name = name
	}
	cp := *g
	ps.mu.Unlock()

	if err := ps.Save(); err != nil {
		return nil, err
	}
	return &cp, nil
}

// Delete removes a custom group and returns its members to the default group.
// The built-in group cannot be deleted, and a group is never deleted while it
// still holds peers, so no device is ever reassigned without the operator
// seeing it happen.
func (ps *PolicyStore) Delete(id string) error {
	ps.mu.Lock()
	g, ok := ps.groups[id]
	if !ok {
		ps.mu.Unlock()
		return fmt.Errorf("group not found")
	}
	if g.Builtin {
		ps.mu.Unlock()
		return fmt.Errorf("the default group cannot be deleted")
	}
	if ps.membersLocked(id) > 0 {
		ps.mu.Unlock()
		return fmt.Errorf("group is not empty: move its devices out first")
	}
	delete(ps.groups, id)
	ps.refreshActiveLocked()
	ps.mu.Unlock()
	return ps.Save()
}

func (ps *PolicyStore) membersLocked(groupID string) int {
	n := 0
	for _, id := range ps.assign {
		if id == groupID {
			n++
		}
	}
	return n
}

// Assign moves peers into a group. Unknown public keys are rejected so a
// typo cannot silently create a phantom membership.
func (ps *PolicyStore) Assign(groupID string, publicKeys []string, known func(string) bool) error {
	ps.mu.Lock()
	g, ok := ps.groups[groupID]
	if !ok {
		ps.mu.Unlock()
		return fmt.Errorf("group not found")
	}
	if g.Builtin {
		ps.mu.Unlock()
		return fmt.Errorf("devices belong to the default group unless you move them")
	}
	for _, key := range publicKeys {
		if !known(key) {
			ps.mu.Unlock()
			return fmt.Errorf("unknown device %q", key)
		}
	}
	for _, key := range publicKeys {
		ps.assign[key] = groupID
	}
	ps.mu.Unlock()
	return ps.Save()
}

// Unassign returns peers to the default group.
func (ps *PolicyStore) Unassign(publicKeys []string) error {
	ps.mu.Lock()
	for _, key := range publicKeys {
		delete(ps.assign, key)
	}
	ps.mu.Unlock()
	return ps.Save()
}

// Apply replaces the entire policy state with pf in one shot, which is what an
// automation client wants: one call declares every group and every device's
// membership, instead of a create/assign call per device.
//
// The default group is always present and always permissive, and it is never
// taken from the payload, so applying a policy can never lock every device out
// of the network. Memberships naming an unknown device are rejected and nothing
// is changed.
func (ps *PolicyStore) Apply(pf PolicyFile, known func(string) bool) error {
	groups, err := pf.validateAgainst(known)
	if err != nil {
		return err
	}
	assign := make(map[string]string, len(pf.Assign))
	for pubKey, id := range pf.Assign {
		if id == "" || id == DefaultPolicyGroupID {
			// An explicit "put this device back in the default group".
			continue
		}
		assign[pubKey] = id
	}

	ps.mu.Lock()
	ps.groups = groups
	ps.assign = assign
	ps.refreshActiveLocked()
	ps.mu.Unlock()
	return ps.Save()
}

// validateAgainst checks a whole policy payload and returns the group map it
// describes, default group included. Nothing is applied: a caller either gets a
// fully valid map or an error and the live state is untouched, which is what
// makes an apply atomic.
//
// known reports whether a public key belongs to a real peer. Pass nil to skip
// that check, which is what the restore path wants: a backup carries its own
// peers.json, and the peer list is validated separately during the restore.
func (pf PolicyFile) validateAgainst(known func(string) bool) (map[string]*PolicyGroup, error) {
	groups := make(map[string]*PolicyGroup, len(pf.Groups)+1)
	groups[DefaultPolicyGroupID] = defaultGroup()
	for _, g := range pf.Groups {
		if g == nil || strings.TrimSpace(g.Name) == "" {
			return nil, fmt.Errorf("every group needs a name")
		}
		if g.ID == "" {
			g.ID = meshShortID()
		}
		// Check the reserved id before the duplicate check: the default group
		// is already in the map, so otherwise a payload that declares it would
		// be reported as a plain duplicate instead of the real problem.
		if g.ID == DefaultPolicyGroupID {
			return nil, fmt.Errorf("the default group is managed automatically and cannot be declared")
		}
		if _, dup := groups[g.ID]; dup {
			return nil, fmt.Errorf("duplicate group id %q", g.ID)
		}
		groups[g.ID] = g
	}
	// Names are the thing an operator sees, so reject collisions up front
	// rather than saving a state the UI cannot distinguish.
	seen := map[string]string{}
	for id, g := range groups {
		lower := strings.ToLower(g.Name)
		if other, dup := seen[lower]; dup {
			return nil, fmt.Errorf("groups %q and %q share the name %q", other, id, g.Name)
		}
		seen[lower] = id
	}

	for pubKey, id := range pf.Assign {
		if id == "" || id == DefaultPolicyGroupID {
			// An explicit "put this device back in the default group".
			continue
		}
		if _, ok := groups[id]; !ok {
			return nil, fmt.Errorf("device %q references unknown group %q", pubKey, id)
		}
		if known != nil && !known(pubKey) {
			return nil, fmt.Errorf("unknown device %q", pubKey)
		}
	}
	return groups, nil
}

// AllowP2PMeshForNode reports whether the device behind a tun control node may
// take part in the automatic mesh. A node with no matching peer record has no
// policy group of its own and is allowed, keeping P2P working exactly as before
// for anyone who has not used the policy layer. A nil store means no policy
// layer at all, which likewise allows everything.
func (ps *PolicyStore) AllowP2PMeshForNode(store *PeerStore, deviceID string) bool {
	if ps == nil || store == nil || deviceID == "" {
		return true
	}
	pubKey, ok := store.PublicKeyForDeviceID(deviceID)
	if !ok {
		return true
	}
	return ps.Allows(pubKey, CapP2PMesh)
}

// AllowTRPForNode is the TRP counterpart of AllowP2PMeshForNode.
func (ps *PolicyStore) AllowTRPForNode(store *PeerStore, deviceID string) bool {
	if ps == nil || store == nil || deviceID == "" {
		return true
	}
	pubKey, ok := store.PublicKeyForDeviceID(deviceID)
	if !ok {
		return true
	}
	return ps.Allows(pubKey, CapTRP)
}

// tunnelNet is a parsed CIDR used by the packet filter to tell tunnel-internal
// traffic from internet-bound traffic.
type tunnelNet struct {
	net  uint32
	mask uint32
}

// contains reports whether ip falls inside the tunnel subnet.
func (t tunnelNet) contains(ip uint32) bool {
	return ip&t.mask == t.net
}

// parseTunnelNet converts a CIDR like 10.100.0.0/24 into its network and mask.
// An unparseable value yields the zero value, whose contains always reports
// true: with no known subnet every packet looks tunnel-internal, which is the
// safe direction because it routes traffic to the inter-device rule instead of
// silently treating unknown destinations as internet traffic.
func parseTunnelNet(cidr string) tunnelNet {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return tunnelNet{}
	}
	v4 := ip.To4()
	if v4 == nil {
		return tunnelNet{}
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones < 0 {
		return tunnelNet{}
	}
	mask := ^uint32(0)
	if ones > 0 {
		mask = ^uint32(0) << uint(32-ones)
	}
	return tunnelNet{net: binary.BigEndian.Uint32(v4) & mask, mask: mask}
}

// ipToUint32 converts a dotted-quad to its numeric form, reporting false for
// anything that is not IPv4.
func ipToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}
