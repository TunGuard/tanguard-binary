package main

import (
	"log"
	"net/http"
	"sort"
	"strings"
)

// registerPolicyRoutes mounts the policy-group API on the shared HTTP mux.
// These are administrative operations on device membership, so they are
// guarded by the same dashboard-login/API-key check as everything else.
func registerPolicyRoutes(mux *http.ServeMux, a *API) {
	guard := a.requireAPI
	mux.Handle("/api/policy/groups", guard(a.handlePolicyGroups))
	mux.Handle("/api/policy/group/create", guard(a.handlePolicyGroupCreate))
	mux.Handle("/api/policy/group/update", guard(a.handlePolicyGroupUpdate))
	mux.Handle("/api/policy/group/delete", guard(a.handlePolicyGroupDelete))
	mux.Handle("/api/policy/group/assign", guard(a.handlePolicyGroupAssign))
	mux.Handle("/api/policy/group/unassign", guard(a.handlePolicyGroupUnassign))
	mux.Handle("/api/policy/apply", guard(a.handlePolicyGroupApply))
}

// peerInfo is the one view of a peer the policy page needs: enough to render a
// checkbox, and nothing secret.
type peerInfo struct {
	PublicKey  string `json:"public_key"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	AllowedIP  string `json:"allowed_ip"`
	GroupID    string `json:"group_id"`
	GroupName  string `json:"group_name"`
}

// label is what the page shows for a device, falling back to the public key
// when no name was given. shortKey is length-safe: peers.json is not validated
// on load, so a truncated key must not be able to panic this handler.
func (p peerInfo) label() string {
	if p.DeviceName != "" {
		return p.DeviceName
	}
	return shortKey(p.PublicKey)
}

func (a *API) peerPolicyInfo() []peerInfo {
	peers := a.store.All()
	out := make([]peerInfo, 0, len(peers))
	for _, p := range peers {
		info := peerInfo{
			PublicKey:  p.PublicKey,
			DeviceID:   p.DeviceID,
			DeviceName: p.DeviceName,
			AllowedIP:  p.AllowedIP,
			GroupID:    DefaultPolicyGroupID,
		}
		if group := a.policies.GroupForPeer(p.PublicKey); group != nil {
			info.GroupID = group.ID
			info.GroupName = group.Name
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].label() != out[j].label() {
			return out[i].label() < out[j].label()
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}

// groupView is a group plus the devices inside it, which is what the page
// renders as a card.
type groupView struct {
	*PolicyGroup
	Devices []peerInfo `json:"devices"`
}

// handlePolicyGroups returns every group with its members, plus the full peer
// list so the "add device" dialog can offer every device the server knows
// about in one call.
func (a *API) handlePolicyGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, 405, "GET required")
		return
	}

	all := a.peerPolicyInfo()
	byKey := make(map[string]peerInfo, len(all))
	for _, p := range all {
		byKey[p.PublicKey] = p
	}

	// A device belongs to the default group exactly when it is not assigned
	// anywhere else, so the default group's membership is the complement of
	// every custom group rather than whatever is explicitly stored for it.
	custom := make(map[string]bool, len(all))
	for _, g := range a.policies.List() {
		if g.ID == DefaultPolicyGroupID {
			continue
		}
		for _, key := range a.policies.Members(g.ID) {
			custom[key] = true
		}
	}

	groups := a.policies.List()
	views := make([]groupView, 0, len(groups))
	for _, g := range groups {
		v := groupView{PolicyGroup: g, Devices: []peerInfo{}}
		for _, key := range a.policies.Members(g.ID) {
			if info, ok := byKey[key]; ok {
				v.Devices = append(v.Devices, info)
			}
		}
		if g.ID == DefaultPolicyGroupID {
			for _, info := range all {
				if !custom[info.PublicKey] {
					v.Devices = append(v.Devices, info)
				}
			}
		}
		views = append(views, v)
	}

	interDrops, accessDrops := a.wg.PolicyDrops()
	jsonResp(w, 200, map[string]interface{}{
		"groups": views,
		"peers":  all,
		"drop_count": map[string]uint64{
			"inter_device": interDrops,
			"internet":     accessDrops,
		},
	})
}

// policyRules is the shared rule payload for create and update. The switches
// are pointers so "absent" stays distinguishable from false: an update that
// only changes one rule must not silently clear the other three.
type policyRules struct {
	Name             string `json:"name"`
	AllowInterDevice *bool  `json:"allow_inter_device,omitempty"`
	AllowP2PMesh     *bool  `json:"allow_p2p_mesh,omitempty"`
	AllowTRP         *bool  `json:"allow_trp,omitempty"`
	AllowWGAccess    *bool  `json:"allow_wg_access,omitempty"`
}

// apply produces a group carrying exactly the switches that were sent, which
// is what Create wants (everything absent means deny) and what Update wants
// once the absent ones have been filled in from the current group.
func (r policyRules) apply() PolicyGroup {
	var g PolicyGroup
	if r.AllowInterDevice != nil {
		g.AllowInterDevice = *r.AllowInterDevice
	}
	if r.AllowP2PMesh != nil {
		g.AllowP2PMesh = *r.AllowP2PMesh
	}
	if r.AllowTRP != nil {
		g.AllowTRP = *r.AllowTRP
	}
	if r.AllowWGAccess != nil {
		g.AllowWGAccess = *r.AllowWGAccess
	}
	return g
}

func (a *API) handlePolicyGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req policyRules
	if !postBody(w, r, &req) {
		return
	}
	// A new group denies everything unless a rule was explicitly switched on,
	// so creating one is always a restricting action.
	g, err := a.policies.Create(req.Name, req.apply())
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	logPolicy("created group", g)
	jsonResp(w, 200, map[string]interface{}{"success": true, "group": g})
}

func (a *API) handlePolicyGroupUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
		policyRules
	}
	if !postBody(w, r, &req) {
		return
	}
	if req.ID == "" {
		jsonErr(w, 400, "id required")
		return
	}
	current := a.policies.Group(req.ID)
	if current == nil {
		jsonErr(w, 404, "group not found")
		return
	}
	// Fill in every switch the caller left out from the group's current value.
	next := policyRules{Name: strings.TrimSpace(req.Name)}
	if next.Name == "" {
		next.Name = current.Name
	}
	if req.AllowInterDevice == nil {
		next.AllowInterDevice = &current.AllowInterDevice
	} else {
		next.AllowInterDevice = req.AllowInterDevice
	}
	if req.AllowP2PMesh == nil {
		next.AllowP2PMesh = &current.AllowP2PMesh
	} else {
		next.AllowP2PMesh = req.AllowP2PMesh
	}
	if req.AllowTRP == nil {
		next.AllowTRP = &current.AllowTRP
	} else {
		next.AllowTRP = req.AllowTRP
	}
	if req.AllowWGAccess == nil {
		next.AllowWGAccess = &current.AllowWGAccess
	} else {
		next.AllowWGAccess = req.AllowWGAccess
	}

	g, err := a.policies.Update(req.ID, next.apply())
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	logPolicy("updated group", g)
	jsonResp(w, 200, map[string]interface{}{"success": true, "group": g})
}

func (a *API) handlePolicyGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.policies.Delete(id); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	log.Printf("[policy] group %s deleted", id)
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

// deviceList is the shared body for assign and unassign.
type deviceList struct {
	ID      string   `json:"id"`
	Devices []string `json:"devices"`
}

func (a *API) decodeDeviceList(w http.ResponseWriter, r *http.Request) (deviceList, bool) {
	var req deviceList
	if !postBody(w, r, &req) {
		return deviceList{}, false
	}
	if len(req.Devices) == 0 {
		jsonErr(w, 400, "devices required")
		return deviceList{}, false
	}
	return req, true
}

func (a *API) handlePolicyGroupAssign(w http.ResponseWriter, r *http.Request) {
	req, ok := a.decodeDeviceList(w, r)
	if !ok {
		return
	}
	err := a.policies.Assign(req.ID, req.Devices, func(key string) bool {
		return a.store.Get(key) != nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	name := req.ID
	if group := a.policies.Group(req.ID); group != nil {
		name = group.Name
	}
	log.Printf("[policy] moved %d device(s) into group %q", len(req.Devices), name)
	jsonResp(w, 200, map[string]interface{}{"success": true, "group_id": req.ID})
}

func (a *API) handlePolicyGroupUnassign(w http.ResponseWriter, r *http.Request) {
	req, ok := a.decodeDeviceList(w, r)
	if !ok {
		return
	}
	if err := a.policies.Unassign(req.Devices); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	log.Printf("[policy] returned %d device(s) to the default group", len(req.Devices))
	jsonResp(w, 200, map[string]interface{}{"success": true, "group_id": DefaultPolicyGroupID})
}

func (a *API) handlePolicyGroupApply(w http.ResponseWriter, r *http.Request) {
	var req PolicyFile
	if !postBody(w, r, &req) {
		return
	}
	err := a.policies.Apply(req, func(key string) bool {
		return a.store.Get(key) != nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	groups := a.policies.List()
	members := 0
	for _, g := range groups {
		if g.ID != DefaultPolicyGroupID {
			members += len(a.policies.Members(g.ID))
		}
	}
	log.Printf("[policy] applied: %d custom group(s), %d assigned device(s)", len(groups)-1, members)
	jsonResp(w, 200, map[string]interface{}{
		"success":      true,
		"groups":       len(groups) - 1,
		"assigned":     members,
		"active":       a.policies.IsActive(),
		"default_open": true,
	})
}

func logPolicy(action string, g *PolicyGroup) {
	log.Printf("[policy] %s %q (%s): inter_device=%v p2p=%v trp=%v wg_access=%v",
		action, g.Name, g.ID, g.AllowInterDevice, g.AllowP2PMesh, g.AllowTRP, g.AllowWGAccess)
}
