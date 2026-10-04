package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"tanguard/p2p"
)

// registerMeshRoutes mounts the tun control-plane API on the existing HTTP
// mux. Every route is guarded by the standard dashboard-login/API-key check.
func registerMeshRoutes(mux *http.ServeMux, a *API) {
	guard := a.requireAPI
	mux.Handle("/api/mesh/status", guard(a.handleMeshStatus))
	mux.Handle("/api/mesh/nodes", guard(a.handleMeshNodes))
	mux.Handle("/api/mesh/groups", guard(a.handleMeshGroups))
	mux.Handle("/api/mesh/links", guard(a.handleMeshLinks))
	mux.Handle("/api/mesh/node/add", guard(a.handleMeshNodeAdd))
	mux.Handle("/api/mesh/node/remove", guard(a.handleMeshNodeRemove))
	mux.Handle("/api/mesh/node/reset", guard(a.handleMeshNodeReset))
	mux.Handle("/api/mesh/relay/join", guard(a.handleMeshRelayJoin))
	mux.Handle("/api/mesh/relay/leave", guard(a.handleMeshRelayLeave))
	mux.Handle("/api/mesh/relay/link", guard(a.handleMeshRelayLink))
	mux.Handle("/api/mesh/relay/unlink", guard(a.handleMeshRelayUnlink))
	mux.Handle("/api/mesh/p2p/connect", guard(a.handleMeshP2PConnect))
	mux.Handle("/api/mesh/p2p/mesh", guard(a.handleMeshP2PMesh))
	mux.Handle("/api/trp/proxies", guard(a.handleTRPProxies))
	mux.Handle("/api/trp/proxy/add", guard(a.handleTRPProxyAdd))
	mux.Handle("/api/trp/proxy/remove", guard(a.handleTRPProxyRemove))
}

// postBody decodes a JSON body and rejects anything but POST, so every mutating
// handler in this file shares the same contract.
func postBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	if r.Method != "POST" {
		jsonErr(w, 405, "POST required")
		return false
	}
	if err := limitedDecoder(r, v); err != nil {
		jsonErr(w, 400, "invalid JSON")
		return false
	}
	return true
}

func idParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		ID string `json:"id"`
	}
	if !postBody(w, r, &req) {
		return "", false
	}
	if req.ID == "" {
		jsonErr(w, 400, "id required")
		return "", false
	}
	return req.ID, true
}

// hubFor returns the running control plane, or writes the 503 that every mesh
// route answers with when it is disabled.
func (a *API) hubFor(w http.ResponseWriter) *p2p.MeshHub {
	if a.hub == nil {
		jsonErr(w, 503, "tun control plane is disabled (MESH_ENABLED)")
		return nil
	}
	return a.hub
}

func (a *API) handleMeshStatus(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, h.MeshStatus())
}

func (a *API) handleMeshNodes(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	withPSK := r.URL.Query().Get("show_psk") == "1"
	jsonResp(w, 200, map[string]interface{}{
		"nodes": h.ListNodes(withPSK),
	})
}

// handleMeshGroups is the P2P page's data source: devices bucketed by the PSK
// they share, which is exactly the automatic discovery set.
func (a *API) handleMeshGroups(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	withPSK := r.URL.Query().Get("show_psk") == "1"
	jsonResp(w, 200, map[string]interface{}{
		"groups": h.ListGroups(withPSK),
		"status": h.MeshStatus(),
	})
}

func (a *API) handleMeshLinks(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"links": h.ListLinks(),
	})
}

func (a *API) handleMeshNodeAdd(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
		PSK  string `json:"psk,omitempty"`
	}
	if !postBody(w, r, &req) {
		return
	}
	rec, err := h.AddNode(strings.TrimSpace(req.Name), strings.TrimSpace(req.PSK))
	if err != nil {
		jsonErr(w, 409, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"id":      rec.ID,
		"name":    rec.Name,
		"psk":     rec.PSK,
	})
}

func (a *API) handleMeshNodeRemove(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.RemoveNode(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshNodeReset(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	h.ResetNode(id)
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshRelayJoin(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.JoinRelay(id); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshRelayLeave(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.LeaveRelay(id); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshRelayLink(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	}
	if !postBody(w, r, &req) {
		return
	}
	if err := h.Relay().LinkRelay(req.Src, req.Dst); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshRelayUnlink(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		Src string `json:"src"`
	}
	if !postBody(w, r, &req) {
		return
	}
	h.Relay().Unlink(req.Src)
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func (a *API) handleMeshP2PConnect(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	if !postBody(w, r, &req) {
		return
	}
	if err := h.DirectConnect(req.A, req.B); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

// handleMeshP2PMesh re-runs (or tears down) auto-meshing for one PSK group.
// Auto-meshing is already on by default; this is the manual re-punch and the
// way to drop a group's relay links.
func (a *API) handleMeshP2PMesh(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		Group  string `json:"group"`
		Enable *bool  `json:"enable,omitempty"`
	}
	if !postBody(w, r, &req) {
		return
	}
	enable := true
	if req.Enable != nil {
		enable = *req.Enable
	}
	n, err := h.MeshGroup(req.Group, enable)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"success": true,
		"enabled": enable,
		"nodes":   n,
	})
}

func (a *API) handleTRPProxies(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"proxies": a.trp.ListProxies(),
	})
}

func (a *API) handleTRPProxyAdd(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		NodeID     string `json:"node_id"`
		BindIP     string `json:"bind_ip,omitempty"`
		BindPort   string `json:"bind_port"`
		TargetIP   string `json:"target_ip,omitempty"`
		TargetPort string `json:"target_port"`
	}
	if !postBody(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		jsonErr(w, 400, "node_id required")
		return
	}
	// An empty bind_port means "pick a free one": bind() listens on :0 and
	// writes the port the OS handed back into the record before persisting it.
	bindPort := 0
	if p := strings.TrimSpace(req.BindPort); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			jsonErr(w, 400, "bind_port must be a port between 1 and 65535")
			return
		}
		bindPort = n
	}
	targetPort, err := strconv.Atoi(strings.TrimSpace(req.TargetPort))
	if err != nil || targetPort < 1 || targetPort > 65535 {
		jsonErr(w, 400, "target_port must be a port between 1 and 65535")
		return
	}
	rec, err := a.trp.CreateProxy(req.NodeID, req.BindIP, bindPort, targetPort, req.TargetIP)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"success":    true,
		"id":         rec.ID,
		"bind_ip":    rec.BindIP,
		"bind_port":  rec.BindPort,
		"public_url": fmt.Sprintf("%s:%d", rec.BindIP, rec.BindPort),
	})
}

func (a *API) handleTRPProxyRemove(w http.ResponseWriter, r *http.Request) {
	h := a.hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.trp.RemoveProxy(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}
