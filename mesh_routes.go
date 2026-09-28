package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// registerMeshRoutes mounts the tun control-plane API on the existing HTTP
// mux. Every route is guarded by the standard dashboard-login/API-key check.
func registerMeshRoutes(mux *http.ServeMux, a *API) {
	guard := a.requireAPI
	mux.Handle("/api/mesh/status", guard(handleMeshStatus))
	mux.Handle("/api/mesh/nodes", guard(handleMeshNodes))
	mux.Handle("/api/mesh/groups", guard(handleMeshGroups))
	mux.Handle("/api/mesh/links", guard(handleMeshLinks))
	mux.Handle("/api/mesh/node/add", guard(handleMeshNodeAdd))
	mux.Handle("/api/mesh/node/remove", guard(handleMeshNodeRemove))
	mux.Handle("/api/mesh/node/reset", guard(handleMeshNodeReset))
	mux.Handle("/api/mesh/relay/join", guard(handleMeshRelayJoin))
	mux.Handle("/api/mesh/relay/leave", guard(handleMeshRelayLeave))
	mux.Handle("/api/mesh/relay/link", guard(handleMeshRelayLink))
	mux.Handle("/api/mesh/relay/unlink", guard(handleMeshRelayUnlink))
	mux.Handle("/api/mesh/p2p/connect", guard(handleMeshP2PConnect))
	mux.Handle("/api/mesh/p2p/mesh", guard(handleMeshP2PMesh))
	mux.Handle("/api/trp/proxies", guard(handleTRPProxies))
	mux.Handle("/api/trp/proxy/add", guard(handleTRPProxyAdd))
	mux.Handle("/api/trp/proxy/remove", guard(handleTRPProxyRemove))
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

func hubFor(w http.ResponseWriter) *MeshHub {
	if meshHub == nil {
		jsonErr(w, 503, "tun control plane is disabled (MESH_ENABLED)")
		return nil
	}
	return meshHub
}

func handleMeshStatus(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, h.meshStatus())
}

func handleMeshNodes(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	withPSK := r.URL.Query().Get("show_psk") == "1"
	jsonResp(w, 200, map[string]interface{}{
		"nodes": h.listNodes(withPSK),
	})
}

// handleMeshGroups is the P2P page's data source: devices bucketed by the PSK
// they share, which is exactly the automatic discovery set.
func handleMeshGroups(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	withPSK := r.URL.Query().Get("show_psk") == "1"
	jsonResp(w, 200, map[string]interface{}{
		"groups": h.listGroups(withPSK),
		"status": h.meshStatus(),
	})
}

func handleMeshLinks(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"links": h.listLinks(),
	})
}

func handleMeshNodeAdd(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
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
	rec, err := h.addNode(strings.TrimSpace(req.Name), strings.TrimSpace(req.PSK))
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

func handleMeshNodeRemove(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.removeNode(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshNodeReset(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	h.resetNode(id)
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshRelayJoin(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.joinRelay(id); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshRelayLeave(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.leaveRelay(id); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshRelayLink(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
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
	if err := h.relay.linkRelay(req.Src, req.Dst); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshRelayUnlink(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	var req struct {
		Src string `json:"src"`
	}
	if !postBody(w, r, &req) {
		return
	}
	h.relay.unlink(req.Src)
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

func handleMeshP2PConnect(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
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
	if err := h.directConnect(req.A, req.B); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}

// handleMeshP2PMesh re-runs (or tears down) auto-meshing for one PSK group.
// Auto-meshing is already on by default; this is the manual re-punch and the
// way to drop a group's relay links.
func handleMeshP2PMesh(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
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
	n, err := h.meshGroup(req.Group, enable)
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

func handleTRPProxies(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	jsonResp(w, 200, map[string]interface{}{
		"proxies": h.trp.listProxies(),
	})
}

func handleTRPProxyAdd(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
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
	rec, err := h.trp.CreateProxy(req.NodeID, req.BindIP, bindPort, targetPort, req.TargetIP)
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

func handleTRPProxyRemove(w http.ResponseWriter, r *http.Request) {
	h := hubFor(w)
	if h == nil {
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := h.trp.RemoveProxy(id); err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	jsonResp(w, 200, map[string]interface{}{"success": true})
}
