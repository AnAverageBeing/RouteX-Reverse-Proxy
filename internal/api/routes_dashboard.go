package api

import (
	"io"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/go-chi/chi/v5"
)

// ─── System / overview ────────────────────────────────────────────────────

// handleSystem returns server-level health and runtime info for a dashboard
// status panel.
func (r *Router) handleSystem(w http.ResponseWriter, req *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	running := 0
	for _, name := range r.manager.List() {
		if inst := r.manager.Get(name); inst != nil && inst.IsRunning() {
			running++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"project":          "RouteX",
		"version":          r.version,
		"uptime_seconds":   int64(time.Since(r.startTime).Seconds()),
		"started_at":       r.startTime.UTC().Format(time.RFC3339),
		"timezone":         r.global.Timezone,
		"go_version":       runtime.Version(),
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
		"num_cpu":          runtime.NumCPU(),
		"goroutines":       runtime.NumGoroutine(),
		"mem_alloc_bytes":  mem.Alloc,
		"mem_sys_bytes":    mem.Sys,
		"proxies_running":  running,
		"iptables_enabled": r.global.Iptables.Enabled,
		"metrics_enabled":  r.global.Metrics.Enabled,
	})
}

// handleOverview returns everything a dashboard landing page needs in one call:
// system info, global totals, and a per-proxy summary.
func (r *Router) handleOverview(w http.ResponseWriter, req *http.Request) {
	proxies := make([]map[string]interface{}, 0)
	var gActive, gTotal, gIn, gOut, gBlocked, gBanned int64
	for _, name := range r.manager.List() {
		inst := r.manager.Get(name)
		if inst == nil {
			continue
		}
		s := r.collectProxyStats(name)
		gActive += toI64(s["active_connections"])
		gTotal += toI64(s["total_connections"])
		gIn += toI64(s["bytes_in"])
		gOut += toI64(s["bytes_out"])
		gBlocked += toI64(s["l7_blocked"])
		gBanned += toI64(s["l7_banned"])
		proxies = append(proxies, map[string]interface{}{
			"name":               name,
			"running":            inst.IsRunning(),
			"active_connections": s["active_connections"],
			"total_connections":  s["total_connections"],
			"bytes_in":           s["bytes_in"],
			"bytes_out":          s["bytes_out"],
			"upstreams_healthy":  s["upstreams_healthy"],
			"upstreams_total":    s["upstreams_total"],
			"l7_blocked":         s["l7_blocked"],
			"suspended":          s["suspended"],
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":        r.version,
		"uptime_seconds": int64(time.Since(r.startTime).Seconds()),
		"totals": map[string]interface{}{
			"proxies":            len(proxies),
			"active_connections": gActive,
			"total_connections":  gTotal,
			"bytes_in":           gIn,
			"bytes_out":          gOut,
			"l7_blocked":         gBlocked,
			"l7_banned":          gBanned,
		},
		"proxies": proxies,
	})
}

// ─── Stats ────────────────────────────────────────────────────────────────

func (r *Router) handleGlobalStats(w http.ResponseWriter, req *http.Request) {
	var gActive, gTotal, gIn, gOut, gBlocked, gBanned int64
	count := 0
	for _, name := range r.manager.List() {
		if inst := r.manager.Get(name); inst == nil {
			continue
		}
		count++
		s := r.collectProxyStats(name)
		gActive += toI64(s["active_connections"])
		gTotal += toI64(s["total_connections"])
		gIn += toI64(s["bytes_in"])
		gOut += toI64(s["bytes_out"])
		gBlocked += toI64(s["l7_blocked"])
		gBanned += toI64(s["l7_banned"])
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"proxies":            count,
		"active_connections": gActive,
		"total_connections":  gTotal,
		"bytes_in":           gIn,
		"bytes_out":          gOut,
		"l7_blocked":         gBlocked,
		"l7_banned":          gBanned,
	})
}

func (r *Router) handleProxyStats(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	if r.manager.Get(name) == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	writeJSON(w, http.StatusOK, r.collectProxyStats(name))
}

// collectProxyStats aggregates live counters for a single proxy from the proxy
// engines, balancer, L7 engine and bandwidth tracker.
func (r *Router) collectProxyStats(name string) map[string]interface{} {
	inst := r.manager.Get(name)
	out := map[string]interface{}{"name": name}
	if inst == nil {
		return out
	}
	var active, total, bytesIn, bytesOut int64
	for _, p := range inst.TCPProxies() {
		active += p.ActiveConns()
		total += p.TotalConns()
		bytesIn += p.BytesIn()
		bytesOut += p.BytesOut()
	}
	for _, p := range inst.UDPProxies() {
		active += p.ActiveConns()
		total += p.TotalConns()
		bytesIn += p.BytesIn()
		bytesOut += p.BytesOut()
	}
	ups := inst.Balancer().Snapshot()
	healthy := 0
	for _, u := range ups {
		if u.Healthy {
			healthy++
		}
	}
	out["running"] = inst.IsRunning()
	out["active_connections"] = active
	out["total_connections"] = total
	out["bytes_in"] = bytesIn
	out["bytes_out"] = bytesOut
	out["upstreams"] = ups
	out["upstreams_total"] = len(ups)
	out["upstreams_healthy"] = healthy

	if eng := r.l7For(name); eng != nil {
		out["l7_enabled"] = true
		out["l7_blocked"] = eng.BlockedConns()
		out["l7_banned"] = eng.BannedIPs()
	} else {
		out["l7_enabled"] = false
		out["l7_blocked"] = int64(0)
		out["l7_banned"] = int64(0)
	}

	if bw := r.manager.GetBandwidthTracker(name); bw != nil {
		snap := bw.Snapshot()
		out["bandwidth"] = snap
		out["suspended"] = snap.Suspended
	} else {
		out["suspended"] = false
	}
	return out
}

// handleProxyHistory serves persisted time-series samples for dashboard graphs.
// Query params: ?hours=24 (window, default 24, max 720) and ?limit=N.
func (r *Router) handleProxyHistory(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	if r.metrics == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"proxy": name, "points": []interface{}{}})
		return
	}
	hours := 24
	if h := req.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 {
			hours = n
		}
	}
	if hours > 720 {
		hours = 720
	}
	limit := 0
	if l := req.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	points, err := r.metrics.Store().History(name, since, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"proxy": name, "hours": hours, "count": len(points), "points": points,
	})
}

// ─── API keys ─────────────────────────────────────────────────────────────

// handleListKeys lists configured API keys WITHOUT exposing the secret value —
// only a masked preview, label, and permission scopes.
func (r *Router) handleListKeys(w http.ResponseWriter, req *http.Request) {
	type keyInfo struct {
		Label       string   `json:"label"`
		Masked      string   `json:"masked_key"`
		Permissions []string `json:"permissions"`
	}
	out := make([]keyInfo, 0, len(r.global.API.APIKeys))
	for _, k := range r.global.API.APIKeys {
		out = append(out, keyInfo{Label: k.Label, Masked: maskKey(k.Key), Permissions: k.Permissions})
	}
	writeJSON(w, http.StatusOK, out)
}

func maskKey(k string) string {
	if len(k) <= 8 {
		return "****"
	}
	return k[:4] + "…" + k[len(k)-4:]
}

// ─── Proxy config CRUD ────────────────────────────────────────────────────

// handleGetProxyConfig returns the full proxy config as a structured JSON object
// plus the raw YAML form, so a dashboard can show and edit it.
func (r *Router) handleGetProxyConfig(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	m, err := config.ProxyToMap(p)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	raw, _ := config.MarshalProxyYAML(p)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config": m, "yaml": string(raw),
	})
}

// handleValidateProxy validates a proxy config supplied in the request body
// (YAML or JSON — YAML is a JSON superset) without applying it.
func (r *Router) handleValidateProxy(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	if _, err := config.LoadProxyFromYAML(body); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true})
}

// handleCreateProxy creates a new proxy from a config body, persists it to the
// proxies directory, and starts it if enabled.
func (r *Router) handleCreateProxy(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	p, err := config.LoadProxyFromYAML(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config: " + err.Error()})
		return
	}
	if _, exists := r.resolveProxyConfig(p.Name); exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a proxy named " + p.Name + " already exists"})
		return
	}
	p.ConfigPath = "" // force a fresh canonical file
	path, err := config.SaveProxy(p, r.proxiesDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed: " + err.Error()})
		return
	}
	if p.Enabled {
		if err := r.manager.Start(p); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "started config saved but start failed: " + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status": "created", "name": p.Name, "running": p.Enabled, "config_path": path,
	})
}

// handleUpdateProxy replaces a proxy's config and restarts it (or stops it if
// the new config is disabled).
func (r *Router) handleUpdateProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	existing, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}
	p, err := config.LoadProxyFromYAML(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config: " + err.Error()})
		return
	}
	if p.Name != name {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config name must match URL name (" + name + ")"})
		return
	}
	// Overwrite the existing file in place.
	p.ConfigPath = existing.ConfigPath
	if _, err := config.SaveProxy(p, r.proxiesDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed: " + err.Error()})
		return
	}
	if p.Enabled {
		if err := r.manager.Start(p); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	} else {
		r.manager.Stop(name)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "name": name, "running": p.Enabled})
}

// handleDeleteProxy stops a proxy and removes its config file.
func (r *Router) handleDeleteProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	r.manager.Stop(name)
	path := p.ConfigPath
	if path == "" && r.proxiesDir != "" {
		path = config.FindProxyConfigPath(r.proxiesDir, name)
	}
	if err := config.DeleteProxyFile(path); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleted from runtime but file removal failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "name": name})
}

// ─── L7 + rate-limit views ────────────────────────────────────────────────

// handleProxyL7 returns L7 protection status + live counters for a proxy.
func (r *Router) handleProxyL7(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	resp := map[string]interface{}{
		"name":    name,
		"enabled": p.L7Protection.Enabled,
	}
	// Return the config with YAML field names for consistency with /config.
	if m, err := config.ProxyToMap(p); err == nil {
		resp["config"] = m["l7_protection"]
	} else {
		resp["config"] = p.L7Protection
	}
	if eng := r.l7For(name); eng != nil {
		resp["blocked_connections"] = eng.BlockedConns()
		resp["banned_ips"] = eng.BannedIPs()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleGetRateLimits returns the configured L3/L4 rate-limit block for a proxy.
func (r *Router) handleGetRateLimits(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	rl := interface{}(p.RateLimits)
	if m, err := config.ProxyToMap(p); err == nil {
		if v, ok := m["rate_limits"]; ok {
			rl = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": name, "rate_limits": rl,
	})
}

func toI64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}
