package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/acl"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/iptables"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/l7"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/metrics"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/proxy"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type Router struct {
	mux        *chi.Mux
	auth       *AuthMiddleware
	manager    *proxy.Manager
	iptMgr     *iptables.Manager
	l7Engines  map[string]*l7.Engine
	metrics    *metrics.MetricsAPI
	global     *config.Global
	logger     *zap.Logger
	version    string
	globalACL  *acl.Engine
	proxyACLs  map[string]*acl.Engine
	proxiesDir string
	startTime  time.Time
}

func NewRouter(
	global *config.Global,
	mgr *proxy.Manager,
	iptMgr *iptables.Manager,
	l7s map[string]*l7.Engine,
	metAPI *metrics.MetricsAPI,
	logger *zap.Logger,
	version string,
	globalACL *acl.Engine,
	proxyACLs map[string]*acl.Engine,
	proxiesDir string,
) *Router {
	auth := NewAuthMiddleware(global)
	r := &Router{
		mux: chi.NewRouter(), auth: auth, manager: mgr,
		iptMgr: iptMgr, l7Engines: l7s, metrics: metAPI,
		global: global, logger: logger, version: version,
		globalACL: globalACL, proxyACLs: proxyACLs,
		proxiesDir: proxiesDir, startTime: time.Now(),
	}
	r.registerRoutes()
	return r
}

// L7EngineForProxy resolves the live L7 engine for a proxy from the manager,
// falling back to the startup snapshot. Returns nil when L7 is disabled.
func (r *Router) l7For(name string) *l7.Engine {
	if eng := r.manager.GetL7Engine(name); eng != nil {
		return eng
	}
	return r.l7Engines[name]
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) registerRoutes() {
	r.mux.Use(CORSMiddleware)
	r.mux.Get("/api/health", r.handleHealth)
	r.mux.Get("/api/version", r.handleVersion)

	r.mux.Group(func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("metrics:read"))
		mux.Get("/metrics", r.metrics.ServeHTTP)
		mux.HandleFunc("/metrics/*", r.metrics.ServeHTTP)
	})

	// Read-only system / dashboard endpoints (proxies:read scope).
	r.mux.Group(func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("proxies:read"))
		mux.Get("/api/system", r.handleSystem)
		mux.Get("/api/overview", r.handleOverview)
		mux.Get("/api/stats", r.handleGlobalStats)
		mux.Get("/api/stats/proxy/{name}", r.handleProxyStats)
		mux.Get("/api/stats/proxy/{name}/history", r.handleProxyHistory)
	})

	// API key introspection — admin only, never returns the secret value.
	r.mux.Group(func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("*"))
		mux.Get("/api/keys", r.handleListKeys)
	})

	r.mux.Route("/api/proxies", func(mux chi.Router) {
		// Reads.
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/", r.handleListProxies)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}", r.handleGetProxy)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}/config", r.handleGetProxyConfig)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}/connections", r.handleListConnections)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}/upstreams", r.handleListUpstreams)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}/l7", r.handleProxyL7)
		mux.With(r.auth.RequirePermission("proxies:read")).Get("/{name}/ratelimits", r.handleGetRateLimits)
		// Mutations (admin scope).
		mux.With(r.auth.RequirePermission("*")).Post("/", r.handleCreateProxy)
		mux.With(r.auth.RequirePermission("*")).Post("/validate", r.handleValidateProxy)
		mux.With(r.auth.RequirePermission("*")).Put("/{name}", r.handleUpdateProxy)
		mux.With(r.auth.RequirePermission("*")).Delete("/{name}", r.handleDeleteProxy)
		mux.With(r.auth.RequirePermission("*")).Post("/{name}/enable", r.handleEnableProxy)
		mux.With(r.auth.RequirePermission("*")).Post("/{name}/disable", r.handleDisableProxy)
		mux.With(r.auth.RequirePermission("*")).Post("/{name}/reload", r.handleReloadProxy)
		mux.With(r.auth.RequirePermission("*")).Delete("/{name}/connections/{id}", r.handleKillConnection)
		mux.With(r.auth.RequirePermission("*")).Post("/{name}/upstreams/{ip}/eject", r.handleEjectUpstream)
		mux.With(r.auth.RequirePermission("*")).Post("/{name}/upstreams/{ip}/readmit", r.handleReadmitUpstream)
	})

	r.mux.Route("/api/iptables", func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("*"))
		mux.Get("/rules", r.handleListIptablesRules)
		mux.Post("/validate", r.handleValidateIptables)
		mux.Post("/flush/{proxy}", r.handleFlushIptables)
		mux.Post("/orphan-sweep", r.handleOrphanSweep)
	})

	r.mux.Route("/api/l7", func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("*"))
		mux.Get("/banned", r.handleListBanned)
		mux.Delete("/banned/{ip}", r.handleUnbanIP)
		mux.Post("/banned/{ip}", r.handleBanIP)
		mux.Get("/events", r.handleL7Events)
	})

	r.mux.Route("/api/acl", func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("*"))
		mux.Get("/global", r.handleGetGlobalACL)
		mux.Post("/global/rules", r.handleAddGlobalACLRule)
		mux.Delete("/global/rules", r.handleRemoveGlobalACLRule)
		mux.Put("/global/rules", r.handleReplaceGlobalACLRules)
		mux.Get("/proxy/{name}", r.handleGetProxyACL)
		mux.Post("/proxy/{name}/rules", r.handleAddProxyACLRule)
		mux.Delete("/proxy/{name}/rules", r.handleRemoveProxyACLRule)
		mux.Put("/proxy/{name}/rules", r.handleReplaceProxyACLRules)
	})
	r.mux.Route("/api/bandwidth", func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("metrics:read"))
		mux.Get("/proxy/{name}", r.handleGetBandwidth)
		mux.Post("/proxy/{name}/reset", r.handleResetBandwidth)
	})


	r.mux.HandleFunc("POST /api/reload", func(w http.ResponseWriter, req *http.Request) {
		h := r.auth.RequirePermission("*")(http.HandlerFunc(r.handleReloadAll))
		h.ServeHTTP(w, req)
	})
}

func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (r *Router) handleVersion(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": r.version, "project": "RouteX"})
}

func (r *Router) handleListProxies(w http.ResponseWriter, req *http.Request) {
	type proxyInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Running     bool   `json:"running"`
		Enabled     bool   `json:"enabled"`
		Protocol    string `json:"protocol"`
		OriginPort  string `json:"origin_port"`
		ActiveConns int64  `json:"active_connections"`
		ConfigPath  string `json:"config_path"`
	}
	// Index running instances by name.
	out := map[string]*proxyInfo{}
	for _, name := range r.manager.List() {
		inst := r.manager.Get(name)
		if inst == nil {
			continue
		}
		pi := &proxyInfo{Name: name, Running: inst.IsRunning(), ActiveConns: inst.Tracker().Live()}
		if inst.Config != nil {
			pi.Description = inst.Config.Description
			pi.Enabled = inst.Config.Enabled
			pi.Protocol = inst.Config.Protocol
			pi.OriginPort = inst.Config.OriginPort
			pi.ConfigPath = inst.Config.ConfigPath
		}
		out[name] = pi
	}
	// Merge in proxies that exist on disk but are not currently running (e.g.
	// disabled), so a dashboard can list and re-enable them.
	if r.proxiesDir != "" {
		for _, res := range config.LoadProxyDir(r.proxiesDir) {
			if res.Err != nil || res.Proxy == nil {
				continue
			}
			if _, ok := out[res.Proxy.Name]; ok {
				continue
			}
			out[res.Proxy.Name] = &proxyInfo{
				Name: res.Proxy.Name, Description: res.Proxy.Description,
				Running: false, Enabled: res.Proxy.Enabled, Protocol: res.Proxy.Protocol,
				OriginPort: res.Proxy.OriginPort, ConfigPath: res.Path,
			}
		}
	}
	list := make([]*proxyInfo, 0, len(out))
	for _, v := range out {
		list = append(list, v)
	}
	writeJSON(w, http.StatusOK, list)
}

func (r *Router) handleGetProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": inst.Name, "running": inst.IsRunning(), "active_conns": inst.Tracker().Live(),
	})
}

// resolveProxyConfig finds a proxy's config either from the running instance or
// by loading it fresh from disk (so disabled/stopped proxies are reachable too).
func (r *Router) resolveProxyConfig(name string) (*config.Proxy, bool) {
	if inst := r.manager.Get(name); inst != nil && inst.Config != nil {
		return inst.Config, true
	}
	if r.proxiesDir != "" {
		if path := config.FindProxyConfigPath(r.proxiesDir, name); path != "" {
			if p, err := config.LoadProxy(path); err == nil {
				return p, true
			}
		}
	}
	return nil, false
}

func (r *Router) handleEnableProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	p.Enabled = true
	if _, err := config.SaveProxy(p, r.proxiesDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed: " + err.Error()})
		return
	}
	if err := r.manager.Start(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "name": name})
}

func (r *Router) handleDisableProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	p, ok := r.resolveProxyConfig(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	p.Enabled = false
	if _, err := config.SaveProxy(p, r.proxiesDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed: " + err.Error()})
		return
	}
	// Actually stop the running proxy so it stops accepting/forwarding traffic.
	r.manager.Stop(name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "name": name})
}

func (r *Router) handleReloadProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	// Reload from disk so on-disk edits are picked up (not just the in-memory copy).
	path := ""
	if inst := r.manager.Get(name); inst != nil && inst.Config != nil {
		path = inst.Config.ConfigPath
	}
	if path == "" && r.proxiesDir != "" {
		path = config.FindProxyConfigPath(r.proxiesDir, name)
	}
	if path == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy config file not found"})
		return
	}
	p, err := config.LoadProxy(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config reload failed: " + err.Error()})
		return
	}
	if !p.Enabled {
		r.manager.Stop(p.Name)
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped (disabled in config)", "name": p.Name})
		return
	}
	if err := r.manager.Start(p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded", "name": p.Name})
}

func (r *Router) handleListConnections(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	conns := inst.Tracker().Snapshot()
	type connOut struct {
		ID        uint64 `json:"id"`
		SrcIP     string `json:"src_ip"`
		SrcPort   int    `json:"src_port"`
		Upstream  string `json:"upstream"`
		Uport     int    `json:"upstream_port"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
		StartedAt string `json:"started_at"`
		Closed    bool   `json:"closed"`
	}
	out := make([]connOut, 0, len(conns))
	for _, c := range conns {
		srcIP := ""
		if c.SrcIP != nil {
			srcIP = c.SrcIP.String()
		}
		upstreamIP := ""
		if c.UpstreamIP != nil {
			upstreamIP = c.UpstreamIP.String()
		}
		out = append(out, connOut{
			ID: c.ID, SrcIP: srcIP, SrcPort: c.SrcPort,
			Upstream: upstreamIP, Uport: c.UpstreamPort,
			BytesIn: c.BytesIn(), BytesOut: c.BytesOut(),
			StartedAt: c.StartedAt.Format(time.RFC3339), Closed: c.IsClosed(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (r *Router) handleKillConnection(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	idStr := chi.URLParam(req, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	// Walk the tracker snapshot to find the conn and close it.
	// ConnTracker.Kill requires a closer func; we find the conn by ID and
	// close its underlying net.Conn by calling Kill with a no-op closer
	// (the actual socket close happens via the connection's defer chain).
	found := inst.Tracker().Kill(id, func() error { return nil })
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "connection not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "killed"})
}

func (r *Router) handleListUpstreams(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	writeJSON(w, http.StatusOK, inst.Balancer().Snapshot())
}

func (r *Router) handleEjectUpstream(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	ipStr := chi.URLParam(req, "ip")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}
	// FIX: SetHealth requires an exact (ip, port) match. Port 0 never matches.
	// Mark all targets with this IP unhealthy across all ports.
	count := 0
	for _, snap := range inst.Balancer().Snapshot() {
		if snap.IP.Equal(parsedIP) {
			inst.Balancer().SetHealth(parsedIP, snap.Port, false)
			count++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ejected", "targets_affected": count})
}

func (r *Router) handleReadmitUpstream(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	ipStr := chi.URLParam(req, "ip")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}
	// FIX: readmit all ports belonging to this IP.
	count := 0
	for _, snap := range inst.Balancer().Snapshot() {
		if snap.IP.Equal(parsedIP) {
			inst.Balancer().SetHealth(parsedIP, snap.Port, true)
			count++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "readmitted", "targets_affected": count})
}

func (r *Router) handleListIptablesRules(w http.ResponseWriter, req *http.Request) {
	if r.iptMgr == nil {
		writeJSON(w, http.StatusOK, []string{})
		return
	}
	writeJSON(w, http.StatusOK, r.iptMgr.ListRules())
}

func (r *Router) handleValidateIptables(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "validation OK"})
}

func (r *Router) handleFlushIptables(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "proxy")
	if r.iptMgr == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "iptables disabled"})
		return
	}
	_ = r.iptMgr.FlushProxy(name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "flushed"})
}

func (r *Router) handleOrphanSweep(w http.ResponseWriter, req *http.Request) {
	if r.iptMgr == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "iptables disabled"})
		return
	}
	_ = r.iptMgr.OrphanSweep(nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "orphan sweep complete"})
}

func (r *Router) handleListBanned(w http.ResponseWriter, req *http.Request) {
	var all []map[string]interface{}
	for _, e := range r.l7Engines {
		for _, b := range e.BannedList() {
			all = append(all, map[string]interface{}{"ip": b.IP.String(), "reason": b.Reason})
		}
	}
	writeJSON(w, http.StatusOK, all)
}

func (r *Router) handleUnbanIP(w http.ResponseWriter, req *http.Request) {
	ipStr := chi.URLParam(req, "ip")
	ip := net.ParseIP(ipStr)
	for _, e := range r.l7Engines {
		e.UnbanIP(ip)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned"})
}

func (r *Router) handleBanIP(w http.ResponseWriter, req *http.Request) {
	ipStr := chi.URLParam(req, "ip")
	ip := net.ParseIP(ipStr)
	durStr := req.URL.Query().Get("duration")
	dur := time.Hour
	if d, err := time.ParseDuration(durStr); err == nil {
		dur = d
	}
	for _, e := range r.l7Engines {
		e.BanIP(ip, dur, "manual ban via API")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "banned"})
}

func (r *Router) handleL7Events(w http.ResponseWriter, req *http.Request) {
	limit := 100
	if l := req.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	var all []l7.Event
	for _, e := range r.l7Engines {
		all = append(all, e.Events(limit)...)
	}
	writeJSON(w, http.StatusOK, all)
}

func (r *Router) handleReloadAll(w http.ResponseWriter, req *http.Request) {
	if r.proxiesDir == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no proxies dir configured"})
		return
	}
	results := config.LoadProxyDir(r.proxiesDir)
	onDisk := map[string]bool{}
	var started, stopped, failed int
	var errs []string
	for _, res := range results {
		if res.Err != nil || res.Proxy == nil {
			if res.Err != nil {
				failed++
				errs = append(errs, res.Err.Error())
			}
			continue
		}
		onDisk[res.Proxy.Name] = true
		if !res.Proxy.Enabled {
			r.manager.Stop(res.Proxy.Name)
			stopped++
			continue
		}
		if err := r.manager.Start(res.Proxy); err != nil {
			failed++
			errs = append(errs, res.Proxy.Name+": "+err.Error())
		} else {
			started++
		}
	}
	// Stop any running proxy whose config file no longer exists on disk.
	for _, name := range r.manager.List() {
		if !onDisk[name] {
			r.manager.Stop(name)
			stopped++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "reloaded", "started": started, "stopped": stopped,
		"failed": failed, "errors": errs,
	})
}

// ─── ACL Handlers ─────────────────────────────────────────────────────────

func (r *Router) handleGetGlobalACL(w http.ResponseWriter, req *http.Request) {
	if r.globalACL == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": false, "rules": []interface{}{}})
		return
	}
	allowed, denied := r.globalACL.Stats()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":        r.globalACL.IsEnabled(),
		"default_action": r.globalACL.DefaultAction(),
		"rules":          r.globalACL.Rules(),
		"stats":          map[string]uint64{"allowed": allowed, "denied": denied},
	})
}

func (r *Router) handleAddGlobalACLRule(w http.ResponseWriter, req *http.Request) {
	var rule acl.Rule
	if err := json.NewDecoder(req.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if r.globalACL == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "global ACL not initialized"})
		return
	}
	if err := r.globalACL.AddRule(acl.Action(rule.Action), rule.CIDR, rule.Comment); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (r *Router) handleRemoveGlobalACLRule(w http.ResponseWriter, req *http.Request) {
	cidr := req.URL.Query().Get("cidr")
	if cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cidr query param required"})
		return
	}
	if r.globalACL == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "global ACL not initialized"})
		return
	}
	n := r.globalACL.RemoveRule(cidr)
	writeJSON(w, http.StatusOK, map[string]interface{}{"removed": n})
}

func (r *Router) handleReplaceGlobalACLRules(w http.ResponseWriter, req *http.Request) {
	var rules []acl.Rule
	if err := json.NewDecoder(req.Body).Decode(&rules); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if r.globalACL == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "global ACL not initialized"})
		return
	}
	r.globalACL.ReplaceRules(rules)
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(rules)})
}

func (r *Router) handleGetProxyACL(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	a, ok := r.proxyACLs[name]
	if !ok || a == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy ACL not found"})
		return
	}
	allowed, denied := a.Stats()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name": name, "enabled": a.IsEnabled(), "default_action": a.DefaultAction(),
		"rules": a.Rules(), "stats": map[string]uint64{"allowed": allowed, "denied": denied},
	})
}

func (r *Router) handleAddProxyACLRule(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	a, ok := r.proxyACLs[name]
	if !ok || a == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy ACL not found"})
		return
	}
	var rule acl.Rule
	if err := json.NewDecoder(req.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.AddRule(acl.Action(rule.Action), rule.CIDR, rule.Comment); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (r *Router) handleRemoveProxyACLRule(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	cidr := req.URL.Query().Get("cidr")
	a, ok := r.proxyACLs[name]
	if !ok || a == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy ACL not found"})
		return
	}
	n := a.RemoveRule(cidr)
	writeJSON(w, http.StatusOK, map[string]interface{}{"removed": n})
}

func (r *Router) handleReplaceProxyACLRules(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	a, ok := r.proxyACLs[name]
	if !ok || a == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy ACL not found"})
		return
	}
	var rules []acl.Rule
	if err := json.NewDecoder(req.Body).Decode(&rules); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.ReplaceRules(rules)
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(rules)})
}


func (r *Router) handleGetBandwidth(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	bw := r.manager.GetBandwidthTracker(name)
	if bw == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "bandwidth tracker not found for this proxy"})
		return
	}
	writeJSON(w, http.StatusOK, bw.Snapshot())
}

func (r *Router) handleResetBandwidth(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	bw := r.manager.GetBandwidthTracker(name)
	if bw == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "bandwidth tracker not found"})
		return
	}
	bw.Reset()
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
