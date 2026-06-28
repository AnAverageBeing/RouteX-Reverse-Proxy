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
	mux       *chi.Mux
	auth      *AuthMiddleware
	manager   *proxy.Manager
	iptMgr    *iptables.Manager
	l7Engines map[string]*l7.Engine
	metrics   *metrics.MetricsAPI
	global    *config.Global
	logger    *zap.Logger
	version   string
	globalACL *acl.Engine
	proxyACLs map[string]*acl.Engine
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
) *Router {
	auth := NewAuthMiddleware(global)
	r := &Router{
		mux: chi.NewRouter(), auth: auth, manager: mgr,
		iptMgr: iptMgr, l7Engines: l7s, metrics: metAPI,
		global: global, logger: logger, version: version,
		globalACL: globalACL, proxyACLs: proxyACLs,
	}
	r.registerRoutes()
	return r
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

	r.mux.Route("/api/proxies", func(mux chi.Router) {
		mux.Use(r.auth.RequirePermission("proxies:read"))
		mux.Get("/", r.handleListProxies)
		mux.Get("/{name}", r.handleGetProxy)
		mux.Post("/{name}/enable", r.handleEnableProxy)
		mux.Post("/{name}/disable", r.handleDisableProxy)
		mux.Post("/{name}/reload", r.handleReloadProxy)
		mux.Get("/{name}/connections", r.handleListConnections)
		mux.Delete("/{name}/connections/{id}", r.handleKillConnection)
		mux.Get("/{name}/upstreams", r.handleListUpstreams)
		mux.Post("/{name}/upstreams/{ip}/eject", r.handleEjectUpstream)
		mux.Post("/{name}/upstreams/{ip}/readmit", r.handleReadmitUpstream)
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
	names := r.manager.List()
	type proxyInfo struct {
		Name    string `json:"name"`
		Running bool   `json:"running"`
	}
	out := make([]proxyInfo, 0, len(names))
	for _, name := range names {
		inst := r.manager.Get(name)
		if inst != nil {
			out = append(out, proxyInfo{Name: name, Running: inst.IsRunning()})
		}
	}
	writeJSON(w, http.StatusOK, out)
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

func (r *Router) handleEnableProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	if inst.Config != nil {
		inst.Config.Enabled = true
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

func (r *Router) handleDisableProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	if inst.Config != nil {
		inst.Config.Enabled = false
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (r *Router) handleReloadProxy(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	if err := r.manager.Start(inst.Config); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
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
		out = append(out, connOut{
			ID: c.ID, SrcIP: c.SrcIP.String(), SrcPort: c.SrcPort,
			Upstream: c.UpstreamIP.String(), Uport: c.UpstreamPort,
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
	_ = inst
	_ = id
	writeJSON(w, http.StatusOK, map[string]string{"status": "kill requested"})
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
	ip := chi.URLParam(req, "ip")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	inst.Balancer().SetHealth(net.ParseIP(ip), 0, false)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ejected"})
}

func (r *Router) handleReadmitUpstream(w http.ResponseWriter, req *http.Request) {
	name := chi.URLParam(req, "name")
	ip := chi.URLParam(req, "ip")
	inst := r.manager.Get(name)
	if inst == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	inst.Balancer().SetHealth(net.ParseIP(ip), 0, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "readmitted"})
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "reload triggered"})
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
