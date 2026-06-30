package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/acl"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/api"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/iptables"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/metrics"
	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/proxy"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Version   = "0.1.0"
	BuildTime = "unknown"
)

func main() {
	globalCfgPath := flag.String("config", "configs/global.yaml", "path to global config")
	proxiesDir := flag.String("proxies", "configs/proxies", "path to proxies directory")
	flag.Parse()

	global, err := config.LoadGlobal(*globalCfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load global config: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(global)
	defer logger.Sync()

	logger.Info("RouteX starting",
		zap.String("version", Version),
		zap.String("build", BuildTime))

	results := config.LoadProxyDir(*proxiesDir)

	var proxies []*config.Proxy
	for _, r := range results {
		if r.Err != nil {
			logger.Error("proxy config error — skipping",
				zap.String("path", r.Path), zap.Error(r.Err))
			continue
		}
		if r.Proxy != nil && r.Proxy.Enabled {
			proxies = append(proxies, r.Proxy)
		}
	}

	if len(proxies) == 0 {
		logger.Warn("no enabled proxy configs found — nothing to proxy")
	} else {
		logger.Info("loaded proxy configs", zap.Int("count", len(proxies)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── iptables ──────────────────────────────────────────────────────────
	var iptMgr *iptables.Manager
	if global.Iptables.Enabled {
		iptMgr, err = iptables.NewManager(
			global.Iptables.CommentPrefix,
			global.Iptables.IPv6Enabled,
			logger,
		)
		if err != nil {
			logger.Error("iptables manager init failed", zap.Error(err))
		} else {
			logger.Info("iptables manager initialized",
				zap.String("prefix", global.Iptables.CommentPrefix))
		}
	}

	// ── Global ACL ────────────────────────────────────────────────────────
	var globalACL *acl.Engine
	if global.ACL.Enabled {
		defaultAction := acl.Action(global.ACL.DefaultAction)
		if defaultAction == "" {
			defaultAction = acl.Allow
		}
		rules := make([]acl.Rule, 0, len(global.ACL.Rules))
		for _, r := range global.ACL.Rules {
			rules = append(rules, acl.Rule{
				Action: acl.Action(r.Action), CIDR: r.CIDR, Comment: r.Comment,
			})
		}
		globalACL, err = acl.NewEngine("global", defaultAction, rules, true)
		if err != nil {
			logger.Error("global ACL init failed", zap.Error(err))
		} else {
			logger.Info("global ACL initialized",
				zap.Int("rules", len(rules)),
				zap.String("default", string(defaultAction)))
		}
	}

	// ── Proxy Manager ─────────────────────────────────────────────────────
	proxyMgr := proxy.NewManager(global, logger)
	// Only register the global ACL when it actually exists. Passing a typed-nil
	// *acl.Engine here would store a non-nil ACLChecker interface wrapping a nil
	// pointer, which defeats every `== nil` guard downstream and panics on Check.
	if globalACL != nil {
		proxyMgr.SetGlobalACL(globalACL)
	}

	// L7 engines are owned by the proxy manager now (created in buildInstance and
	// wired directly into the TCP/UDP data path). The API reads them via
	// proxyMgr.AllL7Engines(). proxyACLs is still built here for the ACL API.
	proxyACLs := make(map[string]*acl.Engine)

	proxyMgr.SetHooks(
		func(inst *proxy.Instance) {
			// iptables
			if iptMgr != nil {
				ports := inst.Config.ResolveOriginPorts()
				rules := iptables.BuildRules(
					inst.Name, ports,
					inst.Config.RateLimits,
					inst.Config.Protocol,
					global.Iptables.CommentPrefix,
				)
				if applyErr := iptMgr.ApplyRules(inst.Name, ports, rules); applyErr != nil {
					logger.Error("iptables apply failed",
						zap.String("proxy", inst.Name), zap.Error(applyErr))
				}
			}
			// Per-proxy ACL
			if inst.Config.ACL.DefaultAction != "" {
				da := acl.Action(inst.Config.ACL.DefaultAction)
				if da == "" {
					da = acl.Allow
				}
				rules := make([]acl.Rule, 0, len(inst.Config.ACL.Rules))
				for _, r := range inst.Config.ACL.Rules {
					rules = append(rules, acl.Rule{
						Action: acl.Action(r.Action), CIDR: r.CIDR, Comment: r.Comment,
					})
				}
				pac, aclErr := acl.NewEngine(inst.Name, da, rules, true)
				if aclErr == nil {
					proxyACLs[inst.Name] = pac
					proxyMgr.SetProxyACL(inst.Name, pac)
				}
			}
		},
		func(inst *proxy.Instance) {
			if iptMgr != nil {
				_ = iptMgr.FlushProxy(inst.Name)
			}
			// L7 engine lifecycle is handled by the proxy manager (Instance.Stop).
			delete(proxyACLs, inst.Name)
		},
	)

	for _, p := range proxies {
		if startErr := proxyMgr.Start(p); startErr != nil {
			logger.Error("failed to start proxy",
				zap.String("name", p.Name), zap.Error(startErr))
		}
	}

	// ── Metrics ───────────────────────────────────────────────────────────
	var metStore *metrics.Store
	var metAPI *metrics.MetricsAPI
	if global.Metrics.Enabled {
		metStore, err = metrics.NewStore(
			global.Metrics.SqlitePath,
			time.Duration(global.Metrics.FlushIntervalSeconds)*time.Second,
			time.Duration(global.Metrics.RetentionHours)*time.Hour,
			logger,
		)
		if err != nil {
			logger.Error("metrics store init failed", zap.Error(err))
		} else {
			metAPI = metrics.NewMetricsAPI(metStore)
			collector := metrics.NewCollector(metStore, proxyMgr, 10*time.Second, logger)
			collector.Start()
			defer collector.Stop()
			logger.Info("metrics store initialized")
		}
	}

	// ── API Server ────────────────────────────────────────────────────────
	if global.API.Enabled {
		apiRouter := api.NewRouter(global, proxyMgr, iptMgr, proxyMgr.AllL7Engines(), metAPI, logger, Version, globalACL, proxyACLs)
		var tlsCfg *api.TLSConfig
		if global.API.TLS.Enabled {
			tlsCfg = &api.TLSConfig{
				Enabled: true, Cert: global.API.TLS.Cert, Key: global.API.TLS.Key,
			}
		}
		apiSrv := api.NewServer(global.API.Bind, apiRouter, tlsCfg, logger)
		go func() {
			if startErr := apiSrv.Start(ctx); startErr != nil {
				logger.Error("API server error", zap.Error(startErr))
			}
		}()
	}

	// ── Config Watcher (hot reload) ───────────────────────────────────────
	watcher, watchErr := config.NewWatcher(*globalCfgPath, *proxiesDir, logger)
	if watchErr != nil {
		logger.Warn("config watcher init failed — hot reload disabled", zap.Error(watchErr))
	} else {
		defer watcher.Close()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ch, ok := <-watcher.Events():
					if !ok {
						return
					}
					if ch.IsGlobal {
						logger.Info("global config changed — full reload not yet supported; restart to apply")
						continue
					}
					// Per-proxy file changed: reload only that proxy.
					p, loadErr := config.LoadProxy(ch.Path)
					if loadErr != nil {
						logger.Error("hot reload: config parse failed",
							zap.String("path", ch.Path), zap.Error(loadErr))
						continue
					}
					if ch.Kind == config.ChangeRemove {
						proxyMgr.Stop(p.Name)
						logger.Info("hot reload: proxy removed", zap.String("name", p.Name))
					} else {
						if startErr := proxyMgr.Start(p); startErr != nil {
							logger.Error("hot reload: proxy restart failed",
								zap.String("name", p.Name), zap.Error(startErr))
						} else {
							logger.Info("hot reload: proxy reloaded", zap.String("name", p.Name))
						}
					}
				}
			}
		}()
		logger.Info("config watcher started — hot reload enabled")
	}

	// ── Shutdown ──────────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("received signal, shutting down gracefully", zap.String("signal", sig.String()))

	cancel()
	proxyMgr.StopAll()
	if metStore != nil {
		_ = metStore.Close()
	}
	logger.Info("RouteX stopped cleanly")
}

func buildLogger(g *config.Global) *zap.Logger {
	cfg := zap.NewProductionConfig()
	switch g.Logging.Level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	if g.Logging.Format == "text" {
		cfg.Encoding = "console"
	} else {
		cfg.Encoding = "json"
	}
	if g.Logging.Output == "file" {
		cfg.OutputPaths = []string{g.Logging.FilePath}
	} else {
		cfg.OutputPaths = []string{"stdout"}
	}
	logger, buildErr := cfg.Build()
	if buildErr != nil {
		return zap.NewNop()
	}
	return logger
}
