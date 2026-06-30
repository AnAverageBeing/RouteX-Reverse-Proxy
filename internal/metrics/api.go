package metrics

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type MetricsAPI struct {
	store *Store
}

func NewMetricsAPI(store *Store) *MetricsAPI {
	return &MetricsAPI{store: store}
}

// Store exposes the underlying metrics store so the REST API can serve
// historical time-series and aggregate dashboard queries.
func (api *MetricsAPI) Store() *Store { return api.store }

func (api *MetricsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	path := strings.TrimPrefix(r.URL.Path, "/metrics")
	path = strings.TrimPrefix(path, "/")
	proxyName := strings.TrimPrefix(path, "proxy/")
	if proxyName != "" && proxyName != path {
		api.serveProxyMetrics(w, r, proxyName, format)
		return
	}
	api.serveGlobalMetrics(w, format)
}

func (api *MetricsAPI) serveGlobalMetrics(w http.ResponseWriter, format string) {
	g := api.store.GlobalSnapshot()
	all := api.store.All()
	metrics := map[string]interface{}{
		"active_connections": g.ActiveConnections,
		"total_connections":  g.TotalConnections,
		"bytes_in":           g.TotalBytesIn,
		"bytes_out":          g.TotalBytesOut,
		"proxy_count":        len(all),
	}
	switch format {
	case "json":
		writeJSON(w, metrics)
	case "prometheus":
		writePrometheus(w, metrics, all)
	case "influx":
		writeInflux(w, metrics)
	case "csv":
		writeCSV(w, metrics)
	default:
		writeJSON(w, metrics)
	}
}

func (api *MetricsAPI) serveProxyMetrics(w http.ResponseWriter, r *http.Request, name, format string) {
	m := api.store.Get(name)
	if m == nil {
		http.Error(w, "proxy not found", http.StatusNotFound)
		return
	}
	metrics := map[string]interface{}{
		"proxy_name":         m.Name,
		"active_connections": m.ActiveConnections,
		"bytes_in":           m.BytesIn,
		"bytes_out":          m.BytesOut,
	}
	writeJSON(w, metrics)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writePrometheus(w http.ResponseWriter, global map[string]interface{}, proxies map[string]*ProxyMetrics) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	sb := &strings.Builder{}
	writePromMetric(sb, "routex_active_connections", "gauge", fmt.Sprintf("%v", global["active_connections"]), nil)
	writePromMetric(sb, "routex_total_connections", "counter", fmt.Sprintf("%v", global["total_connections"]), nil)
	writePromMetric(sb, "routex_bytes_in", "counter", fmt.Sprintf("%v", global["bytes_in"]), nil)
	writePromMetric(sb, "routex_bytes_out", "counter", fmt.Sprintf("%v", global["bytes_out"]), nil)
	for name, m := range proxies {
		labels := map[string]string{"proxy": name}
		writePromMetric(sb, "routex_proxy_active_connections", "gauge", fmt.Sprintf("%d", m.ActiveConnections), labels)
		writePromMetric(sb, "routex_proxy_bytes_in", "counter", fmt.Sprintf("%d", m.BytesIn), labels)
		writePromMetric(sb, "routex_proxy_bytes_out", "counter", fmt.Sprintf("%d", m.BytesOut), labels)
		for key, u := range m.Upstreams {
			uLabels := map[string]string{"proxy": name, "upstream": key}
			writePromMetric(sb, "routex_upstream_active_conns", "gauge", fmt.Sprintf("%d", u.ActiveConns), uLabels)
			writePromMetric(sb, "routex_upstream_healthy", "gauge", fmt.Sprintf("%d", u.Healthy), uLabels)
		}
	}
	w.Write([]byte(sb.String()))
}

func writePromMetric(sb *strings.Builder, name, typ, value string, labels map[string]string) {
	if labels != nil {
		labelStr := ""
		for k, v := range labels {
			labelStr += fmt.Sprintf(`%s="%s",`, k, v)
		}
		labelStr = strings.TrimRight(labelStr, ",")
		sb.WriteString(fmt.Sprintf("# TYPE %s %s\n%s{%s} %s\n", name, typ, name, labelStr, value))
	} else {
		sb.WriteString(fmt.Sprintf("# TYPE %s %s\n%s %s\n", name, typ, name, value))
	}
}

func writeInflux(w http.ResponseWriter, metrics map[string]interface{}) {
	w.Header().Set("Content-Type", "text/plain")
	now := time.Now().UnixNano()
	sb := &strings.Builder{}
	for k, v := range metrics {
		sb.WriteString(fmt.Sprintf("routex %s=%v %d\n", k, v, now))
	}
	w.Write([]byte(sb.String()))
}

func writeCSV(w http.ResponseWriter, metrics map[string]interface{}) {
	w.Header().Set("Content-Type", "text/csv")
	wr := csv.NewWriter(w)
	_ = wr.Write([]string{"metric", "value"})
	for k, v := range metrics {
		_ = wr.Write([]string{k, fmt.Sprintf("%v", v)})
	}
	wr.Flush()
}


