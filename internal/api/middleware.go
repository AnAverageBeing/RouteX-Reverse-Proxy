package api

import (
	"net/http"

	"github.com/AnAverageBeing/RouteX-Reverse-Proxy/internal/config"
)

type AuthMiddleware struct {
	global *config.Global
}

func NewAuthMiddleware(g *config.Global) *AuthMiddleware {
	return &AuthMiddleware{global: g}
}

func (am *AuthMiddleware) RequirePermission(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if am.global.APIAuthBypass() {
				next.ServeHTTP(w, r)
				return
			}
			key := extractAPIKey(r)
			if key == "" {
				http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
				return
			}
			apiKey, ok := am.global.LookupAPIKey(key)
			if !ok {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}
			if !config.HasPermission(apiKey.Permissions, scope) {
				http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractAPIKey(r *http.Request) string {
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}
	return r.URL.Query().Get("api_key")
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
