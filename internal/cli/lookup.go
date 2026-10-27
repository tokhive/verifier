package cli

import (
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/tokhive/verifier/lookup"
)

// LookupHandler adds a narrowly scoped buyer evidence bridge to the static UI.
// It accepts no local evidence files. The destination is fixed at startup and
// credentials exist only for the lifetime of the user's lookup request.
func LookupHandler(assets fs.FS, baseURL string) http.Handler {
	static := Handler(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/lookup" && r.URL.Path != "/api/config" {
			static.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		// Refuse DNS rebinding and cross-origin requests to the local bridge.
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
			http.Error(w, "Loopback host required", 403)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host || u.Scheme != "http" {
				http.Error(w, "Same-origin request required", 403)
				return
			}
		}
		if r.URL.Path == "/api/config" {
			if r.Method != http.MethodGet {
				http.Error(w, "GET required", 405)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"api_base_url": baseURL})
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST required", 405)
			return
		}
		if r.Header.Get("X-TokHive-Verifier") != "1" || strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
			http.Error(w, "JSON verifier request required", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var input struct {
			RequestID string `json:"request_id"`
			APIKey    string `json:"api_key"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&input) != nil || d.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "Invalid lookup request", 400)
			return
		}
		bundle, err := lookup.Fetch(r.Context(), lookup.Config{BaseURL: baseURL, APIKey: input.APIKey}, input.RequestID)
		if err != nil {
			w.WriteHeader(502)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(bundle)
	})
}
