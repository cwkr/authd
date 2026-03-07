package server

import (
	"encoding/json"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
)

func InfoHandler(version, runtimeVersion string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if httputil.AllowMethods(w, r, []string{http.MethodGet, http.MethodHead, http.MethodOptions}, true, false) {
			return
		}

		var info = struct {
			Version   string `json:"version"`
			GoVersion string `json:"go_version"`
		}{version, runtimeVersion}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		var bytes, _ = json.Marshal(info)
		w.Write(bytes)
	})
}
