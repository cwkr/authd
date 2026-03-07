package httputil

import (
	"net/http"
	"slices"
	"strings"
)

func BearerAuth(r *http.Request) (string, bool) {
	var fields = strings.Fields(r.Header.Get("Authorization"))
	if len(fields) >= 2 && strings.EqualFold("Bearer", fields[0]) {
		return fields[1], true
	}
	return "", false
}

func AllowCORS(w http.ResponseWriter, r *http.Request, allowMethods []string, allowCredentials bool) {
	var allowedMethods = strings.Join(allowMethods, ", ")

	w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	if requestHeaders := r.Header.Get("Access-Control-Request-Headers"); requestHeaders != "" {
		w.Header().Set("Access-Control-Allow-Headers", requestHeaders)
	}
	if allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Access-Control-Max-Age", "7200")
	w.Header().Set("Vary", "Origin, Access-Control-Request-Headers")
}

func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func AllowMethods(w http.ResponseWriter, r *http.Request, allowedMethods []string, allowCORS, allowCredentials bool) bool {
	if !slices.Contains(allowedMethods, r.Method) {
		w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
		PlainError(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if allowCORS {
		AllowCORS(w, r, allowedMethods, allowCredentials)
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}
