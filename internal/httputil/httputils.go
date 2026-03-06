package httputil

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

func RedirectFragment(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s#%s", url, params.Encode()), http.StatusFound)
}

func RedirectQuery(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s?%s", url, params.Encode()), http.StatusFound)
}

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

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", allowedMethods)
	}
}

func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func IsJSON(contentType string) bool {
	var mediaType, _, err = mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "application") && strings.HasSuffix(mediaType, "json")
}

func IsFormData(contentType string) bool {
	var mediaType, _, err = mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return slices.Contains([]string{"application/x-www-form-urlencoded", "multipart/form-data"}, mediaType)
}
