package oauth2

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/keyset"
	"github.com/go-jose/go-jose/v3"
)

type jwksHandler struct {
	keySetProvider keyset.Provider
}

func (j *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var keySet jose.JSONWebKeySet
	if publicKeys, err := j.keySetProvider.Get(); err != nil {
		Error(w, "key_retrieval_error", err.Error(), http.StatusInternalServerError)
		return
	} else {
		keySet = jose.JSONWebKeySet{
			Keys: ToJwks(publicKeys),
		}
	}

	if bytes, err := json.Marshal(keySet); err != nil {
		Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
		return
	} else {
		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	}
}

// ToJwks creates JSON Web Keys from multiple public keys
func ToJwks(publicKeys map[string]any) []jose.JSONWebKey {
	var keys = make([]jose.JSONWebKey, 0, len(publicKeys))
	for kid, publicKey := range publicKeys {
		keys = append(keys, jose.JSONWebKey{
			Key:   publicKey,
			KeyID: kid,
			Use:   "sig",
		})
	}
	return keys
}

func JwksHandler(keySetProvider keyset.Provider) http.Handler {
	return &jwksHandler{keySetProvider}
}
