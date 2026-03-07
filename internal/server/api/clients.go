package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
)

type maskedClient struct {
	clients.Client
	SecretHash string `json:"secret_hash,omitempty"`
	Secret     bool   `json:"secret"`
}

func LookupClientHandler(clientStore clients.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		if httputil.AllowMethods(w, r, []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost}, true, true) {
			return
		}

		var (
			clientID = strings.TrimSpace(r.PathValue("client_id"))
			client   clients.Client
		)

		if c, err := clientStore.Lookup(clientID); err != nil {
			if errors.Is(err, clients.ErrClientNotFound) {
				Problem(w, http.StatusNotFound, err.Error())
			} else {
				Problem(w, http.StatusInternalServerError, err.Error())
			}
			return
		} else {
			client = *c
		}

		if jsonBytes, err := json.Marshal(maskedClient{Client: client, Secret: client.SecretHash != ""}); err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(jsonBytes)
		}
	})
}
