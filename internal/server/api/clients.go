package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/gorilla/mux"
)

type maskedClient struct {
	clients.Client
	SecretHash string `json:"secret_hash,omitempty"`
	Secret     bool   `json:"secret"`
}

func LookupClientHandler(clientStore clients.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, true)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var (
			clientID = mux.Vars(r)["client_id"]
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
