package server

import (
	"crypto/rsa"
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/pkce"
	"github.com/cwkr/authd/internal/server/session"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/cwkr/authd/settings"
)

//go:embed templates/index.gohtml
var indexTpl string

type indexHandler struct {
	basePath       string
	serverSettings *settings.Server
	publicKey      *rsa.PublicKey
	sessionManager session.Manager
	clientStore    clients.Store
	scope          string
	tpl            *template.Template
	version        string
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		clientIDs      []string
		currentSession session.Current
	)

	if cids, err := i.clientStore.List(); err == nil {
		clientIDs = cids
	} else {
		htmlutil.Error(w, i.basePath, err.Error(), http.StatusInternalServerError)
		return
	}

	i.sessionManager.GetCurrentSession(&currentSession, r)

	httputil.NoCache(w)

	var title = strings.TrimSpace(i.serverSettings.Title)
	if title == "" {
		title = "Auth Server"
	}
	var codeVerifier = stringutil.RandomAlphanumericString(10)
	var err = i.tpl.ExecuteTemplate(w, "index", map[string]any{
		"base_path":       i.basePath,
		"issuer":          strings.TrimRight(i.serverSettings.Issuer, "/"),
		"title":           title,
		"public_key":      i.serverSettings.PublicKeyPEM(false),
		"state":           fmt.Sprint(rand.Int()),
		"nonce":           stringutil.RandomAlphanumericString(10),
		"scopes":          strings.Fields(i.scope),
		"code_verifier":   codeVerifier,
		"code_challenge":  pkce.CodeChallange(codeVerifier),
		"version":         i.version,
		"client_ids":      clientIDs,
		"current_session": currentSession,
	})
	if err != nil {
		htmlutil.Error(w, i.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(basePath string, serverSettings *settings.Server, sessionManager session.Manager, clientStore clients.Store, scope, version string) http.Handler {
	return &indexHandler{
		basePath:       basePath,
		serverSettings: serverSettings,
		sessionManager: sessionManager,
		clientStore:    clientStore,
		scope:          scope,
		tpl:            template.Must(template.New("index").Funcs(stringutil.TemplateFuncs).Parse(indexTpl)),
		version:        version,
	}
}
