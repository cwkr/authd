package server

import (
	"crypto/rsa"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"

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
	basePath        string
	serverSettings  *settings.Server
	publicKey       *rsa.PublicKey
	sessionManager  session.Manager
	clientStore     clients.Store
	scope           string
	tpl             *template.Template
	version         string
	customKeySetURI string
}

func (i *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

	if httputil.AllowMethods(w, r, []string{http.MethodGet, http.MethodHead, http.MethodOptions}, false, false) {
		return
	}

	var (
		clientIDs      []string
		currentSession session.Current
	)

	if cids, err := i.clientStore.List(); err == nil {
		clientIDs = cids
	} else {
		httputil.PlainError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	i.sessionManager.GetCurrentSession(&currentSession, r)

	httputil.NoCache(w)

	var title = strings.TrimSpace(i.serverSettings.Title)
	if title == "" {
		title = "Auth Server"
	}

	var (
		codeVerifier = stringutil.RandomAlphanumericString(10)
		jwksURI      = i.basePath + "/.well-known/keys"
	)

	if customKeySetURI := strings.TrimSpace(i.customKeySetURI); customKeySetURI != "" {
		if !strings.HasPrefix(customKeySetURI, "http://") && !strings.HasPrefix(customKeySetURI, "https://") {
			jwksURI = i.basePath + "/" + strings.Trim(customKeySetURI, "/")
		}
	}

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
		"jwks_uri":        jwksURI,
	})
	if err != nil {
		httputil.PlainError(w, err.Error(), http.StatusInternalServerError)
	}
}

func IndexHandler(basePath string, serverSettings *settings.Server, sessionManager session.Manager, clientStore clients.Store, scope, version, customKeySetURI string) http.Handler {
	return &indexHandler{
		basePath:        basePath,
		serverSettings:  serverSettings,
		sessionManager:  sessionManager,
		clientStore:     clientStore,
		scope:           scope,
		tpl:             template.Must(template.New("index").Funcs(stringutil.TemplateFuncs).Parse(indexTpl)),
		version:         version,
		customKeySetURI: customKeySetURI,
	}
}
