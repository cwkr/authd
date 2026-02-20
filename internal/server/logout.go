package server

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/server/session"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/cwkr/authd/settings"
	"github.com/go-jose/go-jose/v3/jwt"
)

//go:embed templates/logout.gohtml
var logoutTpl string

func LoadLogoutTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		logoutTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type logoutHandler struct {
	basePath       string
	serverSettings *settings.Server
	sessionManager session.Manager
	clientStore    clients.Store
	tpl            *template.Template
}

func (l *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		clientID    = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI = strings.TrimSpace(r.FormValue("post_logout_redirect_uri"))
		idTokenHint = strings.TrimSpace(r.FormValue("id_token_hint"))
	)

	if idTokenHint != "" {
		if token, err := jwt.ParseSigned(idTokenHint); err == nil {
			var claims = jwt.Claims{}
			if err := token.UnsafeClaimsWithoutVerification(&claims); err == nil {
				if len([]string(claims.Audience)) > 0 && claims.Issuer == l.serverSettings.Issuer {
					clientID = claims.Audience[0]
				}
			}
		}
	}

	if clientID == "" {
		htmlutil.Error(w, l.basePath, "client_id or id_token_hint parameters are required", http.StatusBadRequest)
		return
	}

	var client clients.Client
	if c, err := l.clientStore.Lookup(clientID); err != nil {
		htmlutil.Error(w, l.basePath, "invalid_client", http.StatusForbidden)
		return
	} else {
		client = *c
	}

	if redirectURI != "" && !strings.HasPrefix(redirectURI, strings.TrimRight(l.serverSettings.Issuer, "/")) {
		if !client.MatchesRedirectURI(redirectURI) {
			htmlutil.Error(w, l.basePath, "post_logout_redirect_uri mismatch", http.StatusBadRequest)
			return
		}
	}

	httputil.NoCache(w)

	if err := l.sessionManager.EndSession(r, w, client); err != nil {
		htmlutil.Error(w, l.basePath, err.Error(), http.StatusInternalServerError)
		return
	}

	if redirectURI != "" {
		http.Redirect(w, r, redirectURI, http.StatusFound)
	} else {
		w.Header().Set("Content-Type", "text/html;charset=UTF-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := l.tpl.ExecuteTemplate(w, "logout", map[string]any{"base_path": l.basePath}); err != nil {
			htmlutil.Error(w, l.basePath, err.Error(), http.StatusInternalServerError)
		}
	}
}

func LogoutHandler(basePath string, serverSettings *settings.Server, sessionManager session.Manager, clientStore clients.Store) http.Handler {
	return &logoutHandler{
		basePath:       basePath,
		serverSettings: serverSettings,
		sessionManager: sessionManager,
		clientStore:    clientStore,
		tpl:            template.Must(template.New("logout").Funcs(stringutil.TemplateFuncs).Parse(logoutTpl)),
	}
}
