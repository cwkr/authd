package server

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/server/sessions"
	"github.com/cwkr/authd/internal/stringutil"
)

//go:embed templates/otp.gohtml
var otpTpl string

type otpHandler struct {
	sessionManager sessions.SessionManager
	clientStore    clients.Store
	otpauthStore   otpauth.Store
	tpl            *template.Template
	basePath       string
	version        string
}

func (o *otpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var clientID = strings.TrimSpace(r.FormValue("client_id"))

	if stringutil.IsAnyEmpty(clientID) {
		htmlutil.Error(w, o.basePath, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	var client clients.Client
	if c, err := o.clientStore.Lookup(clientID); err != nil {
		htmlutil.Error(w, o.basePath, "client not found", http.StatusForbidden)
		return
	} else {
		client = *c
	}

	if uid, active, _ := o.sessionManager.CheckSession(r, client); active {
		keyWrapper, _ := o.otpauthStore.Lookup(uid)
		httputil.NoCache(w)
		var imageURL string
		if keyWrapper != nil {
			if dataURL, err := keyWrapper.PNG(); err != nil {
				htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
				return
			} else {
				imageURL = dataURL
			}
		}
		if err := o.tpl.ExecuteTemplate(w, "otp", map[string]any{
			"base_path":         o.basePath,
			"qrcode":            template.URL(imageURL),
			"user_totp_enabled": keyWrapper != nil,
			"version":           o.version,
		}); err != nil {
			htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		htmlutil.Error(w, o.basePath, "not logged in", http.StatusUnauthorized)
		return
	}
}

func OTPHandler(sessionManager sessions.SessionManager, clientStore clients.Store, otpauthStore otpauth.Store, basePath, version string) http.Handler {
	return &otpHandler{
		sessionManager: sessionManager,
		clientStore:    clientStore,
		otpauthStore:   otpauthStore,
		tpl:            template.Must(template.New("otp").Parse(otpTpl)),
		basePath:       basePath,
		version:        version,
	}
}
