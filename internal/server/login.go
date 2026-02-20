package server

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/server/session"
	"github.com/cwkr/authd/internal/stringutil"
)

//go:embed templates/login.gohtml
var loginTpl string

func LoadLoginTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		loginTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type loginHandler struct {
	basePath             string
	sessionManager       session.Manager
	peopleStore          people.Store
	clientStore          clients.Store
	otpauthStore         otpauth.Store
	issuer               string
	passwordResetEnabled bool
	tpl                  *template.Template
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		message, userID, password, clientID, code string
		sessionActive, sessionVerified            bool
		kw                                        *otpauth.KeyWrapper
	)

	clientID = strings.ToLower(r.FormValue("client_id"))
	if clientID == "" {
		htmlutil.Error(w, j.basePath, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	var client clients.Client
	if c, err := j.clientStore.Lookup(clientID); err == nil {
		client = *c
	} else {
		htmlutil.Error(w, j.basePath, "invalid_client", http.StatusForbidden)
		return
	}

	var (
		require2FA       = client.Require2FA
		loginQueryBase64 = base64.RawURLEncoding.EncodeToString([]byte(r.URL.RawQuery))
	)

	userID, sessionActive, sessionVerified = j.sessionManager.CheckSession(r, client)

	if !sessionActive {
		userID = strings.TrimSpace(r.FormValue("user_id"))
		if userID == "" {
			userID = strings.TrimSpace(r.FormValue("username"))
		}
	}

	if userID != "" {
		if k, err := j.otpauthStore.Lookup(userID); err == nil {
			kw = k
		}
	}

	if r.Method == http.MethodPost {
		password = r.PostFormValue("password")
		code = stringutil.StripSpaces(r.PostFormValue("code"))

		// debug output of parameters
		log.Printf("user_id=%q password=%q code=%q", userID, strings.Repeat("*", utf8.RuneCountInString(password)), strings.Repeat("*", utf8.RuneCountInString(code)))

		if !sessionActive {
			if stringutil.IsAnyEmpty(userID, password) {
				message = "username and password must not be empty"
			} else {
				if realUserID, err := j.peopleStore.Authenticate(userID, password); err == nil {
					var codeRequired = require2FA || kw != nil
					if err := j.sessionManager.CreateSession(r, w, client, realUserID, !codeRequired); err != nil {
						htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
						return
					}
					sessionActive = true
					if codeRequired {
						sessionVerified = false
						if kw == nil {
							var params = make(url.Values)
							params.Set("client_id", clientID)
							params.Set("login_query", loginQueryBase64)
							httputil.RedirectQuery(w, r, strings.TrimRight(j.issuer, "/")+"/setup-2fa", params)
							return
						}
					} else {
						sessionVerified = true
					}
				} else {
					message = err.Error()
				}
			}
		} else {
			if !sessionVerified {
				if stringutil.IsAnyEmpty(code) {
					message = "code must not be empty"
				} else {
					if kw == nil {
						message = "OTP Key not found"
					} else {
						if kw.VerifyCode(code) == true {
							if err := j.sessionManager.VerifySession(r, w, client); err != nil {
								message = err.Error()
							} else {
								sessionVerified = true
							}
						} else {
							message = fmt.Sprintf("code %s is invalid", code)
						}
					}
				}
			}
		}
	} else if r.Method == http.MethodGet {
		httputil.NoCache(w)
		if sessionActive && !sessionVerified && kw == nil && require2FA {
			var params = make(url.Values)
			params.Set("client_id", clientID)
			params.Set("login_query", loginQueryBase64)
			httputil.RedirectQuery(w, r, strings.TrimRight(j.issuer, "/")+"/setup-2fa", params)
			return
		}
	}

	if sessionActive && sessionVerified {
		message = "current active session for " + userID
		var authorizeQueryBase64 = strings.TrimSpace(r.URL.Query().Get("authorize_query"))
		if authorizeQueryBase64 != "" {
			if authorizeQuery, err := base64.RawURLEncoding.DecodeString(authorizeQueryBase64); err == nil {
				var query, _ = url.ParseQuery(string(authorizeQuery))
				httputil.RedirectQuery(w, r, strings.TrimRight(j.issuer, "/")+"/authorize", query)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var err = j.tpl.ExecuteTemplate(w, "login", map[string]any{
		"base_path":              j.basePath,
		"issuer":                 strings.TrimRight(j.issuer, "/"),
		"query":                  template.HTML("?" + r.URL.RawQuery),
		"message":                message,
		"client_id":              clientID,
		"login_query_base64":     loginQueryBase64,
		"user_id":                userID,
		"password_empty":         password == "",
		"code_required":          sessionActive && !sessionVerified,
		"password_reset_enabled": j.passwordResetEnabled,
	})
	if err != nil {
		htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(basePath string, sessionManager session.Manager, peopleStore people.Store, clientStore clients.Store, otpauthStore otpauth.Store, issuer string, passwordResetEnabled bool) http.Handler {
	return &loginHandler{
		basePath:             basePath,
		sessionManager:       sessionManager,
		peopleStore:          peopleStore,
		clientStore:          clientStore,
		otpauthStore:         otpauthStore,
		issuer:               issuer,
		passwordResetEnabled: passwordResetEnabled,
		tpl:                  template.Must(template.New("login").Funcs(stringutil.TemplateFuncs).Parse(loginTpl)),
	}
}
