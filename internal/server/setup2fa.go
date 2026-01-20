package server

import (
	_ "embed"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/server/sessions"
	"github.com/cwkr/authd/internal/stringutil"
)

//go:embed templates/setup2fa.gohtml
var setup2faTpl string

func LoadSetup2FATemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		setup2faTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type setup2FAHandler struct {
	sessionManager sessions.SessionManager
	clientStore    clients.Store
	realms         realms.Realms
	otpauthStore   otpauth.Store
	tpl            *template.Template
	issuer         string
	basePath       string
	version        string
}

func (o *setup2FAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		var (
			algorithm    = strings.TrimSpace(r.FormValue("alg"))
			secret       string
			errorMessage string
			keyWrapper   *otpauth.KeyWrapper
			enabled      bool
			require2FA   = o.realms[strings.ToLower(client.Realm)].Require2FA
		)
		if algorithm == "" {
			algorithm = "sha256"
		}

		keyWrapper, _ = o.otpauthStore.Lookup(uid)
		enabled = keyWrapper != nil

		if r.Method == http.MethodPost {
			var (
				code             = strings.TrimSpace(r.PostFormValue("code"))
				recoveryCode     = strings.TrimSpace(r.PostFormValue("recovery_code"))
				loginQueryBase64 = strings.TrimSpace(r.URL.Query().Get("login_query"))
				redirectURI      = strings.TrimSpace(r.URL.Query().Get("post_setup_redirect_uri"))
			)
			secret = strings.TrimSpace(r.PostFormValue("secret"))

			if secret != "" && code != "" {
				if kw, err := otpauth.NewKeyWrapper(o.issuer, uid, algorithm, secret); err != nil {
					errorMessage = err.Error()
				} else {
					if kw.VerifyCode(code) {
						if err := o.otpauthStore.Put(uid, *kw); err != nil {
							errorMessage = err.Error()
						} else {
							if _, _, verified := o.sessionManager.CheckSession(r, client); !verified {
								if err := o.sessionManager.VerifySession(r, w, client); err != nil {
									htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
									return
								}
							}
							if redirectURI != "" {
								if !strings.HasPrefix(redirectURI, strings.TrimRight(o.issuer, "/")) {
									if client.RedirectURIPattern != "" {
										if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
											htmlutil.Error(w, o.basePath, "post_setup_redirect_uri does not match Clients redirect URI pattern", http.StatusBadRequest)
											return
										}
									}
								}
								http.Redirect(w, r, redirectURI, http.StatusFound)
								return
							} else if loginQueryBase64 != "" {
								if loginQuery, err := base64.RawURLEncoding.DecodeString(loginQueryBase64); err == nil {
									var query, _ = url.ParseQuery(string(loginQuery))
									httputil.RedirectQuery(w, r, strings.TrimRight(o.issuer, "/")+"/login", query)
									return
								}
							}
							httputil.RedirectQuery(w, r, strings.TrimRight(o.issuer, "/")+"/setup-2fa", r.URL.Query())
							return
						}
					} else {
						errorMessage = "invalid code"
					}
				}
			} else if enabled && recoveryCode != "" {
				if strings.Contains(recoveryCode, "00") {
					if err := o.otpauthStore.Delete(uid); err != nil {
						htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
						return
					}
					if _, _, verified := o.sessionManager.CheckSession(r, client); !require2FA && !verified {
						if err := o.sessionManager.VerifySession(r, w, client); err != nil {
							htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
							return
						}
					}
					if redirectURI != "" {
						if !strings.HasPrefix(redirectURI, strings.TrimRight(o.issuer, "/")) {
							if client.RedirectURIPattern != "" {
								if !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
									htmlutil.Error(w, o.basePath, "post_setup_redirect_uri does not match Clients redirect URI pattern", http.StatusBadRequest)
									return
								}
							}
						}
						http.Redirect(w, r, redirectURI, http.StatusFound)
						return
					} else if loginQueryBase64 != "" {
						if loginQuery, err := base64.RawURLEncoding.DecodeString(loginQueryBase64); err == nil {
							var query, _ = url.ParseQuery(string(loginQuery))
							httputil.RedirectQuery(w, r, strings.TrimRight(o.issuer, "/")+"/login", query)
							return
						}
					}
					httputil.RedirectQuery(w, r, strings.TrimRight(o.issuer, "/")+"/setup-2fa", r.URL.Query())
					return
				} else {
					errorMessage = "invalid recovery code"
				}
			}
		} else if r.Method == http.MethodGet {
			httputil.NoCache(w)
		}

		var imageURL string

		if keyWrapper == nil {
			if kw, err := otpauth.NewKeyWrapper(o.issuer, uid, algorithm, secret); err != nil {
				htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
				return
			} else {
				keyWrapper = kw
			}
		}
		if dataURL, err := keyWrapper.PNG(); err != nil {
			htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
			return
		} else {
			imageURL = dataURL
		}

		if err := o.tpl.ExecuteTemplate(w, "2fa", map[string]any{
			"base_path":              o.basePath,
			"qrcode":                 template.URL(imageURL),
			"require_2fa":            require2FA,
			"user_2fa_enabled":       enabled,
			"query":                  template.HTML("?" + r.URL.RawQuery),
			"version":                o.version,
			"algorithm":              algorithm,
			"readonly_otpauth_store": o.otpauthStore.ReadOnly(),
			"secret":                 keyWrapper.Secret(),
			"error_message":          errorMessage,
		}); err != nil {
			htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		htmlutil.Error(w, o.basePath, "not logged in", http.StatusUnauthorized)
		return
	}
}

func Setup2FAHandler(sessionManager sessions.SessionManager, clientStore clients.Store, realms realms.Realms, otpauthStore otpauth.Store, basePath, version, issuer string) http.Handler {
	return &setup2FAHandler{
		sessionManager: sessionManager,
		clientStore:    clientStore,
		realms:         realms,
		otpauthStore:   otpauthStore,
		tpl:            template.Must(template.New("2fa").Parse(setup2faTpl)),
		basePath:       basePath,
		version:        version,
		issuer:         issuer,
	}
}
