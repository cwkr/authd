package server

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/server/sessions"
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
	basePath       string
	sessionManager sessions.SessionManager
	peopleStore    people.Store
	clientStore    clients.Store
	issuer         string
	realms         realms.Realms
	tpl            *template.Template
}

func (j *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)
	var message string

	var userID, password, clientID string

	clientID = strings.ToLower(r.FormValue("client_id"))
	if clientID == "" {
		htmlutil.Error(w, j.basePath, "client_id parameter is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		userID = strings.TrimSpace(r.PostFormValue("user_id"))
		if userID == "" {
			userID = strings.TrimSpace(r.PostFormValue("username"))
		}
		password = r.PostFormValue("password")
		if stringutil.IsAnyEmpty(userID, password) {
			message = "username and password must not be empty"
		} else {
			var client clients.Client
			if c, err := j.clientStore.Lookup(clientID); err == nil {
				client = *c
			} else {
				htmlutil.Error(w, j.basePath, "invalid_client", http.StatusForbidden)
				return
			}

			if realUserID, err := j.peopleStore.Authenticate(userID, password); err == nil {
				if err := j.sessionManager.SaveSession(r, w, time.Now(), client, realUserID); err != nil {
					htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
					return
				}
				log.Printf("user_id=%s", realUserID)
				httputil.RedirectQuery(w, r, strings.TrimRight(j.issuer, "/")+"/authorize", r.URL.Query())
				return
			} else {
				message = err.Error()
			}
		}
	} else if r.Method == http.MethodGet {
		httputil.NoCache(w)
	}

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var err = j.tpl.ExecuteTemplate(w, "login", map[string]any{
		"base_path":      j.basePath,
		"issuer":         strings.TrimRight(j.issuer, "/"),
		"query":          template.HTML("?" + r.URL.RawQuery),
		"message":        message,
		"user_id":        userID,
		"password_empty": password == "",
	})
	if err != nil {
		htmlutil.Error(w, j.basePath, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(basePath string, sessionManager sessions.SessionManager, peopleStore people.Store, clientStore clients.Store, realms realms.Realms, issuer string) http.Handler {
	return &loginHandler{
		basePath:       basePath,
		sessionManager: sessionManager,
		peopleStore:    peopleStore,
		clientStore:    clientStore,
		realms:         realms,
		issuer:         issuer,
		tpl:            template.Must(template.New("login").Parse(loginTpl)),
	}
}
