package oauth2

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/server/sessions"
	"github.com/cwkr/authd/internal/stringutil"
)

func IntersectScope(availableScope, requestedScope string) string {
	var results []string
	var as, rs = strings.Fields(availableScope), strings.Fields(requestedScope)
	for _, aw := range as {
		for _, rw := range rs {
			if strings.EqualFold(aw, rw) {
				results = append(results, aw)
			}
		}
	}
	return strings.Join(results, " ")
}

type authorizeHandler struct {
	basePath       string
	tokenService   TokenCreator
	sessionManager sessions.SessionManager
	peopleStore    people.Store
	clientStore    clients.Store
	realms         realms.Realms
	scope          string
}

func (a *authorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		timing          = httputil.NewTiming()
		responseType    = strings.ToLower(strings.TrimSpace(r.FormValue("response_type")))
		clientID        = strings.TrimSpace(r.FormValue("client_id"))
		redirectURI     = strings.TrimSpace(r.FormValue("redirect_uri"))
		state           = strings.TrimSpace(r.FormValue("state"))
		scope           = strings.TrimSpace(r.FormValue("scope"))
		challenge       = strings.TrimSpace(r.FormValue("code_challenge"))
		challengeMethod = strings.TrimSpace(r.FormValue("code_challenge_method"))
		nonce           = strings.TrimSpace(r.FormValue("nonce"))
		user            User
	)

	if stringutil.IsAnyEmpty(responseType, clientID, redirectURI) {
		htmlutil.Error(w, a.basePath, "client_id, redirect_uri and response_type parameters are required", http.StatusBadRequest)
		return
	}

	var client clients.Client
	if c, err := a.clientStore.Lookup(clientID); err != nil {
		Error(w, ErrorUnauthorizedClient, ErrorInvalidClient, http.StatusForbidden)
		return
	} else {
		if responseType == ResponseTypeToken && client.DisableImplicit {
			htmlutil.Error(w, a.basePath, ErrorUnsupportedGrantType, http.StatusBadRequest)
			return
		}
		client = *c
	}

	if client.RedirectURIPattern != "" && !regexp.MustCompile(client.RedirectURIPattern).MatchString(redirectURI) {
		htmlutil.Error(w, a.basePath, ErrorRedirectURIMismatch, http.StatusBadRequest)
		return
	}

	if uid, active, verified := a.sessionManager.CheckSession(r, client); active && verified {
		timing.Start("store")
		if person, err := a.peopleStore.Lookup(uid); err == nil {
			user = User{UserID: uid, Person: *person}
		} else {
			htmlutil.Error(w, a.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("store")
	} else {
		var query = make(url.Values)
		query.Set("client_id", clientID)
		query.Set("authorize_query", base64.RawURLEncoding.EncodeToString([]byte(r.URL.RawQuery)))
		httputil.RedirectQuery(w, r, strings.TrimRight(a.tokenService.Issuer(), "/")+"/login", query)
		return
	}

	var redirectParams = url.Values{}
	redirectParams.Set("state", state)

	switch responseType {
	case ResponseTypeToken:
		timing.Start("jwtgen")
		var accessToken, err = a.tokenService.GenerateAccessToken(user, client.Realm, user.UserID, clientID, IntersectScope(a.scope, scope))
		if err != nil {
			htmlutil.Error(w, a.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("jwtgen")
		redirectParams.Set("access_token", accessToken)
		redirectParams.Set("token_type", "Bearer")
		redirectParams.Set("expires_in", fmt.Sprint(a.realms[strings.ToLower(client.Realm)].AccessTokenTTL))

		httputil.NoCache(w)
		timing.Report(w)
		httputil.RedirectFragment(w, r, redirectURI, redirectParams)
	case ResponseTypeCode:
		if challengeMethod != "" {
			if challenge == "" || challengeMethod != "S256" {
				htmlutil.Error(w, a.basePath, "code_challenge and code_challenge_method=S256 required for PKCE", http.StatusInternalServerError)
				return
			}
		}

		timing.Start("jwtgen")
		var authCode, err = a.tokenService.GenerateAuthCode(client.Realm, user.UserID, clientID, IntersectScope(a.scope, scope), challenge, nonce)
		if err != nil {
			htmlutil.Error(w, a.basePath, err.Error(), http.StatusInternalServerError)
			return
		}
		timing.Stop("jwtgen")
		redirectParams.Set("code", authCode)

		httputil.NoCache(w)
		timing.Report(w)
		httputil.RedirectQuery(w, r, redirectURI, redirectParams)
	default:
		htmlutil.Error(w, a.basePath, ErrorUnsupportedGrantType, http.StatusBadRequest)
	}
}

func AuthorizeHandler(basePath string, tokenService TokenCreator, sessionManager sessions.SessionManager, peopleStore people.Store, clientStore clients.Store, realms realms.Realms, scope string) http.Handler {
	return &authorizeHandler{
		basePath:       basePath,
		tokenService:   tokenService,
		sessionManager: sessionManager,
		peopleStore:    peopleStore,
		clientStore:    clientStore,
		realms:         realms,
		scope:          scope,
	}
}
