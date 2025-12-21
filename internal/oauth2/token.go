package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/pkce"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
)

type tokenHandler struct {
	tokenService    TokenCreator
	peopleStore     people.Store
	clientStore     clients.Store
	revocationStore revocation.Store
	realms          realms.Realms
	scope           string
}

func (t *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodOptions, http.MethodPost}, true)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var (
		timing                            = httputil.NewTiming()
		clientID, clientSecret, basicAuth = r.BasicAuth()
		grantType                         = strings.ToLower(strings.TrimSpace(r.PostFormValue("grant_type")))
		code                              = strings.TrimSpace(r.PostFormValue("code"))
		refreshToken                      = strings.TrimSpace(r.PostFormValue("refresh_token"))
		codeVerifier                      = strings.TrimSpace(r.PostFormValue("code_verifier"))
		accessToken                       string
		idToken                           string
	)
	// when not using basic auth load client_id and client_secret parameters
	if !basicAuth {
		clientID = strings.TrimSpace(r.PostFormValue("client_id"))
		clientSecret = r.PostFormValue("client_secret")
	}

	// debug output of parameters
	log.Printf("grant_type=%q client_id=%q client_secret=%q code=%q code_verifier=%q refresh_token=%q",
		grantType, clientID, strings.Repeat("*", utf8.RuneCountInString(clientSecret)), code, codeVerifier, refreshToken)

	var client clients.Client
	if clientSecret != "" || grantType == GrantTypeClientCredentials || grantType == GrantTypePassword {
		if c, err := t.clientStore.Authenticate(clientID, clientSecret); err != nil {
			Error(w, ErrorUnauthorizedClient, err.Error(), http.StatusUnauthorized)
			return
		} else {
			client = *c
		}
	} else {
		if c, err := t.clientStore.Lookup(clientID); err != nil {
			Error(w, ErrorUnauthorizedClient, err.Error(), http.StatusUnauthorized)
			return
		} else {
			client = *c
		}
	}

	switch grantType {
	case GrantTypePassword:
		var (
			userID   = strings.TrimSpace(r.PostFormValue("username"))
			password = strings.TrimSpace(r.PostFormValue("password"))
			scope    = strings.TrimSpace(r.PostFormValue("scope"))
		)

		// debug output of parameters
		log.Printf("username=%q password=%q scope=%q", userID, strings.Repeat("*", utf8.RuneCountInString(password)), scope)

		if stringutil.IsAnyEmpty(clientID, clientSecret, userID, password) {
			Error(w, ErrorInvalidRequest, "client_id, client_secret, username and password parameters are required", http.StatusBadRequest)
			return
		}

		var err error
		userID, err = t.peopleStore.Authenticate(userID, password)
		if err != nil {
			Error(w, ErrorInvalidGrant, "invalid username and password combination", http.StatusBadRequest)
			return
		}

		timing.Start("store")
		var person *people.Person
		person, err = t.peopleStore.Lookup(userID)
		if err != nil {
			Error(w, ErrorInternal, "person not found", http.StatusInternalServerError)
			return
		}
		timing.Stop("store")
		var user = User{Person: *person, UserID: userID}
		timing.Start("jwtgen")
		accessToken, _ = t.tokenService.GenerateAccessToken(user, client.Realm, userID, clientID, IntersectScope(t.scope, scope))
		timing.Stop("jwtgen")
	case GrantTypeAuthorizationCode:
		var codeClaims, authCodeErr = t.tokenService.Verify(code, TokenTypeCode)
		if authCodeErr != nil {
			log.Printf("!!! %s", authCodeErr)
			Error(w, ErrorInvalidGrant, authCodeErr.Error(), http.StatusBadRequest)
			return
		}

		// verify parameters and pkce
		if codeClaims.Challenge == "" {
			if stringutil.IsAnyEmpty(clientID, code) {
				Error(w, ErrorInvalidRequest, "client_id and code parameters are required", http.StatusBadRequest)
				return
			}
		} else {
			if stringutil.IsAnyEmpty(clientID, code, codeVerifier) {
				Error(w, ErrorInvalidRequest, "client_id, code and code_verifier parameters are required", http.StatusBadRequest)
				return
			}

			if !pkce.Verify(codeClaims.Challenge, codeVerifier) {
				Error(w, ErrorInvalidGrant, "invalid challenge", http.StatusBadRequest)
				return
			}
		}

		timing.Start("store")
		var person, err = t.peopleStore.Lookup(codeClaims.UserID)
		if err != nil {
			Error(w, ErrorInternal, "person not found", http.StatusInternalServerError)
			return
		}
		timing.Stop("store")
		var user = User{Person: *person, UserID: codeClaims.UserID}
		timing.Start("jwtgen")
		accessToken, _ = t.tokenService.GenerateAccessToken(user, client.Realm, codeClaims.UserID, clientID, codeClaims.Scope)
		if strings.Contains(codeClaims.Scope, "offline_access") {
			refreshToken, _ = t.tokenService.GenerateRefreshToken(client.Realm, codeClaims.UserID, clientID, codeClaims.Scope, codeClaims.Nonce)
		}
		if strings.Contains(codeClaims.Scope, "openid") {
			var hash = sha256.Sum256([]byte(accessToken))
			idToken, _ = t.tokenService.GenerateIDToken(user, client.Realm, clientID, codeClaims.Scope, base64.RawURLEncoding.EncodeToString(hash[:16]), codeClaims.Nonce)
		}
		timing.Stop("jwtgen")
	case GrantTypeRefreshToken:
		if stringutil.IsAnyEmpty(clientID, refreshToken) {
			Error(w, ErrorInvalidRequest, "client_id and refresh_token parameters are required", http.StatusBadRequest)
			return
		}
		var refreshClaims, refreshTokenErr = t.tokenService.Verify(refreshToken, TokenTypeRefreshToken)
		if refreshTokenErr == nil {
			revokedToken, _ := t.revocationStore.Lookup(refreshClaims.TokenID)
			if revokedToken != nil {
				refreshTokenErr = errors.New("refresh token has been revoked")
			}
		}
		if refreshTokenErr != nil {
			log.Printf("!!! %s", refreshTokenErr)
			Error(w, ErrorInvalidGrant, refreshTokenErr.Error(), http.StatusBadRequest)
			return
		}
		timing.Start("store")
		var person, err = t.peopleStore.Lookup(refreshClaims.UserID)
		if err != nil {
			Error(w, ErrorInternal, "person not found", http.StatusInternalServerError)
			return
		}
		timing.Stop("store")
		var user = User{Person: *person, UserID: refreshClaims.UserID}
		timing.Start("jwtgen")
		accessToken, _ = t.tokenService.GenerateAccessToken(user, client.Realm, refreshClaims.UserID, clientID, refreshClaims.Scope)
		if client.EnableRefreshTokenRotation && strings.Contains(refreshClaims.Scope, "offline_access") {
			_ = t.revocationStore.Put(refreshClaims.TokenID, refreshClaims.Expiry.Time())
			refreshToken, _ = t.tokenService.GenerateRefreshToken(client.Realm, refreshClaims.UserID, clientID, refreshClaims.Scope, refreshClaims.Nonce)
		} else {
			refreshToken = ""
		}
		if strings.Contains(refreshClaims.Scope, "openid") {
			var hash = sha256.Sum256([]byte(accessToken))
			idToken, _ = t.tokenService.GenerateIDToken(user, client.Realm, clientID, refreshClaims.Scope, base64.RawURLEncoding.EncodeToString(hash[:16]), refreshClaims.Nonce)
		}
		timing.Stop("jwtgen")
	case GrantTypeClientCredentials:
		var scope = strings.TrimSpace(r.PostFormValue("scope"))
		log.Printf("scope=%q", scope)

		if stringutil.IsAnyEmpty(clientID, clientSecret) {
			Error(w, ErrorInvalidRequest, "client_id and client_secret parameters are required", http.StatusBadRequest)
			return
		}

		timing.Start("jwtgen")
		accessToken, _ = t.tokenService.GenerateAccessToken(User{}, client.Realm, clientID, clientID, IntersectScope(t.scope, scope))
		timing.Stop("jwtgen")
	default:
		Error(w, ErrorUnsupportedGrantType, "only grant types 'authorization_code', 'client_credentials', 'password' and 'refresh_token' are supported", http.StatusBadRequest)
		return
	}

	var bytes, err = json.Marshal(TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    t.realms[client.Realm].AccessTokenTTL,
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})
	if err != nil {
		Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	timing.Report(w)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bytes))) // no "Transfer-Encoding: chunked" please
	w.Write(bytes)
}

func TokenHandler(tokenService TokenCreator, peopleStore people.Store, clientStore clients.Store, revocationStore revocation.Store, realms realms.Realms, scope string) http.Handler {
	return &tokenHandler{
		tokenService:    tokenService,
		peopleStore:     peopleStore,
		clientStore:     clientStore,
		revocationStore: revocationStore,
		realms:          realms,
		scope:           scope,
	}
}
