package oauth2

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/go-jose/go-jose/v3"
)

const OIDCDefaultScope = "openid profile email phone address offline_access"

var OIDCSupportedAlgorithms = []string{
	string(jose.PS256),
	string(jose.PS384),
	string(jose.PS512),
	string(jose.RS256),
	string(jose.RS384),
	string(jose.RS512),
}

type DiscoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
}

type discoveryDocumentHandler struct {
	issuer                   string
	scope                    string
	tokenRevocationSupported bool
}

func (d *discoveryDocumentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, false)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var baseURL = strings.TrimRight(d.issuer, "/")
	var discoveryDocument = DiscoveryDocument{
		Issuer:                 d.issuer,
		AuthorizationEndpoint:  baseURL + "/authorize",
		JwksURI:                baseURL + "/jwks",
		ResponseTypesSupported: []string{"code", "token"},
		GrantTypesSupported: []string{
			"authorization_code",
			"client_credentials",
			"implicit",
			"refresh_token",
			"password",
		},
		TokenEndpoint:                              baseURL + "/token",
		UserinfoEndpoint:                           baseURL + "/userinfo",
		EndSessionEndpoint:                         baseURL + "/logout",
		ScopesSupported:                            strings.Fields(d.scope),
		TokenEndpointAuthMethodsSupported:          []string{"client_secret_basic", "client_secret_post"},
		TokenEndpointAuthSigningAlgValuesSupported: OIDCSupportedAlgorithms,
		CodeChallengeMethodsSupported:              []string{"S256"},
		IDTokenSigningAlgValuesSupported:           OIDCSupportedAlgorithms,
	}
	if d.tokenRevocationSupported {
		discoveryDocument.RevocationEndpoint = baseURL + "/revoke"
		discoveryDocument.RevocationEndpointAuthMethodsSupported = []string{"client_secret_basic", "client_secret_post"}
	}
	if bytes, err := json.Marshal(discoveryDocument); err != nil {
		Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	}
}

func DiscoveryDocumentHandler(issuer, scope string, tokenRevocationSupported bool) http.Handler {
	return &discoveryDocumentHandler{
		issuer:                   issuer,
		scope:                    scope,
		tokenRevocationSupported: tokenRevocationSupported,
	}
}
