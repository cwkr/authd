package clients

import (
	"log"
	"strings"
)

type Client struct {
	AccessTokenLifetime        int      `json:"access_token_lifetime,omitempty"`
	AuthCodeLifetime           int      `json:"auth_code_lifetime,omitempty"`
	IDTokenLifetime            int      `json:"id_token_lifetime,omitempty"`
	RefreshTokenLifetime       int      `json:"refresh_token_lifetime,omitempty"`
	SigningAlgorithm           string   `json:"signing_algorithm,omitempty"`
	SecretHash                 string   `json:"secret_hash,omitempty"`
	DisableImplicit            bool     `json:"disable_implicit,omitempty"`
	EnableRefreshTokenRotation bool     `json:"enable_refresh_token_rotation,omitempty"`
	Require2FA                 bool     `json:"require_2fa,omitempty"`
	RedirectURIs               []string `json:"redirect_uris,omitempty"`
	Audience                   []string `json:"audience,omitempty"`
}

func (c Client) MatchesRedirectURI(requestedURI string) bool {
	for _, redirectURI := range c.RedirectURIs {
		var match bool
		if strings.HasSuffix(redirectURI, "*") {
			match = strings.HasPrefix(requestedURI, strings.TrimSuffix(redirectURI, "*"))
		} else {
			match = strings.TrimSuffix(requestedURI, "/") == strings.TrimSuffix(redirectURI, "/")
		}
		if match {
			log.Printf("RequestedURI: %s ~= RedirectURI: %s", requestedURI, redirectURI)
			return true
		}
	}
	return false
}
