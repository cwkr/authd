package clients

import (
	"log"
	"strings"
)

type Client struct {
	SecretHash                 string   `json:"secret_hash,omitempty"`
	PresetID                   string   `json:"preset,omitempty"`
	DisableImplicit            bool     `json:"disable_implicit,omitempty"`
	EnableRefreshTokenRotation bool     `json:"enable_refresh_token_rotation,omitempty"`
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
