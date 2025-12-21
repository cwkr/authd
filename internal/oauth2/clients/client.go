package clients

type Client struct {
	RedirectURIPattern         string `json:"redirect_uri_pattern,omitempty"`
	SecretHash                 string `json:"secret_hash,omitempty"`
	Realm                      string `json:"realm,omitempty"`
	DisableImplicit            bool   `json:"disable_implicit,omitempty"`
	EnableRefreshTokenRotation bool   `json:"enable_refresh_token_rotation,omitempty"`
}
