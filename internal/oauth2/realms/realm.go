package realms

type Realm struct {
	SigningAlgorithm       string            `json:"signing_algorithm,omitempty"`
	Audiences              []string          `json:"audiences,omitempty"`
	AccessTokenExtraClaims map[string]string `json:"access_token_extra_claims,omitempty"`
	AccessTokenTTL         int               `json:"access_token_ttl"`
	RefreshTokenTTL        int               `json:"refresh_token_ttl"`
	IDTokenTTL             int               `json:"id_token_ttl"`
	IDTokenExtraClaims     map[string]string `json:"id_token_extra_claims,omitempty"`
	SessionName            string            `json:"session_name,omitempty"`
	SessionTTL             int               `json:"session_ttl"`
	Require2FA             bool              `json:"require_2fa"`
}

type Realms map[string]Realm
