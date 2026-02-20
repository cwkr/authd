package settings

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/cwkr/authd/keyset"
	"github.com/cwkr/authd/mail"
)

type CustomPeopleAPI struct {
	FilterParam     string            `json:"filter_param"`
	Attributes      map[string]string `json:"attributes"`
	FixedAttributes map[string]string `json:"fixed_attributes"`
}

type Server struct {
	Issuer                    string                            `json:"issuer"`
	Port                      int                               `json:"port"`
	Title                     string                            `json:"title,omitempty"`
	Users                     map[string]people.AuthenticPerson `json:"users,omitempty"`
	Key                       string                            `json:"key"`
	AdditionalKeys            []string                          `json:"additional_keys,omitempty"`
	Clients                   map[string]clients.Client         `json:"clients,omitempty"`
	ClientStore               *clients.StoreSettings            `json:"client_store,omitempty"`
	CustomScope               string                            `json:"custom_scope,omitempty"`
	Defaults                  oauth2.TokenSettings              `json:"defaults,omitempty"`
	CustomAccessTokenClaims   map[string]string                 `json:"custom_access_token_claims,omitempty"`
	CustomIDTokenClaims       map[string]string                 `json:"custom_id_token_claims,omitempty"`
	CookieSecret              string                            `json:"cookie_secret"`
	SessionName               string                            `json:"session_name"`
	SessionLifetime           int                               `json:"session_lifetime"`
	CustomUserinfoClaims      map[string]string                 `json:"custom_userinfo_claims,omitempty"`
	PeopleStore               *people.StoreSettings             `json:"people_store,omitempty"`
	OTPAuthStore              *otpauth.StoreSettings            `json:"otpauth_store,omitempty"`
	DisableAPI                bool                              `json:"disable_api,omitempty"`
	PeopleAPICustomVersions   map[string]CustomPeopleAPI        `json:"people_api_custom_versions,omitempty"`
	PeopleAPIRequireAuthN     bool                              `json:"people_api_require_authn,omitempty"`
	LoginTemplate             string                            `json:"login_template,omitempty"`
	LogoutTemplate            string                            `json:"logout_template,omitempty"`
	Setup2FATemplate          string                            `json:"setup_2fa_template,omitempty"`
	ResetPasswordTemplate     string                            `json:"reset_password_template,omitempty"`
	ChangePasswordTemplate    string                            `json:"change_password_template,omitempty"`
	PasswordResetMailTemplate string                            `json:"password_reset_mail_template,omitempty"`
	RevocationStore           *revocation.StoreSettings         `json:"revocation_store,omitempty"`
	EnableTokenRevocation     bool                              `json:"enable_token_revocation,omitempty"`
	AdditionalKeysLifetime    int                               `json:"additional_keys_lifetime,omitempty"`
	Roles                     oauth2.RoleMappings               `json:"roles,omitempty"`
	AdministratorRole         string                            `json:"administrator_role,omitempty"`
	Mail                      *mail.MailSettings                `json:"mail,omitempty"`
	rsaSigningKey             *rsa.PrivateKey
	rsaSigningKeyID           string
	keySetProvider            keyset.Provider
}

func NewDefault(port int) *Server {
	return &Server{
		Issuer: fmt.Sprintf("http://localhost:%d", port),
		Port:   port,
		Defaults: oauth2.TokenSettings{
			AccessTokenLifetime:  3_600,
			AuthCodeLifetime:     300,
			IDTokenLifetime:      28_800,
			RefreshTokenLifetime: 28_800,
			SigningAlgorithm:     "RS256",
		},
		CookieSecret:           stringutil.RandomAlphanumericString(32),
		SessionName:            "AUTHSESSION",
		SessionLifetime:        28_800,
		AdditionalKeysLifetime: 900,
	}
}

func (s *Server) LoadKeys(dir string) error {
	if strings.HasPrefix(s.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(s.Key))
		if s.rsaSigningKeyID = block.Headers[keyset.HeaderKeyID]; s.rsaSigningKeyID == "" {
			s.rsaSigningKeyID = "sigkey"
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return err
		} else {
			s.rsaSigningKey = key
		}
	} else if strings.HasPrefix(s.Key, "@") {
		var filename = filepath.Join(dir, s.Key[1:])
		pemBytes, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(pemBytes)
		if s.rsaSigningKeyID = block.Headers[keyset.HeaderKeyID]; s.rsaSigningKeyID == "" {
			s.rsaSigningKeyID = strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return err
		} else {
			s.rsaSigningKey = key
		}
	} else {
		return errors.New("missing or malformed signing key")
	}

	var keys = append([]string{s.PublicKeyPEM(true)}, s.AdditionalKeys...)

	s.keySetProvider = keyset.NewProvider(dir, keys, time.Duration(s.AdditionalKeysLifetime)*time.Second)

	return nil
}

func (s *Server) GenerateSigningKey(keySize int, keyID string) error {
	var keyBytes []byte
	var err error
	keyBytes, err = keyset.GeneratePrivateKey(keySize, keyID)
	if err != nil {
		return err
	}
	s.Key = string(keyBytes)
	return nil
}

func (s Server) PrivateKey() *rsa.PrivateKey {
	return s.rsaSigningKey
}

func (s Server) PublicKey() *rsa.PublicKey {
	return &s.rsaSigningKey.PublicKey
}

func (s Server) PublicKeyPEM(headers bool) string {
	var pubASN1, _ = x509.MarshalPKIXPublicKey(s.PublicKey())
	var pemBlock = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}
	if headers {
		pemBlock.Headers = map[string]string{keyset.HeaderKeyID: s.rsaSigningKeyID}
	}
	var pubBytes = pem.EncodeToMemory(&pemBlock)
	return string(pubBytes)
}

func (s Server) KeyID() string {
	return s.rsaSigningKeyID
}

func (s Server) KeySetProvider() keyset.Provider {
	return s.keySetProvider
}
