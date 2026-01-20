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
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/cwkr/authd/keyset"
)

type CustomPeopleAPI struct {
	FilterParam     string            `json:"filter_param"`
	Attributes      map[string]string `json:"attributes"`
	FixedAttributes map[string]string `json:"fixed_attributes"`
}

type Server struct {
	Issuer                  string                            `json:"issuer"`
	Port                    int                               `json:"port"`
	Title                   string                            `json:"title,omitempty"`
	Users                   map[string]people.AuthenticPerson `json:"users,omitempty"`
	Key                     string                            `json:"key"`
	AdditionalKeys          []string                          `json:"additional_keys,omitempty"`
	Clients                 map[string]clients.Client         `json:"clients,omitempty"`
	ClientStore             *clients.StoreSettings            `json:"client_store,omitempty"`
	ExtraScope              string                            `json:"extra_scope,omitempty"`
	Realms                  realms.Realms                     `json:"realms,omitempty"`
	CookieSecret            string                            `json:"cookie_secret"`
	UserinfoExtraClaims     map[string]string                 `json:"userinfo_extra_claims,omitempty"`
	PeopleStore             *people.StoreSettings             `json:"people_store,omitempty"`
	OtpauthStore            *otpauth.StoreSettings            `json:"otpauth_store,omitempty"`
	DisableAPI              bool                              `json:"disable_api,omitempty"`
	PeopleAPICustomVersions map[string]CustomPeopleAPI        `json:"people_api_custom_versions,omitempty"`
	PeopleAPIRequireAuthN   bool                              `json:"people_api_require_authn,omitempty"`
	LoginTemplate           string                            `json:"login_template,omitempty"`
	LogoutTemplate          string                            `json:"logout_template,omitempty"`
	Setup2FATemplate        string                            `json:"setup_2fa_template,omitempty"`
	RevocationStore         *revocation.StoreSettings         `json:"revocation_store,omitempty"`
	EnableTokenRevocation   bool                              `json:"enable_token_revocation,omitempty"`
	KeysTTL                 int                               `json:"keys_ttl,omitempty"`
	Roles                   oauth2.RoleMappings               `json:"roles,omitempty"`
	AdministratorRole       string                            `json:"administrator_role,omitempty"`
	rsaSigningKey           *rsa.PrivateKey
	rsaSigningKeyID         string
	keySetProvider          keyset.Provider
}

func NewDefault(port int) *Server {
	return &Server{
		Issuer: fmt.Sprintf("http://localhost:%d", port),
		Port:   port,
		Realms: map[string]realms.Realm{
			"": {
				SigningAlgorithm: "RS256",
				AccessTokenTTL:   3_600,
				RefreshTokenTTL:  28_800,
				IDTokenTTL:       28_800,
				SessionName:      "_auth",
				SessionTTL:       28_800,
			},
		},
		CookieSecret: stringutil.RandomAlphanumericString(32),
		KeysTTL:      900,
	}
}

func (s *Server) LoadKeys(dir string) error {
	var err error

	if strings.HasPrefix(s.Key, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode([]byte(s.Key))
		if s.rsaSigningKeyID = block.Headers[keyset.HeaderKeyID]; s.rsaSigningKeyID == "" {
			s.rsaSigningKeyID = "sigkey"
		}
		s.rsaSigningKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
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
		s.rsaSigningKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	} else {
		return errors.New("missing or malformed signing key")
	}

	var keys = append([]string{s.PublicKeyPEM()}, s.AdditionalKeys...)

	s.keySetProvider = keyset.NewProvider(dir, keys, time.Duration(s.KeysTTL)*time.Second)
	return err
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

func (s Server) PublicKeyPEM() string {
	var pubASN1, _ = x509.MarshalPKIXPublicKey(s.PublicKey())

	var pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Bytes:   pubASN1,
		Headers: map[string]string{keyset.HeaderKeyID: s.rsaSigningKeyID},
	})
	return string(pubBytes)
}

func (s Server) KeyID() string {
	return s.rsaSigningKeyID
}

func (s Server) KeySetProvider() keyset.Provider {
	return s.keySetProvider
}
