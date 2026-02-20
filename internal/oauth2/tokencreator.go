package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/numutil"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/oklog/ulid/v2"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypePassword          = "password"

	TokenTypeCode          = "code"
	TokenTypeRefresh       = "refresh"
	TokenTypePasswordReset = "passwd"
	ResponseTypeCode       = "code"
	ResponseTypeToken      = "token"
)

var (
	ErrInvalidTokenType     = errors.New("invalid token type (typ)")
	ErrUnsupportedAlgorithm = errors.New("unsupported token signing algorithm")
)

type User struct {
	people.Person
	UserID string `json:"user_id"`
}

type VerifiedClaims struct {
	UserID    string           `json:"uid"`
	ClientID  string           `json:"cid"`
	TokenID   string           `json:"jti"`
	Type      string           `json:"typ"`
	Scope     string           `json:"scope"`
	Challenge string           `json:"challenge"`
	Nonce     string           `json:"nonce"`
	Expiry    *jwt.NumericDate `json:"exp"`
}

func NewTokenID(timestamp time.Time) string {
	id, _ := ulid.New(ulid.Timestamp(timestamp), rand.Reader)
	return id.String()
}

type TokenSettings struct {
	AccessTokenLifetime  int    `json:"access_token_lifetime,omitempty"`
	AuthCodeLifetime     int    `json:"auth_code_lifetime,omitempty"`
	IDTokenLifetime      int    `json:"id_token_lifetime,omitempty"`
	RefreshTokenLifetime int    `json:"refresh_token_lifetime,omitempty"`
	SigningAlgorithm     string `json:"signing_algorithm,omitempty"`
}

type TokenCreator interface {
	GenerateAccessToken(user User, client clients.Client, subject, clientID, scope string) (string, int, error)
	GenerateIDToken(user User, client clients.Client, clientID, scope, accessTokenHash, nonce string) (string, error)
	GenerateAuthCode(client clients.Client, userID, clientID, scope, challenge, nonce string) (string, error)
	GeneratePasswordResetToken(userID string) (string, error)
	GenerateRefreshToken(client clients.Client, userID, clientID, scope, nonce string) (string, error)
	Verify(rawToken, tokenType string) (*VerifiedClaims, error)
	Issuer() string
}

type tokenCreator struct {
	privateKey              *rsa.PrivateKey
	signers                 map[string]jose.Signer
	issuer                  string
	scope                   string
	defaults                TokenSettings
	customAccessTokenClaims map[string]string
	customIDTokenClaims     map[string]string
	roleMappings            RoleMappings
}

func (t tokenCreator) SignClaims(algorithm string, claims map[string]any) (string, error) {
	if !slices.Contains(OIDCSupportedAlgorithms, algorithm) {
		return "", ErrUnsupportedAlgorithm
	}
	return jwt.Signed(t.signers[algorithm]).Claims(claims).CompactSerialize()
}

func (t tokenCreator) Issuer() string {
	return t.issuer
}

func (t tokenCreator) algorithm(client clients.Client) string {
	return strings.ToUpper(stringutil.FirstNonEmpty(client.SigningAlgorithm, t.defaults.SigningAlgorithm))
}

func (t tokenCreator) GenerateAccessToken(user User, client clients.Client, subject, clientID, scope string) (string, int, error) {
	var (
		now      = time.Now()
		lifetime = numutil.FirstAboveZero(client.AccessTokenLifetime, t.defaults.AccessTokenLifetime, 3600)
	)

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       subject,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + int64(lifetime),
		ClaimTokenID:       NewTokenID(now),
	}

	var audExpandFn = func(name string) string {
		switch strings.ToLower(name) {
		case "issuer":
			return t.issuer
		case "client_id":
			return clientID
		}
		return ""
	}

	if len(client.Audience) > 0 {
		if len(client.Audience) == 1 {
			if aud := strings.TrimSpace(os.Expand(client.Audience[0], audExpandFn)); aud != "" {
				claims[ClaimAudience] = aud
			}
		} else {
			var audiences []string
			for _, audTmpl := range client.Audience {
				if aud := strings.TrimSpace(os.Expand(audTmpl, audExpandFn)); aud != "" {
					audiences = append(audiences, aud)
				}
			}
			claims[ClaimAudience] = audiences
		}
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}

	AddExtraClaims(claims, t.customAccessTokenClaims, user, subject, clientID, t.roleMappings)

	if token, err := t.SignClaims(t.algorithm(client), claims); err == nil {
		return token, lifetime, nil
	} else {
		return "", 0, err
	}
}

func (t tokenCreator) GenerateIDToken(user User, client clients.Client, clientID, scope, accessTokenHash, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:          t.issuer,
		ClaimSubject:         user.UserID,
		ClaimIssuedAtTime:    now.Unix(),
		ClaimNotBeforeTime:   now.Unix(),
		ClaimExpiryTime:      now.Unix() + int64(numutil.FirstAboveZero(client.IDTokenLifetime, t.defaults.IDTokenLifetime, 3600)),
		ClaimAudience:        clientID,
		ClaimAccessTokenHash: accessTokenHash,
		ClaimNonce:           nonce,
		ClaimTokenID:         NewTokenID(now),
	}

	if strings.Contains(scope, "profile") {
		AddProfileClaims(claims, user)
	}
	if strings.Contains(scope, "email") {
		AddEmailClaims(claims, user)
	}
	if strings.Contains(scope, "phone") {
		AddPhoneClaims(claims, user)
	}
	if strings.Contains(scope, "address") {
		AddAddressClaims(claims, user)
	}
	AddExtraClaims(claims, t.customIDTokenClaims, user, user.UserID, clientID, t.roleMappings)

	return t.SignClaims(t.algorithm(client), claims)
}

func (t tokenCreator) GenerateAuthCode(client clients.Client, userID, clientID, scope, challenge, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimType:          TokenTypeCode,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + int64(numutil.FirstAboveZero(client.AuthCodeLifetime, t.defaults.AuthCodeLifetime, 300)),
	}

	if scope != "" {
		claims[ClaimScope] = IntersectScope(t.scope, scope)
	}
	if challenge != "" {
		claims["challenge"] = challenge
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return t.SignClaims(t.algorithm(client), claims)
}

func (t tokenCreator) GeneratePasswordResetToken(userID string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimType:          TokenTypePasswordReset,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + 1_800,
		ClaimTokenID:       NewTokenID(now),
	}

	return t.SignClaims(strings.ToUpper(t.defaults.SigningAlgorithm), claims)
}

func (t tokenCreator) GenerateRefreshToken(client clients.Client, userID, clientID, scope, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimType:          TokenTypeRefresh,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + int64(numutil.FirstAboveZero(client.RefreshTokenLifetime, t.defaults.RefreshTokenLifetime, 3600)),
		ClaimTokenID:       NewTokenID(now),
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return t.SignClaims(t.algorithm(client), claims)
}

func (t tokenCreator) Verify(rawToken, tokenType string) (*VerifiedClaims, error) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		return nil, err
	}
	var claims = jwt.Claims{}
	var verifiedClaims = VerifiedClaims{}
	if err := token.Claims(&t.privateKey.PublicKey, &claims, &verifiedClaims); err != nil {
		return nil, err
	}
	if tokenType != "" && verifiedClaims.Type != tokenType {
		return nil, ErrInvalidTokenType
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer: t.issuer,
		Time:   time.Now(),
	}, 0)
	if err != nil {
		return nil, err
	} else {
		return &verifiedClaims, nil
	}
}

func NewTokenCreator(privateKey *rsa.PrivateKey, keyID, issuer, scope string,
	defaults TokenSettings, customAccessTokenClaims map[string]string, customIDTokenClaims map[string]string,
	roleMappings RoleMappings) (TokenCreator, error) {

	var signers = make(map[string]jose.Signer)

	for _, algorithm := range OIDCSupportedAlgorithms {
		if signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(strings.ToUpper(algorithm)), Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID)); err != nil {
			return nil, err
		} else {
			signers[algorithm] = signer
		}
	}
	return &tokenCreator{
		privateKey:              privateKey,
		signers:                 signers,
		issuer:                  issuer,
		scope:                   scope,
		defaults:                defaults,
		customAccessTokenClaims: customAccessTokenClaims,
		customIDTokenClaims:     customIDTokenClaims,
		roleMappings:            roleMappings,
	}, nil
}
