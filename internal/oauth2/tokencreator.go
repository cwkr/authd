package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/oauth2/presets"
	"github.com/cwkr/authd/internal/people"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/oklog/ulid/v2"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypePassword          = "password"

	TokenTypeCode         = "code"
	TokenTypeRefreshToken = "refresh_token"
	ResponseTypeCode      = "code"
	ResponseTypeToken     = "token"
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
	UserID    string           `json:"user_id"`
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

type TokenCreator interface {
	GenerateAccessToken(user User, algorithm, subject, clientID, scope string) (string, error)
	GenerateIDToken(user User, algorithm, clientID, scope, accessTokenHash, nonce string) (string, error)
	GenerateAuthCode(algorithm, userID, clientID, scope, challenge, nonce string) (string, error)
	GenerateRefreshToken(algorithm, userID, clientID, scope, nonce string) (string, error)
	Verify(rawToken, tokenType string) (*VerifiedClaims, error)
	Issuer() string
}

type tokenCreator struct {
	privateKey   *rsa.PrivateKey
	signers      map[string]jose.Signer
	issuer       string
	scope        string
	presets      presets.Presets
	roleMappings RoleMappings
}

func (t tokenCreator) SignClaims(presetID string, claims map[string]any) (string, error) {
	var algorithm = strings.ToUpper(t.presets[strings.ToLower(presetID)].SigningAlgorithm)
	if !slices.Contains(OIDCSupportedAlgorithms, algorithm) {
		return "", ErrUnsupportedAlgorithm
	}
	return jwt.Signed(t.signers[algorithm]).Claims(claims).CompactSerialize()
}

func (t tokenCreator) Issuer() string {
	return t.issuer
}

func (t tokenCreator) GenerateAccessToken(user User, presetID, subject, clientID, scope string) (string, error) {
	var (
		now    = time.Now()
		preset = t.presets[strings.ToLower(presetID)]
	)

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       subject,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + int64(preset.AccessTokenTTL),
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

	if len(preset.Audiences) > 0 {
		if len(preset.Audiences) == 1 {
			if aud := strings.TrimSpace(os.Expand(preset.Audiences[0], audExpandFn)); aud != "" {
				claims[ClaimAudience] = aud
			}
		} else {
			var audiences []string
			for _, audTmpl := range preset.Audiences {
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

	AddExtraClaims(claims, preset.AccessTokenExtraClaims, user, subject, clientID, t.roleMappings)

	return t.SignClaims(presetID, claims)
}

func (t tokenCreator) GenerateIDToken(user User, presetID, clientID, scope, accessTokenHash, nonce string) (string, error) {
	var (
		now    = time.Now()
		preset = t.presets[strings.ToLower(presetID)]
	)

	var claims = map[string]any{
		ClaimIssuer:          t.issuer,
		ClaimSubject:         user.UserID,
		ClaimIssuedAtTime:    now.Unix(),
		ClaimNotBeforeTime:   now.Unix(),
		ClaimExpiryTime:      now.Unix() + int64(preset.IDTokenTTL),
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
	AddExtraClaims(claims, preset.IDTokenExtraClaims, user, user.UserID, clientID, t.roleMappings)

	return t.SignClaims(presetID, claims)
}

func (t tokenCreator) GenerateAuthCode(presetID, userID, clientID, scope, challenge, nonce string) (string, error) {
	var now = time.Now()

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       NewTokenID(now),
		ClaimType:          TokenTypeCode,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + 300,
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

	return t.SignClaims(presetID, claims)
}

func (t tokenCreator) GenerateRefreshToken(presetID, userID, clientID, scope, nonce string) (string, error) {
	var now = time.Now()
	var tokenID = NewTokenID(now)

	var claims = map[string]any{
		ClaimIssuer:        t.issuer,
		ClaimSubject:       tokenID,
		ClaimType:          TokenTypeRefreshToken,
		ClaimClientID:      clientID,
		ClaimUserID:        userID,
		ClaimIssuedAtTime:  now.Unix(),
		ClaimNotBeforeTime: now.Unix(),
		ClaimExpiryTime:    now.Unix() + int64(t.presets[strings.ToLower(presetID)].RefreshTokenTTL),
		ClaimTokenID:       tokenID,
	}

	if scope != "" {
		claims[ClaimScope] = scope
	}
	if nonce != "" {
		claims[ClaimNonce] = nonce
	}

	return t.SignClaims(presetID, claims)
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

func NewTokenCreator(privateKey *rsa.PrivateKey, keyID, issuer, scope string, presets presets.Presets, roleMappings RoleMappings) (TokenCreator, error) {

	var signers = make(map[string]jose.Signer)

	for _, algorithm := range OIDCSupportedAlgorithms {
		if signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(strings.ToUpper(algorithm)), Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID)); err != nil {
			return nil, err
		} else {
			signers[algorithm] = signer
		}
	}
	return &tokenCreator{
		privateKey:   privateKey,
		signers:      signers,
		issuer:       issuer,
		scope:        scope,
		presets:      presets,
		roleMappings: roleMappings,
	}, nil
}
