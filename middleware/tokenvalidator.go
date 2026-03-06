package middleware

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/maputil"
	"github.com/cwkr/authd/keyset"
	"github.com/go-jose/go-jose/v3/jwt"
)

var (
	ErrMissingKid          = errors.New("missing key id")
	ErrMatchingKeyNotFound = errors.New("matching key not found")
)

type AccessTokenValidator interface {
	Validate(rawToken string, audiences ...string) (string, error)
}

type accessTokenValidator struct {
	keySetProvider keyset.Provider
}

func NewAccessTokenValidator(keySetProvider keyset.Provider) AccessTokenValidator {
	return &accessTokenValidator{keySetProvider}
}

func (t accessTokenValidator) Validate(rawToken string, audiences ...string) (string, error) {
	var publicKeys map[string]any
	if pk, err := t.keySetProvider.Get(); err != nil {
		return "", err
	} else {
		publicKeys = maputil.LowerKeys(pk)
	}
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		slog.Error(err.Error())
		return "", err
	}
	if len(token.Headers) == 0 || token.Headers[0].KeyID == "" {
		return "", ErrMissingKid
	}
	var publicKey, found = publicKeys[strings.ToLower(token.Headers[0].KeyID)]
	if !found {
		return "", ErrMatchingKeyNotFound
	}
	var claims = jwt.Claims{}
	if err := token.Claims(publicKey, &claims); err != nil {
		slog.Error(err.Error())
		return "", err
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Time:     time.Now(),
		Audience: audiences,
	}, 0)
	if err != nil {
		slog.Error(err.Error())
		return "", err
	} else {
		return claims.Subject, nil
	}
}
