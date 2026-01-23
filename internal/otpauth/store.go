package otpauth

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var ErrNotFound = errors.New("no otp key found")

type KeyWrapper struct {
	key *otp.Key
}

func NewKeyWrapper(issuer, userID, algorithm, secret string, digits int) (*KeyWrapper, error) {
	var otpID string
	if issuerURL, err := url.Parse(issuer); err != nil {
		return nil, err
	} else {
		otpID = strings.ReplaceAll(issuerURL.Hostname(), ":", "_")
		if issuerURL.Path != "" && issuerURL.Path != "/" {
			otpID += issuerURL.Path
		}
	}
	var opts = totp.GenerateOpts{
		Issuer:      otpID,
		AccountName: userID,
		Digits:      otp.Digits(digits),
	}
	if strings.EqualFold(algorithm, "sha256") {
		opts.Algorithm = otp.AlgorithmSHA256
	} else if strings.EqualFold(algorithm, "sha512") {
		opts.Algorithm = otp.AlgorithmSHA512
	} else if !strings.EqualFold(algorithm, "sha1") {
		return nil, fmt.Errorf("%s is not supported: %w", algorithm, ErrUnsupportedAlgorithm)
	}
	if secret != "" {
		var sb, _ = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		opts.Secret = sb
	}
	log.Printf("Generating TOTP Key for %s@%s using %s with %d digits", userID, otpID, opts.Algorithm, digits)
	if totpKey, err := totp.Generate(opts); err != nil {
		return nil, err
	} else {
		return &KeyWrapper{key: totpKey}, nil
	}
}

func (k KeyWrapper) VerifyCode(code string) bool {
	if valid, err := totp.ValidateCustom(code, k.key.Secret(), time.Now(), totp.ValidateOpts{
		Period:    uint(k.key.Period()),
		Digits:    k.key.Digits(),
		Algorithm: k.key.Algorithm(),
	}); err != nil {
		log.Printf("!!! %s", err)
		return false
	} else {
		return valid
	}
}

func (k KeyWrapper) PNG() (string, error) {
	var img, err = k.key.Image(512, 512)
	if err != nil {
		return "", err
	} else {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return "", err
		}
		return "data:image/png;base64," + base64.RawStdEncoding.EncodeToString(buf.Bytes()), nil
	}
}

func (k KeyWrapper) URI() string {
	return k.key.URL()
}

func (k KeyWrapper) Secret() string {
	return k.key.Secret()
}

func (k KeyWrapper) Algorithm() string {
	return k.key.Algorithm().String()
}

func (k KeyWrapper) Digits() int {
	return int(k.key.Digits())
}

type Store interface {
	Lookup(userID string) (*KeyWrapper, error)
	Put(userID string, keyWrapper KeyWrapper) (string, error)
	VerifyRecoveryCode(userID, recoveryCode string) bool
	Delete(userID string) error
	Ping() error
	ReadOnly() bool
}
