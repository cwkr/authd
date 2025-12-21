package otpauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"image/png"
	"log"
	"time"
)

var ErrNotFound = errors.New("no otp key found")

type KeyWrapper struct {
	key *otp.Key
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
	var img, err = k.key.Image(400, 400)
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

type Store interface {
	Lookup(userID string) (*KeyWrapper, error)
	Ping() error
	ReadOnly() bool
}
