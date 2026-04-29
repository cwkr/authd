package passwordhash

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUnknownPasswordHashFormat = errors.New("unknown password hash format")
	ErrPasswordDoesNotMatch      = errors.New("password does not match given hash")
)

func GetFormat(hash string) string {
	if strings.HasPrefix(hash, "{") {
		var rbk = strings.Index(hash, "}")
		if rbk != -1 {
			return hash[1:rbk]
		}
	} else if strings.HasPrefix(hash, "$2") {
		return "bcrypt"
	}
	return ""
}

func Check(hash, password string) error {
	if password == "" {
		return ErrPasswordDoesNotMatch
	}
	var format = GetFormat(hash)

	if format == "bcrypt" {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	} else {
		if b, err := base64.StdEncoding.DecodeString(hash[len(format)+2:]); err != nil {
			return err
		} else {
			switch strings.ToLower(format) {
			case "ssha":
				var salt = b[20:]
				var rawHash = b[:20]
				var calcHash = SSHA([]byte(password), salt)[:20]
				if !bytes.Equal(calcHash, rawHash) {
					return ErrPasswordDoesNotMatch
				}
			case "ssha256":
				if !bytes.Equal(SSHA256([]byte(password), b[32:])[:32], b[:32]) {
					return ErrPasswordDoesNotMatch
				}
			case "ssha512":
				if !bytes.Equal(SSHA512([]byte(password), b[64:])[:64], b[:64]) {
					return ErrPasswordDoesNotMatch
				}
			default:
				return ErrUnknownPasswordHashFormat
			}
		}
	}
	return nil
}
