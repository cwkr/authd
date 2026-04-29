package passwordhash

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func New(format, password string, cost int) (string, error) {
	if strings.EqualFold(format, "SSHA") {
		return SSHAString(password), nil
	} else if strings.EqualFold(format, "SSHA256") {
		return SSHA256String(password), nil
	} else if strings.EqualFold(format, "SSHA512") {
		return SSHA512String(password), nil
	} else if strings.EqualFold(format, "bcrypt") {
		if hash, err := bcrypt.GenerateFromPassword([]byte(password), cost); err != nil {
			return "", err
		} else {
			return string(hash), nil
		}
	}
	return "", ErrUnknownPasswordHashFormat
}
