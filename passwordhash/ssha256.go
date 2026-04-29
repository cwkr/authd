package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func SSHA256(password, salt []byte) []byte {
	var passwordAndSalt = make([]byte, len(password), len(password)+len(salt))
	copy(passwordAndSalt, password)
	passwordAndSalt = append(passwordAndSalt, salt...)
	var hash = sha256.Sum256(passwordAndSalt)
	return append(hash[:], salt...)
}

func SSHA256String(password string) string {
	var salt = make([]byte, 16)
	rand.Read(salt)
	var hashBytes = SSHA256([]byte(password), salt)
	return "{SSHA256}" + base64.StdEncoding.EncodeToString(hashBytes)
}
