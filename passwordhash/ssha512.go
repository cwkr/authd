package passwordhash

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
)

func SSHA512(password, salt []byte) []byte {
	var passwordAndSalt = make([]byte, len(password), len(password)+len(salt))
	copy(passwordAndSalt, password)
	passwordAndSalt = append(passwordAndSalt, salt...)
	var hash = sha512.Sum512(passwordAndSalt)
	return append(hash[:], salt...)
}

func SSHA512String(password string) string {
	var salt = make([]byte, 16)
	rand.Read(salt)
	var hashBytes = SSHA512([]byte(password), salt)
	return "{SSHA512}" + base64.StdEncoding.EncodeToString(hashBytes)
}
