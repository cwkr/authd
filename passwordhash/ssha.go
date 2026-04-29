package passwordhash

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
)

func SSHA(password, salt []byte) []byte {
	var passwordAndSalt = make([]byte, len(password), len(password)+len(salt))
	copy(passwordAndSalt, password)
	passwordAndSalt = append(passwordAndSalt, salt...)
	var hash = sha1.Sum(passwordAndSalt)
	return append(hash[:], salt...)
}

func SSHAString(password string) string {
	var salt = make([]byte, 8)
	rand.Read(salt)
	var hashBytes = SSHA([]byte(password), salt)
	return "{SSHA}" + base64.StdEncoding.EncodeToString(hashBytes)
}
