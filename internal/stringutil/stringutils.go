package stringutil

import (
	"crypto/rand"
	"math/big"
	"strings"
	"unicode"
)

var TemplateFuncs = map[string]any{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
}

func IsAnyEmpty(strings ...string) bool {
	for _, s := range strings {
		if s == "" {
			return true
		}
	}
	return false
}

func RandomAlphanumericString(max int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, max)

	for i := 0; i < max; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		bytes[i] = letters[num.Int64()]
	}

	return string(bytes)
}

func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			return -1
		}
		// else keep it in the string
		return r
	}, str)
}
