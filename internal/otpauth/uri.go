package otpauth

import (
	"errors"
)

const PrefixOTPAuth = "otpauth:"

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)
