package otpauth

import (
	"errors"
	"fmt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"log"
	"net/url"
	"strings"
)

const PrefixOTPAuth = "otpauth:"

var (
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)

func GenerateURI(issuer, userID, algorithm string) (string, error) {
	var otpID = "auth-server"
	if issuerURL, err := url.Parse(issuer); err != nil {
		return "", err
	} else {
		if issuerURL.Hostname() != "" && issuerURL.Hostname() != "localhost" {
			otpID = issuerURL.Hostname()
		}
		if issuerURL.Path != "" && issuerURL.Path != "/" {
			otpID += issuerURL.Path
		}
	}
	var opts = totp.GenerateOpts{
		Issuer:      otpID,
		AccountName: userID,
	}
	if strings.EqualFold(algorithm, "sha256") {
		opts.Algorithm = otp.AlgorithmSHA256
	} else if strings.EqualFold(algorithm, "sha512") {
		opts.Algorithm = otp.AlgorithmSHA512
	} else if !strings.EqualFold(algorithm, "sha1") {
		return "", fmt.Errorf("%s is not supported: %w", algorithm, ErrUnsupportedAlgorithm)
	}
	log.Printf("Generating TOTP Key for %s@%s using %s", userID, otpID, opts.Algorithm)
	if totpKey, err := totp.Generate(opts); err != nil {
		return "", err
	} else {
		return totpKey.URL(), nil
	}
}
