package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/stringutil"
)

func LookupOTPAuthHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		if httputil.AllowMethods(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true, true) {
			return
		}

		var (
			userID     = r.PathValue("user_id")
			keyWrapper *otpauth.KeyWrapper
		)

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if !errors.Is(err, otpauth.ErrNotFound) {
				Problem(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			keyWrapper = kw
		}

		var responseMap = make(map[string]any)

		if keyWrapper != nil {
			responseMap["enabled"] = true
			responseMap["type"] = "totp"
			responseMap["algorithm"] = strings.ToLower(keyWrapper.Algorithm())
			responseMap["period"] = 30
			responseMap["digits"] = keyWrapper.Digits()
		} else {
			responseMap["enabled"] = false
		}

		if bytes, err := json.Marshal(responseMap); err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		}
	})
}

func ValidateOTPCodeHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		if httputil.AllowMethods(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true, true) {
			return
		}

		var (
			userID     = r.PathValue("user_id")
			keyWrapper *otpauth.KeyWrapper
		)

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if errors.Is(otpauth.ErrNotFound, err) {
				Problem(w, http.StatusConflict, "OTPAuth not enabled")
			} else {
				Problem(w, http.StatusInternalServerError, err.Error())
			}
			return
		} else {
			keyWrapper = kw
		}

		var code string

		if strings.Contains(r.Header.Get("Content-Type"), "json") {
			var requestMap = make(map[string]string)

			if bytes, err := io.ReadAll(r.Body); err == nil {
				if err := json.Unmarshal(bytes, &requestMap); err != nil {
					Problem(w, http.StatusBadRequest, err.Error())
					return
				}
			} else {
				Problem(w, http.StatusBadRequest, err.Error())
				return
			}

			code = stringutil.StripSpaces(requestMap["code"])
		} else {
			code = stringutil.StripSpaces(r.PostFormValue("code"))
		}

		if code == "" {
			Problem(w, http.StatusBadRequest, "code required")
			return
		}

		var responseMap = map[string]any{
			"verified": keyWrapper.VerifyCode(code),
		}

		if bytes, err := json.Marshal(responseMap); err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		}
	})
}

type OTPAuthDetails struct {
	Algorithm    string `json:"algorithm"`
	Digits       int    `json:"digits"`
	OTPAuthURI   string `json:"otpauth_uri"`
	Period       int    `json:"period"`
	RecoveryCode string `json:"recovery_code"`
	Secret       string `json:"secret"`
	Type         string `json:"type"`
}

func PutOTPAuthHandler(otpauthStore otpauth.Store, issuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		if httputil.AllowMethods(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true, true) {
			return
		}

		var (
			userID       = r.PathValue("user_id")
			self         = strings.EqualFold(r.Context().Value("user_id").(string), userID)
			recoveryCode string
			keyWrapper   *otpauth.KeyWrapper
		)

		if !httputil.IsJSON(r.Header.Get("Content-Type")) {
			Problem(w, http.StatusUnsupportedMediaType, "json required")
			return
		}

		if recoveryCodeBase64 := r.Header.Get("X-Recovery-Code"); recoveryCodeBase64 != "" {
			if recoveryCodeBytes, err := base64.StdEncoding.DecodeString(recoveryCodeBase64); err != nil {
				Problem(w, http.StatusBadRequest, "recovery code must be base64 encoded")
				return
			} else {
				recoveryCode = strings.ToUpper(stringutil.StripSpaces(string(recoveryCodeBytes)))
			}
		}

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if !errors.Is(otpauth.ErrNotFound, err) {
				Problem(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			keyWrapper = kw
		}

		if self && keyWrapper != nil && recoveryCode == "" {
			Problem(w, http.StatusBadRequest, "x-recovery-code header required")
			return
		}

		if recoveryCode != "" && keyWrapper != nil && !otpauthStore.VerifyRecoveryCode(userID, recoveryCode) {
			Problem(w, http.StatusForbidden, "invalid recovery code")
			return
		}

		var otpAuthDetails OTPAuthDetails

		if bytes, err := io.ReadAll(r.Body); err == nil {
			if err := json.Unmarshal(bytes, &otpAuthDetails); err != nil {
				Problem(w, http.StatusBadRequest, err.Error())
				return
			}
		} else {
			Problem(w, http.StatusBadRequest, err.Error())
			return
		}

		var algorithm = "sha1"
		if alg := strings.ToLower(strings.TrimSpace(otpAuthDetails.Algorithm)); alg != "" {
			algorithm = alg
		}
		var digits = 6
		if otpAuthDetails.Digits > 6 {
			digits = 8
		}

		if otpauthURI := strings.TrimSpace(otpAuthDetails.OTPAuthURI); otpauthURI != "" {
			if kw, err := otpauth.NewKeyWrapperFromURI(otpauthURI); err != nil {
				Problem(w, http.StatusBadRequest, err.Error())
				return
			} else {
				keyWrapper = kw
			}
		} else {
			if kw, err := otpauth.NewKeyWrapper(issuer, userID, algorithm, otpAuthDetails.Secret, digits); err != nil {
				Problem(w, http.StatusInternalServerError, err.Error())
				return
			} else {
				keyWrapper = kw
			}
		}

		if recoveryCode, err := otpauthStore.Put(userID, *keyWrapper); err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
			return
		} else {
			otpAuthDetails.Secret = keyWrapper.Secret()
			otpAuthDetails.Algorithm = keyWrapper.Algorithm()
			otpAuthDetails.OTPAuthURI = keyWrapper.URI()
			otpAuthDetails.RecoveryCode = recoveryCode
			otpAuthDetails.Period = 30
			otpAuthDetails.Digits = keyWrapper.Digits()
			otpAuthDetails.Type = "totp"
			if b, err := json.Marshal(otpAuthDetails); err != nil {
				Problem(w, http.StatusInternalServerError, err.Error())
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}
		}
	})
}

func ResetOTPAuthHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		if httputil.AllowMethods(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true, true) {
			return
		}

		var (
			userID       = r.PathValue("user_id")
			self         = strings.EqualFold(r.Context().Value("user_id").(string), userID)
			recoveryCode string
		)

		if recoveryCodeBase64 := r.Header.Get("X-Recovery-Code"); recoveryCodeBase64 != "" {
			if recoveryCodeBytes, err := base64.StdEncoding.DecodeString(recoveryCodeBase64); err != nil {
				Problem(w, http.StatusBadRequest, "recovery code must be base64 encoded")
				return
			} else {
				recoveryCode = strings.ToUpper(stringutil.StripSpaces(string(recoveryCodeBytes)))
			}
		}

		if self && recoveryCode == "" {
			Problem(w, http.StatusBadRequest, "x-recovery-code header required")
			return
		}

		if recoveryCode != "" && !otpauthStore.VerifyRecoveryCode(userID, recoveryCode) {
			Problem(w, http.StatusForbidden, "invalid recovery code")
			return
		}

		if err := otpauthStore.Delete(userID); err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
