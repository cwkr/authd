package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/gorilla/mux"
)

func LookupOTPAuthHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var (
			userID     = mux.Vars(r)["user_id"]
			keyWrapper *otpauth.KeyWrapper
		)

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if !errors.Is(otpauth.ErrNotFound, err) {
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
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
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(bytes)
		}
	})
}

func ValidateOTPCodeHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true)

		var (
			userID     = mux.Vars(r)["user_id"]
			keyWrapper *otpauth.KeyWrapper
		)

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if errors.Is(otpauth.ErrNotFound, err) {
				oauth2.Error(w, "not_enabled", "", http.StatusConflict)
			} else {
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
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
					oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}

			code = stringutil.StripSpaces(requestMap["code"])
		} else {
			code = stringutil.StripSpaces(r.PostFormValue("code"))
		}

		if code == "" {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "code required", http.StatusBadRequest)
			return
		}

		var responseMap = map[string]any{
			"verified": keyWrapper.VerifyCode(code),
		}

		if bytes, err := json.Marshal(responseMap); err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
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
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodDelete, http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete}, true)

		var (
			userID       = mux.Vars(r)["user_id"]
			self         = strings.EqualFold(r.Context().Value("user_id").(string), userID)
			recoveryCode string
			keyWrapper   *otpauth.KeyWrapper
		)

		if !httputil.IsJSON(r.Header.Get("Content-Type")) {
			oauth2.Error(w, ErrorUnsupportedMediaType, "", http.StatusUnsupportedMediaType)
			return
		}

		if recoveryCodeBase64 := r.Header.Get("X-Recovery-Code"); recoveryCodeBase64 != "" {
			if recoveryCodeBytes, err := base64.StdEncoding.DecodeString(recoveryCodeBase64); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, "recovery code must be base64 encoded", http.StatusBadRequest)
				return
			} else {
				recoveryCode = strings.ToUpper(stringutil.StripSpaces(string(recoveryCodeBytes)))
			}
		}

		if kw, err := otpauthStore.Lookup(userID); err != nil {
			if !errors.Is(otpauth.ErrNotFound, err) {
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			keyWrapper = kw
		}

		if self && keyWrapper != nil && recoveryCode == "" {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "x-recovery-code header required", http.StatusBadRequest)
			return
		}

		if recoveryCode != "" && keyWrapper != nil && !otpauthStore.VerifyRecoveryCode(userID, recoveryCode) {
			oauth2.Error(w, "not_allowed", "wrong recovery code", http.StatusForbidden)
			return
		}

		var otpAuthDetails OTPAuthDetails

		if bytes, err := io.ReadAll(r.Body); err == nil {
			if err := json.Unmarshal(bytes, &otpAuthDetails); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
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
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			} else {
				keyWrapper = kw
			}
		} else {
			if kw, err := otpauth.NewKeyWrapper(issuer, userID, algorithm, otpAuthDetails.Secret, digits); err != nil {
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
				return
			} else {
				keyWrapper = kw
			}
		}

		if recoveryCode, err := otpauthStore.Put(userID, *keyWrapper); err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
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
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
			}
		}
	})
}

func ResetOTPAuthHandler(otpauthStore otpauth.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

		httputil.AllowCORS(w, r, []string{http.MethodOptions, http.MethodGet, http.MethodPost, http.MethodDelete}, true)

		var (
			userID       = mux.Vars(r)["user_id"]
			self         = strings.EqualFold(r.Context().Value("user_id").(string), userID)
			recoveryCode string
		)

		if recoveryCodeBase64 := r.Header.Get("X-Recovery-Code"); recoveryCodeBase64 != "" {
			if recoveryCodeBytes, err := base64.StdEncoding.DecodeString(recoveryCodeBase64); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, "recovery code must be base64 encoded", http.StatusBadRequest)
				return
			} else {
				recoveryCode = strings.ToUpper(stringutil.StripSpaces(string(recoveryCodeBytes)))
			}
		}

		if self && recoveryCode == "" {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "x-recovery-code header required", http.StatusBadRequest)
			return
		}

		if recoveryCode != "" && !otpauthStore.VerifyRecoveryCode(userID, recoveryCode) {
			oauth2.Error(w, "not_allowed", "wrong recovery code", http.StatusForbidden)
			return
		}

		if err := otpauthStore.Delete(userID); err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
