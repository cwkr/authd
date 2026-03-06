package oauth2

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
)

const (
	// ErrorInvalidRequest - The request is missing a parameter so the server
	// can't proceed with the request. This may also be returned if the
	// request includes an unsupported parameter or repeats a parameter.
	ErrorInvalidRequest = "invalid_request"

	// ErrorInvalidClient – Client authentication failed, such as if the
	// request contains an invalid client ID or secret. Send an HTTP 401
	// response in this case.
	ErrorInvalidClient = "invalid_client"

	// ErrorInvalidGrant – The authorization code (or user's password for the
	// password grant type) is invalid or expired. This is also the error you
	// would return if the redirect URL given in the authorization grant does
	// not match the URL provided in this access token request.
	ErrorInvalidGrant = "invalid_grant"

	// ErrorRedirectURIMismatch - The redirect URI is invalid for the
	// requested client id
	ErrorRedirectURIMismatch = "redirect_uri_mismatch"

	// ErrorUnsupportedGrantType – If a grant type is requested that the
	// authorization server doesn't recognize, use this code. Note that
	// unknown grant types also use this specific error code rather than using
	// the ErrorInvalidRequest above.
	ErrorUnsupportedGrantType = "unsupported_grant_type"

	ErrorInternal = "internal_server_error"
	ErrorNotFound = "not_found"
)

func Error(w http.ResponseWriter, error string, description string, code int) {
	var statusText = http.StatusText(code)
	if code < 500 {
		slog.Warn(fmt.Sprintf("%d %s: %s", code, statusText, error))
	} else {
		slog.Error(fmt.Sprintf("%d %s: %s", code, statusText, error))
	}
	w.Header().Set("Content-Type", "application/json")
	httputil.NoCache(w)
	w.WriteHeader(code)
	var bytes, _ = json.Marshal(ErrorResponse{error, description})
	w.Write(bytes)
}
