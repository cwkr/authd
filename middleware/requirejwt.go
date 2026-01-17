package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2"
)

func RequireJWT(next http.Handler, tokenVerifier AccessTokenValidator, audiences ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var accessToken, bearerAuth = httputil.BearerAuth(r)
		if !bearerAuth || accessToken == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			oauth2.Error(w, "unauthorized", "authentication required", http.StatusUnauthorized)
			return
		}
		if sub, err := tokenVerifier.Validate(accessToken, audiences...); err != nil {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=\"invalid_token\", error_description=\"%s\"", err.Error()))
			oauth2.Error(w, "invalid_token", err.Error(), http.StatusUnauthorized)
		} else {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user_id", sub)))
		}
	})
}
