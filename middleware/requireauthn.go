package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/people"
)

func RequireAuthN(next http.Handler, tokenVerifier AccessTokenValidator, peopleStore people.Store, audiences ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			userID, password, basicAuth = r.BasicAuth()
			accessToken, bearerAuth     = httputil.BearerAuth(r)
		)

		if !basicAuth && !bearerAuth {
			w.Header().Set("WWW-Authenticate", "Bearer, Basic")
			oauth2.Error(w, "unauthorized", "authentication required", http.StatusUnauthorized)
			return
		}

		if bearerAuth {
			if sub, err := tokenVerifier.Validate(accessToken, audiences...); err != nil {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=\"invalid_token\", error_description=\"%s\"", err.Error()))
				oauth2.Error(w, "invalid_token", err.Error(), http.StatusUnauthorized)
				return
			} else {
				userID = sub
			}
		} else if basicAuth {
			if foundUserID, err := peopleStore.Authenticate(userID, password); err != nil {
				w.Header().Set("WWW-Authenticate", "Basic")
				oauth2.Error(w, "unauthorized", "authentication required", http.StatusUnauthorized)
				return
			} else {
				userID = foundUserID
			}
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user_id", userID)))
	})
}
