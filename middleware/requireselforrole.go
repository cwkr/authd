package middleware

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/people"
	"github.com/gorilla/mux"
)

const ErrorAccessDenied = "access_denied"

func RequireSelfOrRole(next http.Handler, peopleStore people.Store, roleMappings oauth2.RoleMappings, allowedRole string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			userID = r.Context().Value("user_id").(string)
			self   = strings.EqualFold(mux.Vars(r)["user_id"], userID)
			user   oauth2.User
			roles  []string
		)

		if person, err := peopleStore.Lookup(userID); err != nil {
			if !errors.Is(err, people.ErrPersonNotFound) {
				oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			user = oauth2.User{Person: *person, UserID: userID}
		}

		if user.UserID == "" {
			roles = roleMappings.ClientRoles(userID)
		} else {
			roles = roleMappings.Roles(user)
		}

		if !self && (allowedRole == "" || !slices.Contains(roles, allowedRole)) {
			oauth2.Error(w, ErrorAccessDenied, "", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
