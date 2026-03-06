package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/settings"
	"github.com/gorilla/mux"
)

const ErrorUnsupportedMediaType = "unsupported_media_type"

type lookupPersonHandler struct {
	peopleStore  people.Store
	customAPI    *settings.CustomPeopleAPI
	roleMappings oauth2.RoleMappings
}

type personWithRoles struct {
	people.Person
	Roles []string `json:"roles,omitempty"`
}

func cleanup(slice []string) []string {
	var newSlice = make([]string, 0, len(slice))
	for _, elem := range slice {
		clean := strings.TrimSpace(elem)
		if clean != "" {
			newSlice = append(newSlice, clean)
		}
	}
	return newSlice
}

func (p *lookupPersonHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions, http.MethodPut}, true)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var subject string

	if contextUserID := r.Context().Value("user_id"); contextUserID != nil {
		subject = contextUserID.(string)
	}

	var pathVars = mux.Vars(r)
	var userID = strings.TrimSpace(pathVars["user_id"])

	if person, err := p.peopleStore.Lookup(userID); err == nil {
		var user = oauth2.User{UserID: userID, Person: *person}
		var bytes []byte
		var err error
		if p.customAPI != nil {
			var claims = make(map[string]any)
			oauth2.AddExtraClaims(claims, p.customAPI.Attributes, user, subject, "", p.roleMappings)
			if filterParamName := strings.TrimSpace(p.customAPI.FilterParam); filterParamName != "" {
				var attrsToFetch = cleanup(strings.Split(strings.Join(r.URL.Query()[filterParamName], ","), ","))
				if len(attrsToFetch) > 0 {
					for key, _ := range claims {
						if !slices.Contains(attrsToFetch, key) {
							delete(claims, key)
						}
					}
				}
			}
			oauth2.AddExtraClaims(claims, p.customAPI.FixedAttributes, user, subject, "", p.roleMappings)
			bytes, err = json.Marshal(claims)
		} else {
			bytes, err = json.Marshal(personWithRoles{Person: *person, Roles: p.roleMappings.Roles(user)})
		}
		if err != nil {
			Problem(w, http.StatusInternalServerError, err.Error())
			return
		}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	} else {
		if errors.Is(err, people.ErrPersonNotFound) {
			Problem(w, http.StatusNotFound, err.Error())
		} else {
			Problem(w, http.StatusInternalServerError, err.Error())
		}
	}
}

func LookupPersonHandler(peopleStore people.Store, customAPI *settings.CustomPeopleAPI, roleMappings oauth2.RoleMappings) http.Handler {
	return &lookupPersonHandler{
		peopleStore:  peopleStore,
		customAPI:    customAPI,
		roleMappings: roleMappings,
	}
}

func PutPersonHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions, http.MethodPut}, true)

		if !httputil.IsJSON(r.Header.Get("Content-Type")) {
			oauth2.Error(w, ErrorUnsupportedMediaType, "", http.StatusUnsupportedMediaType)
			return
		}

		var person people.Person

		if bytes, err := io.ReadAll(r.Body); err == nil {
			if err := json.Unmarshal(bytes, &person); err != nil {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
			return
		}

		var userID = mux.Vars(r)["user_id"]

		if err := peopleStore.Put(userID, &person); err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func ChangePasswordHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(fmt.Sprintf("%s %s", r.Method, r.URL))

		httputil.AllowCORS(w, r, []string{http.MethodOptions, http.MethodPut}, true)

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var newPassword string

		if httputil.IsJSON(r.Header.Get("Content-Type")) {
			var passwordChange = make(map[string]string)
			if bytes, err := io.ReadAll(r.Body); err == nil {
				if err := json.Unmarshal(bytes, &passwordChange); err != nil {
					oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
					return
				}
				newPassword = passwordChange["password"]
			} else {
				oauth2.Error(w, oauth2.ErrorInvalidRequest, err.Error(), http.StatusBadRequest)
				return
			}
		} else if httputil.IsFormData(r.Header.Get("Content-Type")) {
			newPassword = strings.TrimSpace(r.PostFormValue("password"))
		} else {
			oauth2.Error(w, ErrorUnsupportedMediaType, "", http.StatusUnsupportedMediaType)
			return
		}

		if newPassword == "" {
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "password is required", http.StatusBadRequest)
			return
		}

		var userID = mux.Vars(r)["user_id"]

		if err := peopleStore.ChangePassword(userID, newPassword); err != nil {
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
