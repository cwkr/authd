package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
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

type peopleAPIHandler struct {
	peopleStore    people.Store
	customVersions map[string]settings.CustomPeopleAPI
	roleMappings   oauth2.RoleMappings
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

func (p *peopleAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

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
	var apiVersion = strings.TrimSpace(pathVars["version"])

	var userID = strings.TrimSpace(pathVars["user_id"])
	if userID == "" {
		oauth2.Error(w, oauth2.ErrorInvalidRequest, "user_id must not be blank", http.StatusBadRequest)
		return
	}

	if person, err := p.peopleStore.Lookup(userID); err == nil {
		var user = oauth2.User{UserID: userID, Person: *person}
		var bytes []byte
		var err error
		if customVersion, found := p.customVersions[apiVersion]; found {
			var claims = make(map[string]any)
			oauth2.AddExtraClaims(claims, customVersion.Attributes, user, subject, "", p.roleMappings)
			if filterParamName := strings.TrimSpace(customVersion.FilterParam); filterParamName != "" {
				var attrsToFetch = cleanup(strings.Split(strings.Join(r.URL.Query()[filterParamName], ","), ","))
				if len(attrsToFetch) > 0 {
					for key, _ := range claims {
						if !slices.Contains(attrsToFetch, key) {
							delete(claims, key)
						}
					}
				}
			}
			oauth2.AddExtraClaims(claims, customVersion.FixedAttributes, user, subject, "", p.roleMappings)
			bytes, err = json.Marshal(claims)
		} else if apiVersion == "v1" {
			bytes, err = json.Marshal(personWithRoles{Person: *person, Roles: p.roleMappings.Roles(user)})
		} else {
			log.Print("!!! 400 Bad Request - unsupported version")
			oauth2.Error(w, oauth2.ErrorInvalidRequest, "unsupported version", http.StatusBadRequest)
			return
		}
		if err != nil {
			log.Printf("!!! %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(bytes)
	} else {
		if errors.Is(err, people.ErrPersonNotFound) {
			log.Printf("!!! 404 Not Found - %v", err)
			oauth2.Error(w, oauth2.ErrorNotFound, err.Error(), http.StatusNotFound)
		} else {
			log.Printf("!!! %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
		}
	}
}

func LookupPersonHandler(peopleStore people.Store, customVersions map[string]settings.CustomPeopleAPI, roleMappings oauth2.RoleMappings) http.Handler {
	return &peopleAPIHandler{
		peopleStore:    peopleStore,
		customVersions: customVersions,
		roleMappings:   roleMappings,
	}
}

func PutPersonHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

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
			log.Printf("!!! Update failed: %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func ChangePasswordHandler(peopleStore people.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)

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
			log.Printf("!!! Update failed: %v", err)
			oauth2.Error(w, oauth2.ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}
