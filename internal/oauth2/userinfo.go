package oauth2

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/cwkr/authd/internal/httputil"
	"github.com/cwkr/authd/internal/people"
)

type userinfoHandler struct {
	peopleStore  people.Store
	extraClaims  map[string]string
	roleMappings RoleMappings
}

func (u *userinfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	httputil.AllowCORS(w, r, []string{http.MethodGet, http.MethodOptions}, true)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var userID = r.Context().Value("user_id").(string)

	if person, err := u.peopleStore.Lookup(userID); err == nil {

		var user = User{*person, userID}

		var claims = map[string]any{
			ClaimSubject: userID,
		}

		AddProfileClaims(claims, user)
		AddEmailClaims(claims, user)
		AddPhoneClaims(claims, user)
		AddAddressClaims(claims, user)
		AddExtraClaims(claims, u.extraClaims, user, "", u.roleMappings)

		var bytes, err = json.Marshal(claims)
		if err != nil {
			Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
			return
		}

		httputil.NoCache(w)
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	} else {
		Error(w, ErrorInternal, err.Error(), http.StatusInternalServerError)
	}
}

func UserinfoHandler(peopleStore people.Store, extraClaims map[string]string, roleMappings RoleMappings) http.Handler {
	return &userinfoHandler{
		peopleStore:  peopleStore,
		extraClaims:  extraClaims,
		roleMappings: roleMappings,
	}
}
