package server

import (
	_ "embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gorilla/mux"
)

//go:embed templates/chpasswd.gohtml
var chpasswdTpl string

func LoadChangePasswdTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		resetPasswdTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type changePasswdHandler struct {
	peopleStore     people.Store
	tokenCreator    oauth2.TokenCreator
	revocationStore revocation.Store
	tpl             *template.Template
	issuer          string
	basePath        string
	version         string
}

func (c changePasswdHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		errorMessage   string
		successMessage string
		userID         string
		linkExpired    bool
		expiryTime     time.Time
		tokenID        string
	)

	if claims, err := c.tokenCreator.Verify(mux.Vars(r)["token"], oauth2.TokenTypePasswordReset); err == nil {
		userID = claims.UserID
		expiryTime = claims.Expiry.Time()
		tokenID = claims.TokenID
		revokedToken, _ := c.revocationStore.Lookup(claims.TokenID)
		if revokedToken != nil {
			linkExpired = true
		}
	} else {
		if errors.Is(err, jwt.ErrExpired) {
			linkExpired = true
		} else {
			htmlutil.Error(w, c.basePath, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if linkExpired {
		errorMessage = "Password reset link has expired"
	} else {
		if r.Method == http.MethodPost {
			var (
				password        = strings.TrimSpace(r.PostFormValue("password"))
				confirmPassword = strings.TrimSpace(r.PostFormValue("confirm_password"))
			)
			if stringutil.IsAnyEmpty(password, confirmPassword) {
				errorMessage = "password and confirm_password required"
			} else if password != confirmPassword {
				errorMessage = "password and confirm_password do not match"
			} else {
				if err := c.peopleStore.ChangePassword(userID, password); err != nil {
					htmlutil.Error(w, c.basePath, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = c.revocationStore.Put(tokenID, expiryTime)
				successMessage = "Password has been changed"
			}
		}
	}

	if err := c.tpl.ExecuteTemplate(w, "chpasswd", map[string]any{
		"error_message":   errorMessage,
		"success_message": successMessage,
		"expired":         linkExpired,
		"user_id":         userID,
		"base_path":       c.basePath,
		"version":         c.version,
	}); err != nil {
		htmlutil.Error(w, c.basePath, err.Error(), http.StatusInternalServerError)
		return
	}

}

func ChangePasswdHandler(peopleStore people.Store, tokenCreator oauth2.TokenCreator, revocationStore revocation.Store, issuer, basePath, version string) http.Handler {
	return &changePasswdHandler{
		peopleStore:     peopleStore,
		tokenCreator:    tokenCreator,
		revocationStore: revocationStore,
		tpl:             template.Must(template.New("chpasswd").Funcs(stringutil.TemplateFuncs).Parse(chpasswdTpl)),
		issuer:          issuer,
		basePath:        basePath,
		version:         version,
	}
}
