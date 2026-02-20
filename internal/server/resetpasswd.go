package server

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/cwkr/authd/mail"
)

var (
	//go:embed templates/resetpasswd.gohtml
	resetPasswdTpl string
	//go:embed templates/passwdmail.gohtml
	passwdMailTpl string
)

func LoadResetPasswdTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		resetPasswdTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

func LoadPasswordResetMailTemplate(filename string) error {
	if bytes, err := os.ReadFile(filename); err == nil {
		passwdMailTpl = string(bytes)
		return nil
	} else {
		return err
	}
}

type resetPasswdHandler struct {
	peopleStore  people.Store
	clientStore  clients.Store
	mailer       mail.Mailer
	tokenCreator oauth2.TokenCreator
	tpl          *template.Template
	mailTpl      *template.Template
	issuer       string
	basePath     string
	version      string
}

func (o *resetPasswdHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL)

	var (
		errorMessage   string
		successMessage string
		userID         = strings.TrimSpace(r.FormValue("user_id"))
	)

	if r.Method == http.MethodPost {
		userID = strings.TrimSpace(r.PostFormValue("user_id"))
		if userID == "" {
			errorMessage = "username must not be empty"
		} else {
			if person, err := o.peopleStore.Lookup(userID); err == nil {
				if !o.peopleStore.ReadOnly() && person.Email != "" {
					log.Printf("Sending mail with password reset link for user %s to %s", userID, person.Email)
					if token, err := o.tokenCreator.GeneratePasswordResetToken(userID); err == nil {
						var msg strings.Builder
						if err := o.mailTpl.ExecuteTemplate(&msg, "mail", map[string]any{
							"link": template.URL(fmt.Sprintf("%s/chpasswd/%s", strings.TrimSuffix(o.issuer, "/"), token)),
						}); err != nil {
							htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
							return
						}
						if err := o.mailer.SendMail(person.Email, "Reset Password", msg.String()); err != nil {
							log.Printf("!!! %s", err)
						}
					}
				}
			} else {
				log.Printf("!!! %s", err)
			}
			successMessage = "You will receive an email shortly if the user exists"
		}
	}

	if err := o.tpl.ExecuteTemplate(w, "resetpasswd", map[string]any{
		"error_message":   errorMessage,
		"success_message": successMessage,
		"user_id":         userID,
		"base_path":       o.basePath,
		"version":         o.version,
	}); err != nil {
		htmlutil.Error(w, o.basePath, err.Error(), http.StatusInternalServerError)
		return
	}

}

func ResetPasswdHandler(peopleStore people.Store, clientStore clients.Store, mailer mail.Mailer, tokenCreator oauth2.TokenCreator, issuer, basePath, version string) http.Handler {
	return &resetPasswdHandler{
		peopleStore:  peopleStore,
		clientStore:  clientStore,
		mailer:       mailer,
		tokenCreator: tokenCreator,
		tpl:          template.Must(template.New("resetpasswd").Funcs(stringutil.TemplateFuncs).Parse(resetPasswdTpl)),
		mailTpl:      template.Must(template.New("mail").Funcs(stringutil.TemplateFuncs).Parse(passwdMailTpl)),
		issuer:       issuer,
		basePath:     basePath,
		version:      version,
	}
}
