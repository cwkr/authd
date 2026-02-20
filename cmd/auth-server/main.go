package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cwkr/authd/internal/fileutil"
	"github.com/cwkr/authd/internal/htmlutil"
	"github.com/cwkr/authd/internal/maputil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/server"
	"github.com/cwkr/authd/internal/server/session"
	"github.com/cwkr/authd/internal/sqlutil"
	"github.com/cwkr/authd/mail"
	"github.com/cwkr/authd/middleware"
	"github.com/cwkr/authd/settings"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/hjson/hjson-go/v4"
	"golang.org/x/crypto/bcrypt"
)

var version = "v0.9.x"

func main() {
	var (
		serverSettings       *settings.Server
		tokenCreator         oauth2.TokenCreator
		accessTokenValidator middleware.AccessTokenValidator
		peopleStore          people.Store
		revocationStore      revocation.Store
		clientStore          clients.Store
		otpauthStore         otpauth.Store
		err                  error
		configFilename       string
		settingsFilename     string
		setClientID          string
		setClientSecret      string
		setClientPresetID    string
		setUserID            string
		setPassword          string
		setGivenName         string
		setFamilyName        string
		setEmail             string
		setDepartment        string
		generateTOTPSecret   bool
		totpAlgorithm        string
		totpDigits           int
		keySize              int
		keyID                string
		saveSettings         bool
		printVersion         bool
		setPort              int
	)

	log.SetOutput(os.Stdout)

	flag.StringVar(&configFilename, "config", "", "config file name")
	flag.StringVar(&setClientID, "client-id", "", "set client id")
	flag.StringVar(&setClientSecret, "client-secret", "", "set client secret")
	flag.StringVar(&setClientPresetID, "client-preset", "", "set client preset")
	flag.StringVar(&setUserID, "user-id", "", "set user id")
	flag.StringVar(&setPassword, "password", "", "set user password")
	flag.StringVar(&setGivenName, "given-name", "", "set user given name")
	flag.StringVar(&setFamilyName, "family-name", "", "set user family name")
	flag.StringVar(&setEmail, "email", "", "set user email")
	flag.StringVar(&setDepartment, "department", "", "set user department")
	flag.BoolVar(&generateTOTPSecret, "totp", false, "enable Time-based One-time Password (TOTP)")
	flag.StringVar(&totpAlgorithm, "totp-algorithm", "sha256", "totp hash algorithm")
	flag.IntVar(&totpDigits, "totp-digits", 6, "totp digits")
	flag.IntVar(&keySize, "key-size", 2048, "generated signing key size")
	flag.StringVar(&keyID, "key-id", "sigkey", "set generated signing key id")
	flag.BoolVar(&saveSettings, "save", false, "save config and exit")
	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	flag.IntVar(&setPort, "port", 6080, "http server port")
	flag.Parse()

	if printVersion {
		fmt.Println(version)
		os.Exit(0)
	} else {
		log.Printf("Starting Auth Server %s built with %s", version, runtime.Version())
	}

	// Set defaults
	serverSettings = settings.NewDefault(setPort)

	settingsFilename = fileutil.ProbeSettingsFilename(configFilename)

	if fileutil.FileExists(settingsFilename) {
		log.Printf("Loading settings from %s", settingsFilename)
		if bytes, err := os.ReadFile(settingsFilename); err == nil {
			options := hjson.DefaultDecoderOptions()
			options.DisallowUnknownFields = true
			options.DisallowDuplicateKeys = true
			if err := hjson.UnmarshalWithOptions(bytes, serverSettings, options); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.Key == "" {
		log.Printf("Generating %d bit RSA key with ID %q", keySize, keyID)
		if err := serverSettings.GenerateSigningKey(keySize, keyID); err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if err := serverSettings.LoadKeys(filepath.Dir(settingsFilename)); err != nil {
		log.Fatalf("!!! %s", err)
	}

	if serverSettings.LoginTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LoginTemplate, "@"))
		log.Printf("Loading login form template from %s", filename)
		err = server.LoadLoginTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.LogoutTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LogoutTemplate, "@"))
		log.Printf("Loading logout template from %s", filename)
		err = server.LoadLogoutTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.Setup2FATemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.Setup2FATemplate, "@"))
		log.Printf("Loading setup 2FA template from %s", filename)
		err = server.LoadSetup2FATemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.ResetPasswordTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.ResetPasswordTemplate, "@"))
		log.Printf("Loading password reset template from %s", filename)
		err = server.LoadResetPasswdTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.ChangePasswordTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.ChangePasswordTemplate, "@"))
		log.Printf("Loading change password template from %s", filename)
		err = server.LoadChangePasswdTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if serverSettings.PasswordResetMailTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.PasswordResetMailTemplate, "@"))
		log.Printf("Loading password reset mail template from %s", filename)
		err = server.LoadPasswordResetMailTemplate(filename)
		if err != nil {
			log.Fatalf("!!! %s", err)
		}
	}

	if setClientID != "" {
		if serverSettings.Clients == nil {
			serverSettings.Clients = map[string]clients.Client{}
		}
		var client = serverSettings.Clients[setClientID]
		if setClientSecret != "" {
			if secretHash, err := bcrypt.GenerateFromPassword([]byte(setClientSecret), 5); err != nil {
				log.Fatalf("!!! %s", err)
			} else {
				client.SecretHash = string(secretHash)
			}
		}
		if setClientPresetID != "" {
			client.PresetID = setClientPresetID
		}
		serverSettings.Clients[setClientID] = client
	}

	if setUserID != "" {
		if serverSettings.Users == nil {
			serverSettings.Users = map[string]people.AuthenticPerson{}
		}
		var user = serverSettings.Users[setUserID]
		if setPassword != "" {
			if passwordHash, err := bcrypt.GenerateFromPassword([]byte(setPassword), 5); err != nil {
				log.Fatalf("!!! %s", err)
			} else {
				user.PasswordHash = string(passwordHash)
			}
		}
		if setGivenName != "" {
			user.GivenName = setGivenName
		}
		if setFamilyName != "" {
			user.FamilyName = setFamilyName
		}
		if setEmail != "" {
			user.Email = setEmail
		}
		if setDepartment != "" {
			user.Department = setDepartment
		}
		if user.PasswordHash == "" {
			log.Fatal("!!! missing password")
		}
		if generateTOTPSecret {
			if kw, err := otpauth.NewKeyWrapper(serverSettings.Issuer, setUserID, totpAlgorithm, "", totpDigits); err != nil {
				log.Fatalf("!!! %s", err)
			} else {
				user.OTPAuthURI = kw.URI()
			}
		}
		serverSettings.Users[setUserID] = user
	}

	if setPort != serverSettings.Port {
		serverSettings.Port = setPort
	}

	if saveSettings {
		log.Printf("Saving settings to %s", settingsFilename)
		var configBytes []byte
		if filepath.Ext(strings.ToLower(settingsFilename)) == ".hjson" {
			options := hjson.DefaultOptions()
			options.QuoteAlways = true
			options.EmitRootBraces = false
			options.IndentBy = "  "
			configBytes, _ = hjson.MarshalWithOptions(serverSettings, options)
		} else {
			configBytes, _ = json.MarshalIndent(serverSettings, "", "  ")
		}
		if err := os.WriteFile(settingsFilename, configBytes, 0644); err != nil {
			log.Fatalf("!!! %s", err)
		}
		os.Exit(0)
	}

	var (
		scope   = strings.TrimSpace(oauth2.OIDCDefaultScope + " " + serverSettings.ExtraScope)
		presets = maputil.LowerKeys(serverSettings.Presets)
	)

	tokenCreator, err = oauth2.NewTokenCreator(
		serverSettings.PrivateKey(),
		serverSettings.KeyID(),
		serverSettings.Issuer,
		scope,
		presets,
		serverSettings.Roles,
	)
	if err != nil {
		log.Fatalf("!!! %s", err)
	}

	accessTokenValidator = middleware.NewAccessTokenValidator(serverSettings.KeySetProvider())

	var basePath = ""
	var sessionStore = sessions.NewCookieStore([]byte(serverSettings.CookieSecret))
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.MaxAge = 0
	sessionStore.Options.SameSite = http.SameSiteLaxMode
	if issuerUrl, err := url.Parse(serverSettings.Issuer); err == nil {
		if issuerUrl.Path != "/" {
			basePath = strings.TrimSuffix(issuerUrl.Path, "/")
			sessionStore.Options.Path = basePath
			sessionStore.Options.Secure = false
		}
		if issuerUrl.Scheme == "https" {
			sessionStore.Options.Secure = true
		}
	} else {
		log.Fatalf("!!! %s", err)
	}
	var sessionManager = session.NewManager(sessionStore, presets)

	var dbs = make(map[string]*sql.DB)

	var users = maputil.LowerKeys(serverSettings.Users)

	if serverSettings.PeopleStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.PeopleStore.URI) {
			if peopleStore, err = people.NewSqlStore(users, dbs, serverSettings.PeopleStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else if strings.HasPrefix(serverSettings.PeopleStore.URI, "ldap:") || strings.HasPrefix(serverSettings.PeopleStore.URI, "ldaps:") {
			if peopleStore, err = people.NewLdapStore(users, serverSettings.PeopleStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty people_store.uri: %s", serverSettings.PeopleStore.URI)
		}
	} else {
		peopleStore = people.NewInMemoryStore(users)
	}

	if serverSettings.ClientStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.ClientStore.URI) {
			if clientStore, err = clients.NewSqlStore(serverSettings.Clients, dbs, serverSettings.ClientStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty client_store.uri: %s", serverSettings.ClientStore.URI)
		}
	} else {
		clientStore = clients.NewInMemoryStore(serverSettings.Clients)
	}

	if serverSettings.EnableTokenRevocation {
		if serverSettings.RevocationStore == nil {
			log.Fatal("!!! revocation_store.uri must be specified to enable token revocation")
		}
		if !sqlutil.IsDatabaseURI(serverSettings.RevocationStore.URI) {
			log.Fatalf("!!! unsupported or empty revocation_store.uri: %s", serverSettings.RevocationStore.URI)
		}
		if revocationStore, err = revocation.NewSqlStore(dbs, serverSettings.RevocationStore); err != nil {
			log.Fatalf("!!! %s", err)
		}
	} else {
		revocationStore = revocation.NewNoopStore()
	}

	if serverSettings.OTPAuthStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.OTPAuthStore.URI) {
			if otpauthStore, err = otpauth.NewSqlStore(users, dbs, serverSettings.OTPAuthStore); err != nil {
				log.Fatalf("!!! %s", err)
			}
		} else {
			log.Fatalf("!!! unsupported or empty otpauth_store.uri: %s", serverSettings.ClientStore.URI)
		}
	} else {
		otpauthStore = otpauth.NewInMemoryStore(users)
	}

	var mailer mail.Mailer

	if strings.TrimSpace(serverSettings.Mail.ServerURI) != "" {
		if m, err := mail.NewMailer(serverSettings.Mail); err != nil {
			log.Fatalf("!!! %s", err)
		} else {
			mailer = m
		}
	}

	var passwordResetEnabled = mailer != nil && !peopleStore.ReadOnly()

	var router = mux.NewRouter()

	router.NotFoundHandler = htmlutil.NotFoundHandler(basePath)
	router.Handle(basePath+"/", server.IndexHandler(basePath, serverSettings, sessionManager, clientStore, scope, version)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/style.css", server.StyleHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/scripts/main.js", server.MainScriptHandler()).
		Methods(http.MethodGet)
	router.Handle("/favicon.ico", server.FaviconHandler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-16x16.png", server.Favicon16x16Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/favicon-32x32.png", server.Favicon32x32Handler()).
		Methods(http.MethodGet)
	router.Handle(basePath+"/login", server.LoginHandler(basePath, sessionManager, peopleStore, clientStore, otpauthStore, presets, serverSettings.Issuer, passwordResetEnabled)).
		Methods(http.MethodGet, http.MethodPost)
	router.Handle(basePath+"/logout", server.LogoutHandler(basePath, serverSettings, sessionManager, clientStore))
	router.Handle(basePath+"/health", server.HealthHandler(peopleStore)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/info", server.InfoHandler(version, runtime.Version())).
		Methods(http.MethodGet)

	router.Handle(basePath+"/jwks", oauth2.JwksHandler(serverSettings.KeySetProvider())).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/token", oauth2.TokenHandler(tokenCreator, peopleStore, clientStore, revocationStore, presets, scope)).
		Methods(http.MethodOptions, http.MethodPost)
	router.Handle(basePath+"/authorize", oauth2.AuthorizeHandler(serverSettings.Issuer, basePath, tokenCreator, sessionManager, peopleStore, clientStore, presets, scope)).
		Methods(http.MethodGet)
	router.Handle(basePath+"/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(serverSettings.Issuer, scope, serverSettings.EnableTokenRevocation)).
		Methods(http.MethodGet, http.MethodOptions)
	router.Handle(basePath+"/userinfo", middleware.RequireJWT(oauth2.UserinfoHandler(peopleStore, serverSettings.UserinfoExtraClaims, serverSettings.Roles), accessTokenValidator, serverSettings.Issuer)).
		Methods(http.MethodGet, http.MethodOptions)

	router.Handle(basePath+"/setup-2fa", server.Setup2FAHandler(sessionManager, clientStore, presets, otpauthStore, basePath, version, serverSettings.Issuer)).
		Methods(http.MethodGet, http.MethodPost)

	if passwordResetEnabled {
		router.Handle(basePath+"/resetpasswd", server.ResetPasswdHandler(peopleStore, clientStore, mailer, tokenCreator, serverSettings.Issuer, basePath, version)).
			Methods(http.MethodGet, http.MethodPost)
		router.Handle(basePath+"/chpasswd/{token}", server.ChangePasswdHandler(peopleStore, tokenCreator, revocationStore, serverSettings.Issuer, basePath, version)).
			Methods(http.MethodGet, http.MethodPost)
	}

	if serverSettings.EnableTokenRevocation {
		router.Handle(basePath+"/revoke", oauth2.RevokeHandler(tokenCreator, clientStore, revocationStore)).
			Methods(http.MethodPost, http.MethodOptions)
	}

	if !serverSettings.DisableAPI {
		var lookupPersonHandler = server.LookupPersonHandler(peopleStore,
			serverSettings.PeopleAPICustomVersions, serverSettings.Roles)
		if serverSettings.PeopleAPIRequireAuthN {
			lookupPersonHandler = middleware.RequireAuthN(lookupPersonHandler, accessTokenValidator, peopleStore, serverSettings.Issuer)
		}
		router.Handle(basePath+"/api/{version}/people/{user_id}", lookupPersonHandler).
			Methods(http.MethodGet, http.MethodOptions)
		if !peopleStore.ReadOnly() {
			router.Handle(basePath+"/api/v1/people/{user_id}", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.PutPersonHandler(peopleStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
				Methods(http.MethodPut)
			router.Handle(basePath+"/api/v1/people/{user_id}/password", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.ChangePasswordHandler(peopleStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
				Methods(http.MethodOptions, http.MethodPut)
		}

		router.Handle(basePath+"/api/{version}/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.LookupOTPAuthHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
			Methods(http.MethodGet, http.MethodOptions)
		router.Handle(basePath+"/api/{version}/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.ValidateOTPCodeHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
			Methods(http.MethodPost)
		router.Handle(basePath+"/api/{version}/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.PutOTPAuthHandler(otpauthStore, serverSettings.Issuer), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
			Methods(http.MethodPut)
		router.Handle(basePath+"/api/{version}/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(server.ResetOTPAuthHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer)).
			Methods(http.MethodDelete)
	}

	log.Printf("Listening on http://localhost:%d%s/", serverSettings.Port, basePath)
	err = http.ListenAndServe(fmt.Sprintf(":%d", serverSettings.Port), router)
	if err != nil {
		log.Fatalf("!!! %s", err)
	}
}
