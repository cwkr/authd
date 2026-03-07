package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cwkr/authd/internal/assets"
	"github.com/cwkr/authd/internal/fileutil"
	"github.com/cwkr/authd/internal/maputil"
	"github.com/cwkr/authd/internal/oauth2"
	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/revocation"
	"github.com/cwkr/authd/internal/otpauth"
	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/server"
	"github.com/cwkr/authd/internal/server/api"
	"github.com/cwkr/authd/internal/server/session"
	"github.com/cwkr/authd/internal/sqlutil"
	"github.com/cwkr/authd/mail"
	"github.com/cwkr/authd/middleware"
	"github.com/cwkr/authd/settings"
	"github.com/gorilla/sessions"
	"github.com/hjson/hjson-go/v4"
	"golang.org/x/crypto/bcrypt"
)

var version = "v0.10.x"

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

	flag.StringVar(&configFilename, "config", "", "config file name")
	flag.StringVar(&setClientID, "client-id", "", "set client id")
	flag.StringVar(&setClientSecret, "client-secret", "", "set client secret")
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
		slog.Info(fmt.Sprintf("Starting Auth Server %s built with %s", version, runtime.Version()))
	}

	// Set defaults
	serverSettings = settings.NewDefault(setPort)

	settingsFilename = fileutil.ProbeSettingsFilename(configFilename)

	if fileutil.FileExists(settingsFilename) {
		slog.Info(fmt.Sprintf("Loading settings from %s", settingsFilename))
		if bytes, err := os.ReadFile(settingsFilename); err == nil {
			options := hjson.DefaultDecoderOptions()
			options.DisallowUnknownFields = true
			options.DisallowDuplicateKeys = true
			if err := hjson.UnmarshalWithOptions(bytes, serverSettings, options); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		} else {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	if serverSettings.Key == "" {
		slog.Info(fmt.Sprintf("Generating %d bit RSA key with ID %q", keySize, keyID))
		if err := serverSettings.GenerateSigningKey(keySize, keyID); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if err := serverSettings.LoadKeys(filepath.Dir(settingsFilename)); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	if serverSettings.LoginTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LoginTemplate, "@"))
		slog.Info(fmt.Sprintf("Loading login form template from %s", filename))
		err = server.LoadLoginTemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.LogoutTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.LogoutTemplate, "@"))
		slog.Info(fmt.Sprintf("Loading logout template from %s", filename))
		err = server.LoadLogoutTemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.Setup2FATemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.Setup2FATemplate, "@"))
		slog.Info(fmt.Sprintf("Loading setup 2FA template from %s", filename))
		err = server.LoadSetup2FATemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.ResetPasswordTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.ResetPasswordTemplate, "@"))
		slog.Info(fmt.Sprintf("Loading password reset template from %s", filename))
		err = server.LoadResetPasswdTemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.ChangePasswordTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.ChangePasswordTemplate, "@"))
		slog.Info(fmt.Sprintf("Loading change password template from %s", filename))
		err = server.LoadChangePasswdTemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if serverSettings.PasswordResetMailTemplate != "" {
		var filename = filepath.Join(filepath.Dir(settingsFilename), strings.TrimPrefix(serverSettings.PasswordResetMailTemplate, "@"))
		slog.Info(fmt.Sprintf("Loading password reset mail template from %s", filename))
		err = server.LoadPasswordResetMailTemplate(filename)
		if err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	}

	if setClientID != "" {
		if serverSettings.Clients == nil {
			serverSettings.Clients = map[string]clients.Client{}
		}
		var client = serverSettings.Clients[setClientID]
		if setClientSecret != "" {
			if secretHash, err := bcrypt.GenerateFromPassword([]byte(setClientSecret), 5); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			} else {
				client.SecretHash = string(secretHash)
			}
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
				slog.Error(err.Error())
				os.Exit(1)
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
			slog.Error("missing password")
			os.Exit(1)
		}
		if generateTOTPSecret {
			if kw, err := otpauth.NewKeyWrapper(serverSettings.Issuer, setUserID, totpAlgorithm, "", totpDigits); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
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
		slog.Info(fmt.Sprintf("Saving settings to %s", settingsFilename))
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
			slog.Error(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	var scope = strings.TrimSpace(oauth2.OIDCDefaultScope + " " + serverSettings.CustomScope)

	tokenCreator, err = oauth2.NewTokenCreator(
		serverSettings.PrivateKey(),
		serverSettings.KeyID(),
		serverSettings.Issuer,
		scope,
		serverSettings.Defaults,
		serverSettings.CustomAccessTokenClaims,
		serverSettings.CustomIDTokenClaims,
		serverSettings.Roles,
	)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
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
		slog.Error(err.Error())
		os.Exit(1)
	}
	var sessionManager = session.NewManager(sessionStore, serverSettings.SessionName, serverSettings.SessionLifetime)

	var dbs = make(map[string]*sql.DB)

	var users = maputil.LowerKeys(serverSettings.Users)

	if serverSettings.PeopleStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.PeopleStore.URI) {
			if peopleStore, err = people.NewSqlStore(users, dbs, serverSettings.PeopleStore); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		} else if strings.HasPrefix(serverSettings.PeopleStore.URI, "ldap:") || strings.HasPrefix(serverSettings.PeopleStore.URI, "ldaps:") {
			if peopleStore, err = people.NewLdapStore(users, serverSettings.PeopleStore); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		} else {
			slog.Error(fmt.Sprintf("unsupported or empty people_store.uri: %s", serverSettings.PeopleStore.URI))
			os.Exit(1)
		}
	} else {
		peopleStore = people.NewInMemoryStore(users)
	}

	if serverSettings.ClientStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.ClientStore.URI) {
			if clientStore, err = clients.NewSqlStore(serverSettings.Clients, dbs, serverSettings.ClientStore); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		} else {
			slog.Error(fmt.Sprintf("unsupported or empty client_store.uri: %s", serverSettings.ClientStore.URI))
			os.Exit(1)
		}
	} else {
		clientStore = clients.NewInMemoryStore(serverSettings.Clients)
	}

	if serverSettings.EnableTokenRevocation {
		if serverSettings.RevocationStore == nil {
			slog.Error("revocation_store.uri must be specified to enable token revocation")
			os.Exit(1)
		}
		if !sqlutil.IsDatabaseURI(serverSettings.RevocationStore.URI) {
			slog.Error(fmt.Sprintf("unsupported or empty revocation_store.uri: %s", serverSettings.RevocationStore.URI))
			os.Exit(1)
		}
		if revocationStore, err = revocation.NewSqlStore(dbs, serverSettings.RevocationStore); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}
	} else {
		revocationStore = revocation.NewNoopStore()
	}

	if serverSettings.OTPAuthStore != nil {
		if sqlutil.IsDatabaseURI(serverSettings.OTPAuthStore.URI) {
			if otpauthStore, err = otpauth.NewSqlStore(users, dbs, serverSettings.OTPAuthStore); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			}
		} else {
			slog.Error(fmt.Sprintf("unsupported or empty otpauth_store.uri: %s", serverSettings.ClientStore.URI))
			os.Exit(1)
		}
	} else {
		otpauthStore = otpauth.NewInMemoryStore(users)
	}

	var mailer mail.Mailer

	if serverSettings.Mail != nil {
		if strings.HasPrefix(serverSettings.Mail.ServerURI, "smtp:") || strings.HasPrefix(serverSettings.Mail.ServerURI, "smtps:") {
			if m, err := mail.NewMailer(serverSettings.Mail); err != nil {
				slog.Error(err.Error())
				os.Exit(1)
			} else {
				mailer = m
			}
		} else {
			slog.Error(fmt.Sprintf("unsupported or empty mail.server_uri: %s", serverSettings.Mail.ServerURI))
			os.Exit(1)
		}
	}

	var passwordResetEnabled = mailer != nil && !peopleStore.ReadOnly()

	http.Handle(basePath+"/{$}", server.IndexHandler(basePath, serverSettings, sessionManager, clientStore, scope, version, serverSettings.CustomKeySetURI))
	http.Handle(basePath+"/login", server.LoginHandler(basePath, sessionManager, peopleStore, clientStore, otpauthStore, serverSettings.Issuer, passwordResetEnabled))
	http.Handle(basePath+"/logout", server.LogoutHandler(basePath, serverSettings, sessionManager, clientStore))
	http.Handle(basePath+"/health", server.HealthHandler(peopleStore))
	http.Handle(basePath+"/info", server.InfoHandler(version, runtime.Version()))

	if customKeySetURI := strings.TrimSpace(serverSettings.CustomKeySetURI); customKeySetURI != "" {
		if !(strings.HasPrefix(customKeySetURI, "http://") || strings.HasPrefix(customKeySetURI, "https://")) {
			http.Handle(basePath+"/"+strings.Trim(customKeySetURI, "/"), oauth2.JwksHandler(serverSettings.KeySetProvider()))
		} else {
			http.Handle(basePath+"/.well-known/keys", oauth2.JwksHandler(serverSettings.KeySetProvider()))
		}
	} else {
		http.Handle(basePath+"/.well-known/keys", oauth2.JwksHandler(serverSettings.KeySetProvider()))
	}
	http.Handle(basePath+"/token", oauth2.TokenHandler(tokenCreator, peopleStore, clientStore, revocationStore, scope))
	http.Handle(basePath+"/authorize", oauth2.AuthorizeHandler(serverSettings.Issuer, basePath, tokenCreator, sessionManager, peopleStore, clientStore, scope))
	http.Handle(basePath+"/.well-known/openid-configuration", oauth2.DiscoveryDocumentHandler(serverSettings.Issuer, scope, serverSettings.CustomKeySetURI, serverSettings.EnableTokenRevocation))
	http.Handle(basePath+"/userinfo", middleware.RequireJWT(oauth2.UserinfoHandler(peopleStore, serverSettings.CustomUserinfoClaims, serverSettings.Roles), accessTokenValidator, serverSettings.Issuer))

	http.Handle(basePath+"/setup-2fa", server.Setup2FAHandler(sessionManager, clientStore, otpauthStore, basePath, version, serverSettings.Issuer))

	if passwordResetEnabled {
		http.Handle(basePath+"/resetpasswd", server.ResetPasswdHandler(peopleStore, clientStore, mailer, tokenCreator, serverSettings.Issuer, basePath, version))
		http.Handle(basePath+"/chpasswd/{token}", server.ChangePasswdHandler(peopleStore, tokenCreator, revocationStore, serverSettings.Issuer, basePath, version))
	}

	if serverSettings.EnableTokenRevocation {
		http.Handle(basePath+"/revoke", oauth2.RevokeHandler(tokenCreator, clientStore, revocationStore))
	}

	if !serverSettings.DisableAPI {
		// ----- People API -----
		http.Handle(basePath+"/api/v1/people/{user_id}", middleware.RequireAuthN(api.LookupPersonHandler(peopleStore, nil, serverSettings.Roles), accessTokenValidator, peopleStore, serverSettings.Issuer))
		if !peopleStore.ReadOnly() {
			http.Handle("PUT "+basePath+"/api/v1/people/{user_id}", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.PutPersonHandler(peopleStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))
			http.Handle(basePath+"/api/v1/people/{user_id}/password", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.ChangePasswordHandler(peopleStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))
		}

		// ----- Custom People API

		for customPath, customAPI := range serverSettings.CustomPeopleAPI {
			var handler = api.LookupPersonHandler(peopleStore, &customAPI, serverSettings.Roles)
			if customAPI.RequireAuthN {
				handler = middleware.RequireAuthN(handler, accessTokenValidator, peopleStore, serverSettings.Issuer)
			}
			http.Handle("GET "+basePath+"/"+strings.Trim(customPath, "/ ")+"/{user_id}", handler)
			http.Handle("OPTIONS "+basePath+"/"+strings.Trim(customPath, "/ ")+"/{user_id}", handler)
		}

		// ----- OTPAuth API -----
		http.Handle(basePath+"/api/v1/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.LookupOTPAuthHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))
		http.Handle("POST "+basePath+"/api/v1/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.ValidateOTPCodeHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))
		http.Handle("PUT "+basePath+"/api/v1/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.PutOTPAuthHandler(otpauthStore, serverSettings.Issuer), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))
		http.Handle("DELETE "+basePath+"/api/v1/people/{user_id}/otpauth", middleware.RequireAuthN(middleware.RequireSelfOrRole(api.ResetOTPAuthHandler(otpauthStore), peopleStore, serverSettings.Roles, serverSettings.AdministratorRole), accessTokenValidator, peopleStore, serverSettings.Issuer))

		// ----- Clients -----
		http.Handle(basePath+"/api/v1/clients/{client_id}", middleware.RequireAuthN(api.LookupClientHandler(clientStore), accessTokenValidator, peopleStore, serverSettings.Issuer))
	}

	http.Handle("/", middleware.Log(http.FileServer(http.FS(assets.StaticFiles))))

	slog.Info(fmt.Sprintf("Listening on http://localhost:%d%s/", serverSettings.Port, basePath))
	err = http.ListenAndServe(fmt.Sprintf(":%d", serverSettings.Port), nil)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
