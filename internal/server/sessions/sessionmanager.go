package sessions

import (
	"net/http"
	"strings"
	"time"

	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/gorilla/sessions"
)

type SessionInfo struct {
	UserID     string
	CreatedAt  time.Time
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type SessionManager interface {
	CheckSession(r *http.Request, client clients.Client) (string, bool, bool)
	CreateSession(r *http.Request, w http.ResponseWriter, client clients.Client, userID string, verified bool) error
	VerifySession(r *http.Request, w http.ResponseWriter, client clients.Client) error
	GetSessionInfo(s *SessionInfo, r *http.Request, client clients.Client)
	EndSession(r *http.Request, w http.ResponseWriter, client clients.Client) error
}

type sessionManager struct {
	sessionStore sessions.Store
	realms       realms.Realms
}

func NewSessionManager(sessionStore sessions.Store, realms realms.Realms) SessionManager {
	return &sessionManager{
		sessionStore: sessionStore,
		realms:       realms,
	}
}

func (e sessionManager) CheckSession(r *http.Request, client clients.Client) (string, bool, bool) {
	var session, _ = e.sessionStore.Get(r, e.realms[strings.ToLower(client.Realm)].SessionName)

	if session.Values["uid"] == nil {
		return "", false, false
	}

	var createdAt, verifiedAt time.Time

	if sct, valid := session.Values["sct"].(int64); valid {
		createdAt = time.Unix(sct, 0)
	}

	if vfd, valid := session.Values["vfd"].(int64); valid {
		verifiedAt = time.Unix(vfd, 0)
	}

	if createdAt.Add(time.Duration(e.realms[strings.ToLower(client.Realm)].SessionTTL) * time.Second).After(time.Now()) {
		return session.Values["uid"].(string), true, !verifiedAt.Before(createdAt)
	}

	return "", false, false
}

func (e sessionManager) CreateSession(r *http.Request, w http.ResponseWriter, client clients.Client, userID string, verified bool) error {
	var session, _ = e.sessionStore.Get(r, e.realms[strings.ToLower(client.Realm)].SessionName)
	session.Values["uid"] = userID
	session.Values["sct"] = time.Now().Unix()
	if verified {
		session.Values["vfd"] = session.Values["sct"]
	} else {
		session.Values["vfd"] = 0
	}
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

func (e sessionManager) VerifySession(r *http.Request, w http.ResponseWriter, client clients.Client) error {
	var session, _ = e.sessionStore.Get(r, e.realms[strings.ToLower(client.Realm)].SessionName)
	session.Values["vfd"] = time.Now().Unix()
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

func (e sessionManager) GetSessionInfo(s *SessionInfo, r *http.Request, client clients.Client) {
	var session, _ = e.sessionStore.Get(r, e.realms[strings.ToLower(client.Realm)].SessionName)
	if session.IsNew || session.Values["uid"] == nil {
		return
	}
	var createdAt, verifiedAt time.Time

	if sct, valid := session.Values["sct"].(int64); valid {
		createdAt = time.Unix(sct, 0)
	}

	if vfd, valid := session.Values["vfd"].(int64); valid {
		verifiedAt = time.Unix(vfd, 0)
	}

	s.UserID = session.Values["uid"].(string)
	s.CreatedAt = createdAt
	s.VerifiedAt = verifiedAt
	s.ExpiresAt = createdAt.Add(time.Duration(e.realms[strings.ToLower(client.Realm)].SessionTTL) * time.Second)
}

func (e sessionManager) EndSession(r *http.Request, w http.ResponseWriter, client clients.Client) error {
	var session, _ = e.sessionStore.Get(r, e.realms[strings.ToLower(client.Realm)].SessionName)
	if !session.IsNew {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			return err
		}
	}
	return nil
}
