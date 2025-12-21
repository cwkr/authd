package sessions

import (
	"net/http"
	"time"

	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/cwkr/authd/internal/oauth2/realms"
	"github.com/gorilla/sessions"
)

type SessionManager interface {
	IsSessionActive(r *http.Request, client clients.Client) (string, bool)
	SaveSession(r *http.Request, w http.ResponseWriter, authTime time.Time, client clients.Client, userID string) error
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

func (e sessionManager) IsSessionActive(r *http.Request, client clients.Client) (string, bool) {
	var session, _ = e.sessionStore.Get(r, e.realms[client.Realm].SessionName)

	var uid, sct = session.Values["uid"], session.Values["sct"]

	if uid != nil && sct != nil && time.Unix(sct.(int64), 0).Add(time.Duration(e.realms[client.Realm].SessionTTL)*time.Second).After(time.Now()) {
		return uid.(string), true
	}

	return "", false
}

func (e sessionManager) SaveSession(r *http.Request, w http.ResponseWriter, authTime time.Time, client clients.Client, userID string) error {
	var session, _ = e.sessionStore.Get(r, e.realms[client.Realm].SessionName)
	session.Values["uid"] = userID
	session.Values["sct"] = authTime.Unix()
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}
