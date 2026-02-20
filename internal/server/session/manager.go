package session

import (
	"net/http"
	"time"

	"github.com/cwkr/authd/internal/oauth2/clients"
	"github.com/gorilla/sessions"
)

type Current struct {
	UserID     string
	CreatedAt  time.Time
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type Manager interface {
	CheckSession(r *http.Request, client clients.Client) (string, bool, bool)
	CreateSession(r *http.Request, w http.ResponseWriter, client clients.Client, userID string, verified bool) error
	VerifySession(r *http.Request, w http.ResponseWriter, client clients.Client) error
	GetCurrentSession(s *Current, r *http.Request, client clients.Client)
	EndSession(r *http.Request, w http.ResponseWriter, client clients.Client) error
}

type manager struct {
	sessionStore    sessions.Store
	sessionName     string
	sessionLifetime int
}

func NewManager(sessionStore sessions.Store, sessionName string, sessionLifetime int) Manager {
	return &manager{
		sessionStore:    sessionStore,
		sessionName:     sessionName,
		sessionLifetime: sessionLifetime,
	}
}

func (m manager) CheckSession(r *http.Request, client clients.Client) (string, bool, bool) {
	var session, _ = m.sessionStore.Get(r, m.sessionName)

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

	if createdAt.Add(time.Duration(m.sessionLifetime) * time.Second).After(time.Now()) {
		return session.Values["uid"].(string), true, !verifiedAt.Before(createdAt)
	}

	return "", false, false
}

func (m manager) CreateSession(r *http.Request, w http.ResponseWriter, client clients.Client, userID string, verified bool) error {
	var session, _ = m.sessionStore.Get(r, m.sessionName)
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

func (m manager) VerifySession(r *http.Request, w http.ResponseWriter, client clients.Client) error {
	var session, _ = m.sessionStore.Get(r, m.sessionName)
	session.Values["vfd"] = time.Now().Unix()
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

func (m manager) GetCurrentSession(s *Current, r *http.Request, client clients.Client) {
	var session, _ = m.sessionStore.Get(r, m.sessionName)
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
	s.ExpiresAt = createdAt.Add(time.Duration(m.sessionLifetime) * time.Second)
}

func (m manager) EndSession(r *http.Request, w http.ResponseWriter, client clients.Client) error {
	var session, _ = m.sessionStore.Get(r, m.sessionName)
	if !session.IsNew {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			return err
		}
	}
	return nil
}
