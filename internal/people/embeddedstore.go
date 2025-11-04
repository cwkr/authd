package people

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type AuthenticPerson struct {
	Person
	PasswordHash string `json:"password_hash"`
}

type inMemoryStore struct {
	sessionStore sessions.Store
	users        map[string]AuthenticPerson
	sessionTTL   int64
}

func NewInMemoryStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionTTL int64) Store {
	return &inMemoryStore{
		sessionStore: sessionStore,
		users:        users,
		sessionTTL:   sessionTTL,
	}
}

func (e inMemoryStore) Authenticate(userID, password string) (string, error) {
	var lowercaseUserID = strings.ToLower(userID)
	var authenticPerson, foundUser = e.users[strings.ToLower(lowercaseUserID)]

	if foundUser {
		if err := bcrypt.CompareHashAndPassword([]byte(authenticPerson.PasswordHash), []byte(password)); err != nil {
			log.Printf("!!! password comparison failed: %v", err)
		} else {
			return lowercaseUserID, nil
		}
	}

	return "", ErrAuthenticationFailed
}

func (e inMemoryStore) IsSessionActive(r *http.Request, sessionName string) (string, bool) {
	var session, _ = e.sessionStore.Get(r, sessionName)

	var uid, sct = session.Values["uid"], session.Values["sct"]

	if uid != nil && sct != nil && time.Unix(sct.(int64), 0).Add(time.Duration(e.sessionTTL)*time.Second).After(time.Now()) {
		return uid.(string), true
	}

	return "", false
}

func (e inMemoryStore) SaveSession(r *http.Request, w http.ResponseWriter, authTime time.Time, userID, sessionName string) error {
	var session, _ = e.sessionStore.Get(r, sessionName)
	session.Values["uid"] = userID
	session.Values["sct"] = authTime.Unix()
	if err := session.Save(r, w); err != nil {
		return err
	}
	return nil
}

func (e inMemoryStore) Lookup(userID string) (*Person, error) {
	var authenticPerson, found = e.users[strings.ToLower(userID)]

	if found {
		return &authenticPerson.Person, nil
	}

	return nil, ErrPersonNotFound
}

func (e inMemoryStore) Ping() error {
	return nil
}

func (e inMemoryStore) ReadOnly() bool {
	return true
}

func (e inMemoryStore) Put(userID string, person *Person) error {
	return ErrReadOnly
}

func (e inMemoryStore) ChangePassword(userID, password string) error {
	return ErrReadOnly
}
