package people

import (
	"log"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type AuthenticPerson struct {
	Person
	PasswordHash string `json:"password_hash"`
	OTPAuthURI   string `json:"otpauth_uri,omitempty"`
}

type inMemoryStore struct {
	users map[string]AuthenticPerson
}

func NewInMemoryStore(users map[string]AuthenticPerson) Store {
	return &inMemoryStore{
		users: users,
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
