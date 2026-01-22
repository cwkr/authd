package otpauth

import (
	"errors"
	"strings"

	"github.com/cwkr/authd/internal/people"
	"github.com/pquerna/otp"
)

type inMemoryStore struct {
	users map[string]people.AuthenticPerson
}

func NewInMemoryStore(users map[string]people.AuthenticPerson) Store {
	return &inMemoryStore{
		users: users,
	}
}

func (e inMemoryStore) Lookup(userID string) (*KeyWrapper, error) {
	var authenticPerson, found = e.users[strings.ToLower(userID)]
	if !found || !strings.HasPrefix(authenticPerson.OTPAuthURI, PrefixOTPAuth) {
		return nil, ErrNotFound
	}
	if k, err := otp.NewKeyFromURL(authenticPerson.OTPAuthURI); err != nil {
		return nil, err
	} else {
		return &KeyWrapper{key: k}, nil
	}
}

func (e inMemoryStore) Put(userID string, keyWrapper KeyWrapper) (string, error) {
	return "", errors.ErrUnsupported
}

func (e inMemoryStore) VerifyRecoveryCode(userID, recoveryCode string) bool {
	return false
}

func (e inMemoryStore) Delete(userID string) error {
	return errors.ErrUnsupported
}

func (e inMemoryStore) Ping() error {
	return nil
}

func (e inMemoryStore) ReadOnly() bool {
	return true
}
