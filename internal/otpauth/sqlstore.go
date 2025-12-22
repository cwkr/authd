package otpauth

import (
	"database/sql"
	"strings"

	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/sqlutil"
	"github.com/pquerna/otp"
)

type sqlStore struct {
	inMemoryStore
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewSqlStore(users map[string]people.AuthenticPerson, dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbconn, err := sqlutil.GetDB(dbs, settings.URI); err != nil {
		return nil, err
	} else {
		return &sqlStore{
			inMemoryStore: inMemoryStore{users: users},
			dbconn:        dbconn,
			settings:      settings,
		}, nil
	}
}

func (e sqlStore) Lookup(userID string) (*KeyWrapper, error) {
	var authenticPerson, found = e.users[strings.ToLower(userID)]
	if !found || !strings.HasPrefix(authenticPerson.OTPKeyURI, PrefixOTPAuth) {
		return nil, ErrNotFound
	}
	if k, err := otp.NewKeyFromURL(authenticPerson.OTPKeyURI); err != nil {
		return nil, err
	} else {
		return &KeyWrapper{key: k}, nil
	}
}

func (e sqlStore) Put(userID string, keyWrapper KeyWrapper) error {
	var user = e.users[strings.ToLower(userID)]
	user.OTPKeyURI = keyWrapper.URI()
	e.users[strings.ToLower(userID)] = user
	return nil
}

func (e sqlStore) Ping() error {
	return e.dbconn.Ping()
}

func (e sqlStore) ReadOnly() bool {
	return false
}
