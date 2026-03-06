package otpauth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cwkr/authd/internal/people"
	"github.com/cwkr/authd/internal/sqlutil"
	"github.com/cwkr/authd/internal/stringutil"
	"github.com/pquerna/otp"
	"golang.org/x/crypto/bcrypt"
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
	if c, err := e.inMemoryStore.Lookup(userID); err == nil {
		return c, nil
	}

	if strings.TrimSpace(e.settings.Query) == "" {
		slog.Error("SQL query empty")
		return nil, nil
	}

	var otpauthURI sql.NullString
	slog.Info(fmt.Sprintf("SQL: %s; -- %s", e.settings.Query, userID))
	// SELECT otpauth_uri FROM people WHERE lower(user_id) = lower($1)
	if row := e.dbconn.QueryRow(e.settings.Query, userID); row.Err() == nil {
		if err := row.Scan(&otpauthURI); err != nil {
			slog.Error(fmt.Sprintf("scan otpauth credentials failed: %s", err.Error()))
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	} else {
		slog.Error(fmt.Sprintf("query for otpauth credentials failed: %s", row.Err().Error()))
		return nil, row.Err()
	}
	if !otpauthURI.Valid || strings.TrimSpace(otpauthURI.String) == "" {
		return nil, ErrNotFound
	}
	if k, err := otp.NewKeyFromURL(otpauthURI.String); err != nil {
		return nil, err
	} else {
		return &KeyWrapper{key: k}, nil
	}
}

func (e sqlStore) Put(userID string, keyWrapper KeyWrapper) (string, error) {
	var recoveryCode = GenerateRecoveryCode()
	if recoveryCodeHash, err := bcrypt.GenerateFromPassword([]byte(stringutil.StripSpaces(recoveryCode)), 11); err != nil {
		return "", err
	} else {
		// UPDATE people SET otpauth_uri = $2, recovery_code_hash = $3, last_modified = now() WHERE lower(user_id) = lower($1)
		slog.Info(fmt.Sprintf("SQL: %s; -- %s", e.settings.Update, userID))
		if _, err := e.dbconn.Exec(e.settings.Update, userID, keyWrapper.URI(), recoveryCodeHash); err != nil {
			return "", err
		}
		return recoveryCode, nil
	}
}

func (e sqlStore) VerifyRecoveryCode(userID, recoveryCode string) bool {
	// SELECT recovery_code_hash FROM people WHERE lower(user_id) = lower($1)
	slog.Info(fmt.Sprintf("SQL: %s; -- %s", e.settings.RecoveryCodeQuery, userID))
	var row = e.dbconn.QueryRow(e.settings.RecoveryCodeQuery, userID)
	var recoveryCodeHash string
	if err := row.Scan(&recoveryCodeHash); err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(recoveryCodeHash), []byte(recoveryCode)); err != nil {
			slog.Error(fmt.Sprintf("recovery code comparison failed: %s", err.Error()))
		} else {
			return true
		}
	} else {
		slog.Error(fmt.Sprintf("query for recovery code failed: %s", err.Error()))
	}
	return false
}

func (e sqlStore) Delete(userID string) error {
	// UPDATE people SET otpauth_uri = null, recovery_code_hash = null, last_modified = now() WHERE lower(user_id) = lower($1)
	slog.Info(fmt.Sprintf("SQL: %s; -- %s", e.settings.Delete, userID))
	if _, err := e.dbconn.Exec(e.settings.Delete, userID); err != nil {
		return err
	}
	return nil
}

func (e sqlStore) Ping() error {
	return e.dbconn.Ping()
}

func (e sqlStore) ReadOnly() bool {
	return false
}
