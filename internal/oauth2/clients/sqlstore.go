package clients

import (
	"database/sql"
	"errors"
	"log"
	"slices"
	"strings"

	"github.com/blockloop/scan/v2"
	"github.com/cwkr/authd/internal/maputil"
	"github.com/cwkr/authd/internal/sqlutil"
)

type sqlClient struct {
	RedirectURIPattern         sql.NullString `db:"redirect_uri_pattern"`
	SecretHash                 sql.NullString `db:"secret_hash"`
	PresetID                   sql.NullString `db:"preset"`
	DisableImplicit            sql.NullBool   `db:"disable_implicit"`
	EnableRefreshTokenRotation sql.NullBool   `db:"enable_refresh_token_rotation"`
}

func (s *sqlClient) Client() *Client {
	return &Client{
		RedirectURIPattern:         s.RedirectURIPattern.String,
		SecretHash:                 s.SecretHash.String,
		PresetID:                   s.PresetID.String,
		DisableImplicit:            s.DisableImplicit.Bool,
		EnableRefreshTokenRotation: s.EnableRefreshTokenRotation.Bool,
	}
}

type sqlStore struct {
	inMemoryStore
	dbconn   *sql.DB
	settings *StoreSettings
}

func NewSqlStore(clientMap map[string]Client, dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbconn, err := sqlutil.GetDB(dbs, settings.URI); err != nil {
		return nil, err
	} else {
		return &sqlStore{
			inMemoryStore: maputil.LowerKeys(clientMap),
			dbconn:        dbconn,
			settings:      settings,
		}, nil
	}
}

func (s *sqlStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	if client, err := s.inMemoryStore.Authenticate(clientID, clientSecret); err == nil {
		return client, nil
	}
	if client, err := s.Lookup(clientID); err != nil {
		return nil, err
	} else {
		return s.inMemoryStore.compareSecret(client, clientSecret)
	}
}

func (s *sqlStore) Lookup(clientID string) (*Client, error) {
	if c, err := s.inMemoryStore.Lookup(clientID); err == nil {
		return c, nil
	}

	if strings.TrimSpace(s.settings.Query) == "" {
		log.Print("!!! SQL query empty")
		return nil, nil
	}

	var client sqlClient
	log.Printf("SQL: %s; -- %s", s.settings.Query, clientID)
	// SELECT redirect_uri_pattern, secret_hash, preset, disable_implicit, enable_refresh_token_rotation
	// FROM clients WHERE lower(client_id) = lower($1)
	if rows, err := s.dbconn.Query(s.settings.Query, clientID); err == nil {
		if err := scan.RowStrict(&client, rows); err != nil {
			log.Printf("!!! Scan client failed: %v", err)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrClientNotFound
			}
			return nil, err
		}
	} else {
		log.Printf("!!! Query for client failed: %v", err)
		return nil, err
	}
	log.Printf("%#v", client)
	return client.Client(), nil
}

func (s *sqlStore) List() ([]string, error) {
	var allClientIDs []string
	if c, err := s.inMemoryStore.List(); err == nil {
		allClientIDs = c
	} else {
		return nil, err
	}

	var sqlClientIDs []string

	log.Printf("SQL: %s", s.settings.QuerySessionNames)
	// SELECT client_id FROM sqlClientIDs
	if rows, err := s.dbconn.Query(s.settings.QuerySessionNames); err == nil {
		if err := scan.RowsStrict(&sqlClientIDs, rows); err != nil {
			log.Printf("!!! Scan session_names failed: %v", err)
			return nil, err
		}
	} else {
		log.Printf("!!! Query for session_names failed: %v", err)
		return nil, err
	}

	for _, client := range sqlClientIDs {
		if !slices.Contains(allClientIDs, client) {
			allClientIDs = append(allClientIDs, client)
		}
	}
	return allClientIDs, nil
}

func (s *sqlStore) Ping() error {
	return s.dbconn.Ping()
}
