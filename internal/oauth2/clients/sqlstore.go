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
	"github.com/lib/pq"
)

type sqlClient interface {
	Client() *Client
}

type postgresClient struct {
	SecretHash                 sql.NullString `db:"secret_hash"`
	DisableImplicit            sql.NullBool   `db:"disable_implicit"`
	EnableRefreshTokenRotation sql.NullBool   `db:"enable_refresh_token_rotation"`
	Require2FA                 sql.NullBool   `db:"require_2fa"`
	RedirectURIs               pq.StringArray `db:"redirect_uris"`
	Audience                   pq.StringArray `db:"audience"`
}

func (p postgresClient) Client() *Client {
	return &Client{
		SecretHash:                 p.SecretHash.String,
		DisableImplicit:            p.DisableImplicit.Bool,
		EnableRefreshTokenRotation: p.EnableRefreshTokenRotation.Bool,
		Require2FA:                 p.Require2FA.Bool,
		RedirectURIs:               p.RedirectURIs,
		Audience:                   p.Audience,
	}
}

type genericClient struct {
	SecretHash                 sql.NullString `db:"secret_hash"`
	DisableImplicit            sql.NullBool   `db:"disable_implicit"`
	EnableRefreshTokenRotation sql.NullBool   `db:"enable_refresh_token_rotation"`
	Require2FA                 sql.NullBool   `db:"require_2fa"`
	RedirectURIs               sql.NullString `db:"redirect_uris"`
	Audience                   sql.NullString `db:"audience"`
}

func (p genericClient) Client() *Client {
	return &Client{
		SecretHash:                 p.SecretHash.String,
		DisableImplicit:            p.DisableImplicit.Bool,
		EnableRefreshTokenRotation: p.EnableRefreshTokenRotation.Bool,
		Require2FA:                 p.Require2FA.Bool,
		RedirectURIs:               strings.Split(p.RedirectURIs.String, ","),
		Audience:                   strings.Split(p.Audience.String, ","),
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

	if strings.TrimSpace(s.settings.LookupQuery) == "" {
		log.Print("!!! SQL query empty")
		return nil, nil
	}

	var storedClient sqlClient
	if strings.HasPrefix(s.settings.URI, sqlutil.PrefixPostgres) {
		storedClient = &postgresClient{}
	} else {
		storedClient = &genericClient{}
	}
	log.Printf("SQL: %s; -- %s", s.settings.LookupQuery, clientID)
	// SELECT secret_hash, preset, disable_implicit, enable_refresh_token_rotation, redirect_uris, audience
	// FROM clients WHERE lower(client_id) = lower($1)
	if rows, err := s.dbconn.Query(s.settings.LookupQuery, clientID); err == nil {
		if err := scan.RowStrict(storedClient, rows); err != nil {
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
	log.Printf("%#v", storedClient)
	return storedClient.Client(), nil
}

func (s *sqlStore) List() ([]string, error) {
	var allClientIDs []string
	if c, err := s.inMemoryStore.List(); err == nil {
		allClientIDs = c
	} else {
		return nil, err
	}

	var sqlClientIDs []string

	log.Printf("SQL: %s", s.settings.ListQuery)
	// SELECT client_id FROM clients
	if rows, err := s.dbconn.Query(s.settings.ListQuery); err == nil {
		if err := scan.RowsStrict(&sqlClientIDs, rows); err != nil {
			log.Printf("!!! Scan client id list failed: %v", err)
			return nil, err
		}
	} else {
		log.Printf("!!! Query for client id list failed: %v", err)
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
