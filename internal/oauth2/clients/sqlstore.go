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
	AccessTokenLifetime        sql.NullInt32  `db:"access_token_lifetime"`
	Audience                   pq.StringArray `db:"audience"`
	AuthCodeLifetime           sql.NullInt32  `db:"auth_code_lifetime"`
	DisableImplicit            sql.NullBool   `db:"disable_implicit"`
	EnableRefreshTokenRotation sql.NullBool   `db:"enable_refresh_token_rotation"`
	IDTokenLifetime            sql.NullInt32  `db:"id_token_lifetime"`
	RedirectURIs               pq.StringArray `db:"redirect_uris"`
	RefreshTokenLifetime       sql.NullInt32  `db:"refresh_token_lifetime"`
	Require2FA                 sql.NullBool   `db:"require_2fa"`
	SigningAlgorithm           sql.NullString `db:"signing_algorithm"`
	SecretHash                 sql.NullString `db:"secret_hash"`
}

func (p postgresClient) Client() *Client {
	return &Client{
		AccessTokenLifetime:        int(p.AccessTokenLifetime.Int32),
		Audience:                   p.Audience,
		AuthCodeLifetime:           int(p.AuthCodeLifetime.Int32),
		DisableImplicit:            p.DisableImplicit.Bool,
		EnableRefreshTokenRotation: p.EnableRefreshTokenRotation.Bool,
		IDTokenLifetime:            int(p.IDTokenLifetime.Int32),
		RedirectURIs:               p.RedirectURIs,
		RefreshTokenLifetime:       int(p.RefreshTokenLifetime.Int32),
		Require2FA:                 p.Require2FA.Bool,
		SigningAlgorithm:           p.SigningAlgorithm.String,
		SecretHash:                 p.SecretHash.String,
	}
}

type genericClient struct {
	AccessTokenLifetime        sql.NullInt32  `db:"access_token_lifetime"`
	Audience                   sql.NullString `db:"audience"`
	AuthCodeLifetime           sql.NullInt32  `db:"auth_code_lifetime"`
	DisableImplicit            sql.NullBool   `db:"disable_implicit"`
	EnableRefreshTokenRotation sql.NullBool   `db:"enable_refresh_token_rotation"`
	IDTokenLifetime            sql.NullInt32  `db:"id_token_lifetime"`
	RedirectURIs               sql.NullString `db:"redirect_uris"`
	RefreshTokenLifetime       sql.NullInt32  `db:"refresh_token_lifetime"`
	Require2FA                 sql.NullBool   `db:"require_2fa"`
	SigningAlgorithm           sql.NullString `db:"signing_algorithm"`
	SecretHash                 sql.NullString `db:"secret_hash"`
}

func (p genericClient) Client() *Client {
	return &Client{
		AccessTokenLifetime:        int(p.AccessTokenLifetime.Int32),
		Audience:                   strings.Split(p.Audience.String, ","),
		AuthCodeLifetime:           int(p.AuthCodeLifetime.Int32),
		DisableImplicit:            p.DisableImplicit.Bool,
		EnableRefreshTokenRotation: p.EnableRefreshTokenRotation.Bool,
		IDTokenLifetime:            int(p.IDTokenLifetime.Int32),
		RefreshTokenLifetime:       int(p.RefreshTokenLifetime.Int32),
		RedirectURIs:               strings.Split(p.RedirectURIs.String, ","),
		Require2FA:                 p.Require2FA.Bool,
		SigningAlgorithm:           p.SigningAlgorithm.String,
		SecretHash:                 p.SecretHash.String,
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
	// SELECT access_token_lifetime, audience, auth_code_lifetime, disable_implicit, enable_refresh_token_rotation,
	// id_token_lifetime, redirect_uris, refresh_token_lifetime, require_2fa, signing_algorithm, secret_hash
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
