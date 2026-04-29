package clients

import (
	"fmt"
	"strings"

	"github.com/cwkr/authd/internal/maputil"
	"github.com/cwkr/authd/passwordhash"
)

type inMemoryStore map[string]Client

func NewInMemoryStore(clientMap map[string]Client) Store {
	return inMemoryStore(maputil.LowerKeys(clientMap))
}

func (i inMemoryStore) compareSecret(client *Client, clientSecret string) (*Client, error) {
	if clientSecret == "" {
		return nil, ErrClientSecretRequired
	}
	if client.SecretHash == "" {
		return nil, ErrClientNoSecret
	}
	if err := passwordhash.Check(client.SecretHash, clientSecret); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientSecretMismatch, err)
	}
	return client, nil
}

func (i inMemoryStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	if client, err := i.Lookup(clientID); err != nil {
		return nil, err
	} else {
		return i.compareSecret(client, clientSecret)
	}
}

func (i inMemoryStore) Lookup(clientID string) (*Client, error) {
	if client, clientExists := i[strings.ToLower(clientID)]; clientExists {
		return &client, nil
	}
	return nil, ErrClientNotFound
}

func (i inMemoryStore) List() ([]string, error) {
	var clientIDs []string
	for clientID, _ := range i {
		clientIDs = append(clientIDs, clientID)
	}
	return clientIDs, nil
}

func (i inMemoryStore) Ping() error {
	return nil
}
