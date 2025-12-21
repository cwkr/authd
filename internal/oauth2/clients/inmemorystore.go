package clients

import (
	"strings"

	"github.com/cwkr/authd/internal/maputil"
	"golang.org/x/crypto/bcrypt"
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
	// bcrypt hash or plaintext
	if strings.HasPrefix(client.SecretHash, "$2") {
		if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
			return nil, err
		}
	} else if clientSecret != client.SecretHash {
		return nil, ErrClientSecretMismatch
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
