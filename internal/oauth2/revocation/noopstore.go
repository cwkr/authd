package revocation

import (
	"fmt"
	"log/slog"
	"time"
)

type noopStore struct {
}

func NewNoopStore() Store {
	return &noopStore{}
}

func (s *noopStore) Put(tokenID string, expirationTime time.Time) error {
	slog.Info(fmt.Sprintf("token %s revoked", tokenID))
	return nil
}

func (s *noopStore) Lookup(tokenID string) (*RevokedToken, error) {
	return nil, nil
}

func (s *noopStore) Ping() error {
	return nil
}
