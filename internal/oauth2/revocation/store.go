package revocation

import (
	"time"
)

type RevokedToken struct {
	RevocationTime time.Time `db:"rvt"`
	ExpirationTime time.Time `db:"exp"`
}

type Store interface {
	Put(tokenID string, expirationTime time.Time) error
	Lookup(tokenID string) (*RevokedToken, error)
	Ping() error
}
