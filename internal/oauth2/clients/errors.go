package clients

import "errors"

var (
	ErrClientNotFound       = errors.New("client not found")
	ErrClientSecretMismatch = errors.New("client secret is not the given secret")
	ErrClientNoSecret       = errors.New("client has no secret")
	ErrClientSecretRequired = errors.New("client secret required")
)
