package auth

import (
	"context"
	"errors"
)

// Authenticator is any credential verifier (local store, LDAP, OIDC…).
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
}

// Chain tries providers in order. A success returns immediately; invalid
// credentials move on to the next provider (so the always-on local store
// remains a working break-glass even when a directory rejects or is down).
// If nothing succeeds, the result is ErrInvalidCredentials unless every
// provider failed operationally, in which case the last such error surfaces.
type Chain []Authenticator

// Authenticate implements Authenticator over the chain.
func (c Chain) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	var lastOpErr error
	sawReject := false
	for _, p := range c {
		id, err := p.Authenticate(ctx, username, password)
		if err == nil {
			return id, nil
		}
		if errors.Is(err, ErrInvalidCredentials) {
			sawReject = true
			continue
		}
		lastOpErr = err
	}
	if sawReject || lastOpErr == nil {
		return nil, ErrInvalidCredentials
	}
	return nil, lastOpErr
}
