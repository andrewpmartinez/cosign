package cosign

import (
	"crypto"
	"fmt"
)

type PublicKeyProvider interface {
	GetPublicKey(kid string) (crypto.PublicKey, error)
}

var _ PublicKeyProvider = (*MapKeyProvider)(nil)

type MapKeyProvider map[string]crypto.PublicKey

func (m MapKeyProvider) GetPublicKey(kid string) (crypto.PublicKey, error) {
	publicKey, ok := m[kid]

	if !ok {
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	}

	return publicKey, nil
}
