package cosign

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMapKeyProvider_GetPublicKey(t *testing.T) {
	const (
		kid1 = "kid1"
		key1 = "1234567890"

		kid2 = "kid2"
		key2 = "0987654321"

		fakeKid = "fakeKid"
	)

	provider := MapKeyProvider{}

	provider[kid1] = key1
	provider[kid2] = key2

	t.Run("requesting valid key1 returns result", func(t *testing.T) {
		req := require.New(t)

		val, err := provider.GetPublicKey(kid1)

		req.NoError(err)
		req.Equal(key1, val)
	})

	t.Run("requesting valid key2 returns result", func(t *testing.T) {
		req := require.New(t)

		val, err := provider.GetPublicKey(kid2)

		req.NoError(err)
		req.Equal(key2, val)
	})

	t.Run("requesting invalid key returns error", func(t *testing.T) {
		req := require.New(t)

		val, err := provider.GetPublicKey(fakeKid)

		req.Error(err)
		req.Nil(val)
	})
}
