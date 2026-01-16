package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffToPatchServiceAccount(t *testing.T) {
	t.Run("no patch when owner is unset in desired state", func(t *testing.T) {
		existing := ServiceAccountDetails{Owner: uuid.MustParse("af8e8001-6e12-4010-a426-9e742d02f2cf")}
		desired := ServiceAccountDetails{Owner: uuid.UUID{}}

		patch, changed, err := DiffToPatchServiceAccount(existing, desired)
		require.NoError(t, err)
		assert.False(t, changed)
		assert.Equal(t, PatchServiceAccountByClientIDRequestBody{}, patch)
	})

	t.Run("error when owner is set in desired state", func(t *testing.T) {
		existing := ServiceAccountDetails{Owner: uuid.MustParse("af8e8001-6e12-4010-a426-9e742d02f2cf")}
		desired := ServiceAccountDetails{Owner: uuid.MustParse("b18e8001-6e12-4010-a426-9e742d02f2cf")}

		patch, changed, err := DiffToPatchServiceAccount(existing, desired)
		require.EqualError(t, err, "cannot change the 'owner' field on an existing service account")
		assert.False(t, changed)
		assert.Equal(t, PatchServiceAccountByClientIDRequestBody{}, patch)
	})
}
