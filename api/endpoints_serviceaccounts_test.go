package api

import (
	"context"
	"testing"

	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchServiceAccount_InvalidRoleScopesShowsConflicts(t *testing.T) {
	ctx := context.Background()
	id := "d46f1f0d-299f-11ef-a8ac-2ea42f30fe31"

	mock := []mocksrv.Interaction{
		{
			Expect:   "PATCH /v1/serviceaccounts/" + id,
			MockCode: 400,
			MockBody: `{"errors":[{"code":60223,"message":"Invalid scopes. Check and make sure that you have selected only one role scope"}]}`,
		},
	}
	server := mocksrv.Mock(t, mock, nil)

	cl, err := NewClient(server.URL)
	require.NoError(t, err)

	patch := PatchServiceAccountByClientIDRequestBody{
		Scopes: []Scope{"platform-admin-role", "tenant-admin-role", "distributed-issuance"},
	}

	err = PatchServiceAccount(ctx, cl, id, patch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one scope containing \"role\"")
	assert.Contains(t, err.Error(), "platform-admin-role")
	assert.Contains(t, err.Error(), "tenant-admin-role")
	assert.NotContains(t, err.Error(), "distributed-issuance")
}
