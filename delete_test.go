package main

import (
	"context"
	"testing"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/require"
)

func Test_deleteManifests_order(t *testing.T) {
	givenManifests := undent.Undent(`
		kind: ServiceAccount
		name: mael
		authenticationType: rsaKey
		credentialLifetime: 365
		enabled: true
		scopes:
		  - distributed-issuance
		---
		kind: WIMConfiguration
		name: mael
		clientAuthentication: {}
		clientAuthorization:
		  customClaimsAliases:
		    configuration: ""
		    allowAllPolicies: ""
		    allowedPolicies: ""
		cloudProviders: {}
		minTlsVersion: TLS13
		subCaProviderName: mael
		advancedSettings:
		  enableIssuanceAuditLog: true
	`)

	mock := []mocksrv.Interaction{
		{Expect: "GET /v1/distributedissuers/configurations", MockCode: 200, MockBody: `{"configurations": [` + sampleConfig + `]}`},
		{Expect: "DELETE /v1/distributedissuers/configurations/d867b700-9de6-11f0-b18d-1b1c0845fa26", MockCode: 204, MockBody: ""},
		{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[` + sampleSA + `]`},
		{Expect: "DELETE /v1/serviceaccounts/d46f1f0d-299f-11ef-a8ac-2ea42f30fe31", MockCode: 204, MockBody: ""},
	}

	err := runDeleteTest(t, givenManifests, mock, failOnNotFound)
	require.NoError(t, err)
}

func Test_deleteManifests_ignoreNotFound(t *testing.T) {
	givenManifests := undent.Undent(`
		kind: ServiceAccount
		name: missing-sa
	`)

	mock := []mocksrv.Interaction{
		{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[]`},
	}

	err := runDeleteTest(t, givenManifests, mock, ignoreNotFound)
	require.NoError(t, err)
}

func Test_deleteManifests_notFoundIsError(t *testing.T) {
	givenManifests := undent.Undent(`
		kind: ServiceAccount
		name: missing-sa
	`)

	mock := []mocksrv.Interaction{
		{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[]`},
	}

	err := runDeleteTest(t, givenManifests, mock, failOnNotFound)
	require.Error(t, err)
}

func Test_deleteManifests_continueOnNotFound(t *testing.T) {
	givenManifests := undent.Undent(`
		kind: WIMConfiguration
		name: mael
		serviceAccountNames: [missing-sa]
		subCaProviderName: mael
		---
		kind: ServiceAccount
		name: missing-sa
	`)

	mock := []mocksrv.Interaction{
		{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[]`},
		{Expect: "GET /v1/distributedissuers/configurations", MockCode: 200, MockBody: `{"configurations": [` + sampleConfig + `]}`},
		// Even though the ServiceAccount is not found, the WIMConfiguration
		// deletion should proceed.
		{Expect: "DELETE /v1/distributedissuers/configurations/d867b700-9de6-11f0-b18d-1b1c0845fa26", MockCode: 204},
	}

	err := runDeleteTest(t, givenManifests, mock, failOnNotFound)
	require.EqualError(t, err, "one or more manifests failed to delete")
}

const (
	ignoreNotFound = true
	failOnNotFound = false
)

func runDeleteTest(t *testing.T, givenManifests string, mock []mocksrv.Interaction, ignoreNotFound bool) error {
	_, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	srv := mocksrv.Mock(t, mock, cancel)

	manifests, err := parseManifests([]byte(givenManifests))
	require.NoError(t, err)

	cl, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	return deleteManifests(cl, manifests, ignoreNotFound)
}
