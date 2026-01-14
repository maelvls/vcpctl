package main

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	api "github.com/maelvls/vcpctl/internal/api"
	"github.com/maelvls/vcpctl/internal/manifest"
	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_withoutANSI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\x1b[1;34mHello\x1b[0m", "Hello"},
		{"\x1b[1;34mHello\x1b[0m \x1b[1;34mWorld\x1b[0m", "Hello World"},
		{"\x1b[38;5;1m", ""},
		{"\x1b[1;31m", ""},
		{"\x1b[90m", ""},
		{"\x1b[1;34m", ""},
		{"\x1b[0m", ""},
		{"\x1b[38;5;34m foobar \x1b[0m", " foobar "},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := withoutANSI(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestClientAuthenticationJWTStandardClaims(t *testing.T) {
	input := []byte(`clientAuthentication:
  type: JWT_STANDARD_CLAIMS
  audience: firefly.example.com
  clients:
    - issuer: https://example.com
      subjects:
        - sub-claim-value
        - system:serviceaccount:test-app-namespace:test-app-sa
      allowedPolicies:
        - Policy
    - issuer: "^https://.*\\.example\\.com$"
      jwksURI: https://example.com/.well-known/jwks.json
      subjects:
        - ^system:serviceaccount:test-app-namespace:.*$
      allowedPolicies:
        - Policy
`)

	var cfg struct {
		ClientAuthentication manifest.ClientAuthentication `yaml:"clientAuthentication"`
	}
	err := yaml.UnmarshalWithOptions(input, &cfg, yaml.Strict())
	require.NoError(t, err, "unexpected error while unmarshalling YAML")

	auth := cfg.ClientAuthentication
	require.Equal(t, "JWT_STANDARD_CLAIMS", auth.Type)
	require.Equal(t, "firefly.example.com", auth.Audience)
	require.Len(t, auth.Clients, 2)
	require.Equal(t, "https://example.com", auth.Clients[0].Issuer)
	require.Len(t, auth.Clients[0].AllowedPolicies, 1)
	require.Equal(t, "Policy", auth.Clients[0].AllowedPolicies[0])
	require.Equal(t, "https://example.com/.well-known/jwks.json", auth.Clients[1].JwksURI)
	require.Len(t, auth.Clients[1].Subjects, 1)
	require.Equal(t, "^system:serviceaccount:test-app-namespace:.*$", auth.Clients[1].Subjects[0])

	data, err := json.Marshal(auth)
	require.NoError(t, err, "unexpected error while marshalling JSON")
	jsonStr := string(data)
	// Note: The manifest.ClientAuthentication struct uses Go's default JSON marshaling (capitalized fields)
	for _, key := range []string{"\"Audience\":", "\"Clients\":", "\"AllowedPolicies\":", "\"JwksURI\":"} {
		assert.Contains(t, jsonStr, key)
	}
}

const sampleMultiDoc = `kind: ServiceAccount
name: sa-1
authenticationType: rsaKey
credentialLifetime: 365
enabled: true
scopes:
  - distributed-issuance
---
kind: WIMIssuerPolicy
name: policy-1
validityPeriod: P90D
subject:
  commonName: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  country: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  locality: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  organization: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  organizationalUnit: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  stateOrProvince: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
sans:
  dnsNames: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  ipAddresses: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  rfc822Names: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  uniformResourceIdentifiers: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
keyUsages:
  - digitalSignature
extendedKeyUsages:
  - ANY
keyAlgorithm:
  allowedValues:
    - EC_P256
  defaultValue: EC_P256
---
kind: WIMSubCAProvider
name: demo
caType: BUILTIN
validityPeriod: P90D
commonName: demo
organization: DemoOrg
country: US
locality: City
organizationalUnit: Unit
stateOrProvince: State
keyAlgorithm: EC_P256
pkcs11:
  allowedClientLibraries: []
  partitionLabel: ""
  partitionSerialNumber: ""
  pin: ""
  signingEnabled: false
---
kind: WIMConfiguration
name: demo
clientAuthentication: {}
clientAuthorization:
  customClaimsAliases:
    configuration: ""
    allowAllPolicies: ""
    allowedPolicies: ""
cloudProviders: {}
minTlsVersion: TLS13
policyNames:
  - policy-1
serviceAccountNames:
  - sa-1
subCaProviderName: demo
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
`

func TestParseFireflyConfigManifests_MultiDocument(t *testing.T) {
	items, err := parseManifests([]byte(sampleMultiDoc))
	require.NoError(t, err)
	assert.Len(t, items, 4)

	sa := items[0].ServiceAccount
	require.NotNil(t, sa)
	assert.Equal(t, "sa-1", sa.Name)

	policy := items[1].Policy
	require.NotNil(t, policy)
	require.Equal(t, "policy-1", policy.Name)
	subca := items[2].SubCa
	require.NotNil(t, subca)
	require.Equal(t, "demo", subca.Name)
	config := items[3].WIMConfiguration
	require.NotNil(t, config)
	require.Equal(t, "demo", config.Name)
	require.Len(t, config.PolicyNames, 1)
	require.Equal(t, "policy-1", config.PolicyNames[0])
	require.Len(t, config.ServiceAccountNames, 1)
	require.Equal(t, "sa-1", config.ServiceAccountNames[0])
	require.Equal(t, "demo", config.SubCaProviderName)
}

func TestParseFireflyConfigManifests_AllowsAnyOrder(t *testing.T) {
	input := `kind: WIMSubCAProvider
name: x
caType: BUILTIN
validityPeriod: P1D
commonName: x
organization: X
country: US
locality: X
organizationalUnit: X
stateOrProvince: X
keyAlgorithm: EC_P256
pkcs11:
  allowedClientLibraries: []
  partitionLabel: ""
  partitionSerialNumber: ""
  pin: ""
  signingEnabled: false
---
kind: WIMConfiguration
name: out-of-order
cloudProviders: {}
minTlsVersion: TLS13
clientAuthentication: {}
subCaProviderName: x
serviceAccountNames: [y]
policyNames: [foo]
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
---
kind: ServiceAccount
name: late
`
	items, err := parseManifests([]byte(input))
	require.NoError(t, err)
	assert.Len(t, items, 3)
}

func TestPatchConfig_OK(t *testing.T) {
	id := uuid.New()
	patch := ConfigPatch{
		Name:          "demo",
		MinTlsVersion: api.ConfigurationUpdateRequestMinTlsVersionTLS13,
	}
	wantBody, err := json.Marshal(patch)
	require.NoError(t, err, "unexpected error marshaling patch")

	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := mocksrv.Mock(t, []mocksrv.Interaction{
				{
					Expect:   fmt.Sprintf("PATCH /v1/distributedissuers/configurations/%s", id.String()),
					MockCode: status,
					Assert: func(t *testing.T, r *http.Request, body string) {
						assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
						assert.Equal(t, "api-key", r.Header.Get("tppl-api-key"))
						assert.Equal(t, userAgent, r.Header.Get("User-Agent"))

						var gotBody map[string]any
						err := json.Unmarshal([]byte(body), &gotBody)
						require.NoError(t, err, "unexpected error decoding request body")
						var wantBodyMap map[string]any
						err = json.Unmarshal(wantBody, &wantBodyMap)
						require.NoError(t, err, "unexpected error decoding expected body")
						assert.Equal(t, wantBodyMap, gotBody)
					},
				},
			}, nil)

			cl := api.Client{
				Server: server.URL,
				Client: server.Client(),
			}
			_, err := patchConfig(context.Background(), cl, server.URL, "api-key", id, patch)
			require.NoError(t, err)
		})
	}
}

func TestPatchConfig_NotFound(t *testing.T) {
	id := uuid.New()
	server := mocksrv.Mock(t, []mocksrv.Interaction{
		{
			Expect:   fmt.Sprintf("PATCH /v1/distributedissuers/configurations/%s", id.String()),
			MockCode: http.StatusNotFound,
		},
	}, nil)

	cl := api.Client{
		Server: server.URL,
		Client: server.Client(),
	}
	_, err := patchConfig(context.Background(), cl, server.URL, "api-key", id, ConfigPatch{Name: "demo"})
	require.Error(t, err)
	var notFound NotFound
	require.ErrorAs(t, err, &notFound)
	require.Equal(t, id.String(), notFound.NameOrID)
	assert.Contains(t, err.Error(), "WIM configuration")
}

func TestPatchConfig_HTTPError(t *testing.T) {
	id := uuid.New()
	server := mocksrv.Mock(t, []mocksrv.Interaction{
		{
			Expect:   fmt.Sprintf("PATCH /v1/distributedissuers/configurations/%s", id.String()),
			MockCode: http.StatusInternalServerError,
			MockBody: `{"error":"boom"}`,
		},
	}, nil)

	cl := api.Client{
		Server: server.URL,
		Client: server.Client(),
	}
	_, err := patchConfig(context.Background(), cl, server.URL, "api-key", id, ConfigPatch{Name: "demo"})
	require.Error(t, err)
	var httpErr HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	assert.Contains(t, err.Error(), "patchConfig:")
	assert.Contains(t, err.Error(), "http")
}

func TestParseFireflyConfigManifests_MissingKind(t *testing.T) {
	single := `name: legacy
cloudProviders: {}
minTlsVersion: TLS13
clientAuthentication: {}
subCaProviderName: legacy
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
serviceAccountNames: []
policyNames: []
`
	_, err := parseManifests([]byte(single))
	require.Error(t, err)
	var fix FixableError
	require.ErrorAs(t, err, &fix)
	assert.Contains(t, err.Error(), "kind")
}

func TestRenderFireflyConfigManifests(t *testing.T) {
	t.Skip("renderManifests is not yet fully implemented for the current API structure")
}
