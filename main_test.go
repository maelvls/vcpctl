package main

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
	api "github.com/maelvls/vcpctl/internal/api"
	"github.com/maelvls/vcpctl/internal/manifest"
	"github.com/maelvls/vcpctl/mocksrv"
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
			if result != test.expected {
				t.Errorf("Expected %q but got %q", test.expected, result)
			}
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
	if err := yaml.UnmarshalWithOptions(input, &cfg, yaml.Strict()); err != nil {
		t.Fatalf("unexpected error while unmarshalling YAML: %v", err)
	}

	auth := cfg.ClientAuthentication
	if auth.Type != "JWT_STANDARD_CLAIMS" {
		t.Fatalf("unexpected type: %q", auth.Type)
	}
	if auth.Audience != "firefly.example.com" {
		t.Fatalf("unexpected audience: %q", auth.Audience)
	}
	if len(auth.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(auth.Clients))
	}
	if auth.Clients[0].Issuer != "https://example.com" {
		t.Fatalf("unexpected issuer for client[0]: %q", auth.Clients[0].Issuer)
	}
	if len(auth.Clients[0].AllowedPolicies) != 1 || auth.Clients[0].AllowedPolicies[0] != "Policy" {
		t.Fatalf("unexpected allowedPolicies for client[0]: %#v", auth.Clients[0].AllowedPolicies)
	}
	if auth.Clients[1].JwksURI != "https://example.com/.well-known/jwks.json" {
		t.Fatalf("unexpected jwksURI for client[1]: %q", auth.Clients[1].JwksURI)
	}
	if len(auth.Clients[1].Subjects) != 1 || auth.Clients[1].Subjects[0] != "^system:serviceaccount:test-app-namespace:.*$" {
		t.Fatalf("unexpected subjects for client[1]: %#v", auth.Clients[1].Subjects)
	}

	data, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("unexpected error while marshalling JSON: %v", err)
	}
	jsonStr := string(data)
	// Note: The manifest.ClientAuthentication struct uses Go's default JSON marshaling (capitalized fields)
	for _, key := range []string{"\"Audience\":", "\"Clients\":", "\"AllowedPolicies\":", "\"JwksURI\":"} {
		if !strings.Contains(jsonStr, key) {
			t.Fatalf("expected JSON output to contain %s, got %s", key, jsonStr)
		}
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
policies:
  - policy-1
serviceAccount:
  - sa-1
subCaProvider: demo
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
`

func TestParseFireflyConfigManifests_MultiDocument(t *testing.T) {
	items, err := parseManifests([]byte(sampleMultiDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("expected 4 manifests, got %d", len(items))
	}

	sa := items[0].ServiceAccount
	if sa == nil || sa.Name != "sa-1" {
		t.Fatalf("unexpected service account manifest: %#v", sa)
	}
	policy := items[1].Policy
	if policy == nil || policy.Name != "policy-1" {
		t.Fatalf("unexpected policy manifest: %#v", policy)
	}
	subca := items[2].SubCa
	if subca == nil || subca.Name != "demo" {
		t.Fatalf("unexpected SubCA manifest: %#v", subca)
	}
	config := items[3].WIMConfiguration
	if config == nil || config.Name != "demo" {
		t.Fatalf("unexpected config manifest: %#v", config)
	}
	if len(config.PolicyNames) != 1 || config.PolicyNames[0] != "policy-1" {
		t.Fatalf("unexpected config policy names: %#v", config.PolicyNames)
	}
	if len(config.ServiceAccountNames) != 1 || config.ServiceAccountNames[0] != "sa-1" {
		t.Fatalf("unexpected config service account names: %#v", config.ServiceAccountNames)
	}
	if config.SubCaProviderName != "demo" {
		t.Fatalf("unexpected config subCA provider name: %q", config.SubCaProviderName)
	}
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
subCaProvider: x
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
---
kind: ServiceAccount
name: late
`
	items, err := parseManifests([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 manifests, got %d", len(items))
	}
}

func TestPatchConfig_OK(t *testing.T) {
	id := uuid.New()
	patch := ConfigPatch{
		Name:          "demo",
		MinTlsVersion: api.ConfigurationUpdateRequestMinTlsVersionTLS13,
	}
	wantBody, err := json.Marshal(patch)
	if err != nil {
		t.Fatalf("unexpected error marshaling patch: %v", err)
	}

	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := mocksrv.Mock(t, []mocksrv.Interaction{
				{
					Expect:   fmt.Sprintf("PATCH /v1/distributedissuers/configurations/%s", id.String()),
					MockCode: status,
					Assert: func(t *testing.T, r *http.Request, body string) {
						if got := r.Header.Get("Content-Type"); got != "application/json" {
							t.Errorf("Content-Type = %q, want %q", got, "application/json")
						}
						if got := r.Header.Get("tppl-api-key"); got != "api-key" {
							t.Errorf("tppl-api-key = %q, want %q", got, "api-key")
						}
						if got := r.Header.Get("User-Agent"); got != userAgent {
							t.Errorf("User-Agent = %q, want %q", got, userAgent)
						}

						var gotBody map[string]any
						if err := json.Unmarshal([]byte(body), &gotBody); err != nil {
							t.Errorf("unexpected error decoding request body: %v", err)
							return
						}
						var wantBodyMap map[string]any
						if err := json.Unmarshal(wantBody, &wantBodyMap); err != nil {
							t.Errorf("unexpected error decoding expected body: %v", err)
							return
						}
						if !reflect.DeepEqual(gotBody, wantBodyMap) {
							t.Errorf("request body mismatch: got %#v, want %#v", gotBody, wantBodyMap)
						}
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
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var notFound NotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected NotFound error, got %T: %v", err, err)
	}
	if notFound.NameOrID != id.String() {
		t.Fatalf("unexpected NotFound NameOrID: %q", notFound.NameOrID)
	}
	if !strings.Contains(err.Error(), "WIM configuration") {
		t.Fatalf("expected error to mention WIM configuration, got %v", err)
	}
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
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var httpErr HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("expected HTTPError, got %T: %v", err, err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("unexpected status code: %d", httpErr.StatusCode)
	}
	if !strings.Contains(err.Error(), "patchConfig:") || !strings.Contains(err.Error(), "http") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestParseFireflyConfigManifests_MissingKind(t *testing.T) {
	single := `name: legacy
cloudProviders: {}
minTlsVersion: TLS13
clientAuthentication: {}
subCaProvider: legacy
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
serviceAccounts: []
policies: []
`
	_, err := parseManifests([]byte(single))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var fix FixableError
	if !errors.As(err, &fix) {
		t.Fatalf("expected FixableError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRenderFireflyConfigManifests(t *testing.T) {
	t.Skip("renderManifests is not yet fully implemented for the current API structure")
}
