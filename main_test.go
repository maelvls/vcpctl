package main

import (
	json "encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	api "github.com/maelvls/vcpctl/internal/api"
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
      allowedPolicyIds:
        - Policy
    - issuer: "^https://.*\\.example\\.com$"
      jwksURI: https://example.com/.well-known/jwks.json
      subjects:
        - ^system:serviceaccount:test-app-namespace:.*$
      allowedPolicyIds:
        - Policy
`)

	var cfg api.Config
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
	if len(auth.Clients[0].AllowedPolicyIDs) != 1 || auth.Clients[0].AllowedPolicyIDs[0] != "Policy" {
		t.Fatalf("unexpected allowedPolicyIds for client[0]: %#v", auth.Clients[0].AllowedPolicyIDs)
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
	for _, key := range []string{"\"audience\":", "\"clients\":", "\"allowedPolicyIds\":", "\"jwksURI\":"} {
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
subCaProvider: demo
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
`

func TestParseFireflyConfigManifests_MultiDocument(t *testing.T) {
	cfg, err := parseFireflyConfigManifests([]byte(sampleMultiDoc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "demo" {
		t.Fatalf("unexpected config name: %q", cfg.Name)
	}
	if len(cfg.ServiceAccounts) != 1 {
		t.Fatalf("expected 1 service account, got %d", len(cfg.ServiceAccounts))
	}
	if cfg.ServiceAccounts[0].Name != "sa-1" {
		t.Fatalf("unexpected service account name: %q", cfg.ServiceAccounts[0].Name)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(cfg.Policies))
	}
	if cfg.Policies[0].Name != "policy-1" {
		t.Fatalf("unexpected policy name: %q", cfg.Policies[0].Name)
	}
	if cfg.SubCaProvider.Name != "demo" {
		t.Fatalf("unexpected SubCA provider name: %q", cfg.SubCaProvider.Name)
	}
}

func TestParseFireflyConfigManifests_OrderValidation(t *testing.T) {
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
	_, err := parseFireflyConfigManifests([]byte(input))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var fix FixableError
	if !errors.As(err, &fix) {
		t.Fatalf("expected FixableError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "reorder") {
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
	_, err := parseFireflyConfigManifests([]byte(single))
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
	cfg, err := parseFireflyConfigManifests([]byte(sampleMultiDoc))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	out, err := renderFireflyConfigManifests(cfg)
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	segments := strings.Split(string(out), "---\n")
	if len(segments) != 4 {
		t.Fatalf("expected 4 documents, got %d", len(segments))
	}
	if !strings.Contains(segments[0], "kind: ServiceAccount") {
		t.Fatalf("expected first document to be ServiceAccount, got:\n%s", segments[0])
	}
	if !strings.Contains(segments[1], "kind: WIMIssuerPolicy") {
		t.Fatalf("expected second document to be WIMIssuerPolicy, got:\n%s", segments[1])
	}
	if !strings.Contains(segments[2], "kind: WIMSubCAProvider") {
		t.Fatalf("expected third document to be WIMSubCAProvider, got:\n%s", segments[2])
	}
	if !strings.Contains(segments[3], "kind: WIMConfiguration") {
		t.Fatalf("expected fourth document to be WIMConfiguration, got:\n%s", segments[3])
	}
}
