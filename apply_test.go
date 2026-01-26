package main

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/goccy/go-yaml"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
)

// Among other things, these unit tests aim to make sure that booleans can be
// swithched from true to false, such as WIMConfiguration's
// advancedSettings.enableIssuanceAuditLog. It used to not be possible due to
// 'omitzero', and was fixed by making the API objects nilable. Note that for
// slices and maps, this is not an issue thanks to Go's nil vs. empty slice/map
// distinction.
func Test_applyManifests_WIMConfiguration(t *testing.T) {
	t.Run("no changes", testPatchWIMConfiguration(testPatch_tc{
		existing:    sampleConfig,
		desired:     sampleWIMConfiguration,
		expectPatch: `{}`,
	}))

	t.Run("can set clientAuthentication", testPatchWIMConfiguration(testPatch_tc{
		existing: withJSON(sampleConfig,
			"clientAuthentication.type", "JWT_JWKS",
			"clientAuthentication.urls", []string{"http://localhost:8000/.well-known/jwks.json"},
		),
		desired: withYAML(sampleWIMConfiguration,
			"clientAuthentication.type", "JWT_STANDARD_CLAIMS",
			"clientAuthentication.clients", []map[string]any{{
				"name":            "client1",
				"issuer":          "https://issuer.example.com",
				"jwksURI":         "http://changed/jwks.json",
				"subjects":        []string{"test"},
				"allowedPolicies": []string{"d7a09670-9de6-11f0-b18d-1b1c0845fa26"},
			}},
		),
		expectPatch: `{
			"clientAuthentication":{
				"type":"JWT_STANDARD_CLAIMS",
				"clients":[{
				  "name":"client1",
				  "issuer":"https://issuer.example.com",
				  "jwksUri":"http://changed/jwks.json",
				  "subjects":["test"],
				  "allowedPolicyIds":["d7a09670-9de6-11f0-b18d-1b1c0845fa26"]
        }]
			}
		}`}))

	t.Run("can switch from true to false", testPatchWIMConfiguration(testPatch_tc{
		existing:    withJSON(sampleConfig, "advancedSettings.enableIssuanceAuditLog", true),
		desired:     withYAML(sampleWIMConfiguration, "advancedSettings.enableIssuanceAuditLog", false),
		expectPatch: `{"advancedSettings": {"enableIssuanceAuditLog": false}}`,
	}))

	t.Run("can switch from false to true", testPatchWIMConfiguration(testPatch_tc{
		existing:    withJSON(sampleConfig, "advancedSettings.enableIssuanceAuditLog", false),
		desired:     withYAML(sampleWIMConfiguration, "advancedSettings.enableIssuanceAuditLog", true),
		expectPatch: `{"advancedSettings": {"enableIssuanceAuditLog": true}}`,
	}))

}

var testPatchWIMConfiguration = testPatchFn(func(t *testing.T, existing, expectedPatch string) []mocksrv.Interaction {
	return []mocksrv.Interaction{
		{Expect: "GET /v1/distributedissuers/subcaproviders", MockCode: 200, MockBody: `{"subCaProviders": [` + sampleAPISubCA + `]}`},
		{Expect: "GET /v1/distributedissuers/policies/d7a09670-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200, MockBody: sampleAPIPolicy},
		{Expect: "GET /v1/distributedissuers/configurations", MockCode: 200, MockBody: `{"configurations": [` + existing + `]}`},
		{Expect: "PATCH /v1/distributedissuers/configurations/d867b700-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200, MockBody: existing, Assert: func(t *testing.T, r *http.Request, gotBody string) {
			require.JSONEq(t, expectedPatch, gotBody)
		}},
	}
})

func Test_applyManifests_WIMSubCA(t *testing.T) {
	t.Run("no changes", testPatchSubCA(testPatch_tc{
		existing:    sampleAPISubCA,
		desired:     sampleManifestSubCA,
		expectPatch: `{}`,
	}))

	t.Run("pkcs11.signingEnabled can be switched from true to false", testPatchSubCA(testPatch_tc{
		existing:    withJSON(sampleAPISubCA, "pkcs11.signingEnabled", true),
		desired:     withYAML(sampleManifestSubCA, "pkcs11.signingEnabled", false),
		expectPatch: `{"pkcs11":{"signingEnabled":false}}`,
	}))
}

var testPatchSubCA = testPatchFn(func(t *testing.T, existing, expectedPatch string) []mocksrv.Interaction {
	return []mocksrv.Interaction{
		{Expect: "GET /v1/certificateissuingtemplates", MockCode: 200, MockBody: `{"certificateIssuingTemplates": [` + sampleIssuingTemplate + `]}`},
		{Expect: "GET /v1/distributedissuers/subcaproviders", MockCode: 200, MockBody: `{"subCaProviders": [` + existing + `]}`},
		{Expect: "PATCH /v1/distributedissuers/subcaproviders/d7f211d0-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200,
			MockBody: `{"subCaProviders": [` + existing + `]}`,
			Assert: func(t *testing.T, r *http.Request, gotBody string) {
				require.JSONEq(t, expectedPatch, gotBody)
			},
		},
	}
})

func Test_applyManifests_WIMIssuerPolicy(t *testing.T) {
	t.Run("no changes", testPatchWIMIssuerPolicy(testPatch_tc{
		existing:    sampleAPIPolicy,
		desired:     sampleManifestPolicy,
		expectPatch: `{}`,
	}))

	t.Run("can change minOccurrences", testPatchWIMIssuerPolicy(testPatch_tc{
		existing: withJSON(sampleAPIPolicy,
			"subject.commonName.type", "REQUIRED",
			"subject.commonName.minOccurrences", 1,
			"subject.commonName.maxOccurrences", 5,
		),
		desired: withYAML(sampleManifestPolicy,
			"subject.commonName.type", "OPTIONAL",
			"subject.commonName.minOccurrences", 0,
			"subject.commonName.maxOccurrences", 10,
		),
		expectPatch: `{"subject":{"commonName":{"maxOccurrences":10,"type":"OPTIONAL"}}}`,
	}))
}

var testPatchWIMIssuerPolicy = testPatchFn(func(t *testing.T, existing, expectedPatch string) []mocksrv.Interaction {
	return []mocksrv.Interaction{
		{Expect: "GET /v1/distributedissuers/policies", MockCode: 200, MockBody: `{"policies": [` + existing + `]}`},
		{Expect: "PATCH /v1/distributedissuers/policies/d7a09670-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200,
			MockBody: `{"policies": [` + existing + `]}`,
			Assert: func(t *testing.T, r *http.Request, gotBody string) {
				t.Helper()
				require.Equal(t, expectedPatch, gotBody)
			},
		},
	}
})

func Test_applyManifests_ServiceAccount(t *testing.T) {
	t.Run("no changes", testPatchServiceAccount(testPatch_tc{
		existing:    sampleSA,
		desired:     sampleManifestSA,
		expectPatch: "", // "" = no PATCH must be made.
	}))

	t.Run("can change enabled from false to true", testPatchServiceAccount(testPatch_tc{
		existing:    withJSON(sampleSA, "enabled", true),
		desired:     withYAML(sampleManifestSA, "enabled", false),
		expectPatch: `{"enabled":false}`,
	}))
}

var testPatchServiceAccount = testPatchFn(func(t *testing.T, existing, expectedPatch string) []mocksrv.Interaction {
	var assertEqual func(t *testing.T, expected, actual any, msgAndArgs ...any)
	if expectedPatch == "" {
		assertEqual = requireNotCalled(t, "no PATCH request was expected, but one was made")
	} else {
		assertEqual = assertEqualAndCalled(t, "a PATCH request was expected but none was made")
	}
	return []mocksrv.Interaction{
		{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[` + existing + `]`},
		{Expect: "GET /v1/teams", MockCode: 200, MockBody: `{"teams": [` + sampleTeam + `]}`},
		{Expect: "PATCH /v1/serviceaccounts/d46f1f0d-299f-11ef-a8ac-2ea42f30fe31", MockCode: 200,
			MockBody: existing,
			Assert: func(t *testing.T, r *http.Request, gotBody string) {
				assertEqual(t, expectedPatch, gotBody)
			},
		},
	}
})

func assertEqualAndCalled(t *testing.T, msgAndArgs ...any) func(t *testing.T, expected, actual any, msgAndArgs ...any) {
	t.Helper()
	called := atomic.Bool{}
	t.Cleanup(func() {
		assert.True(t, called.Load(), msgAndArgs...)
	})
	return func(t *testing.T, expected, actual any, msgAndArgs ...any) {
		called.Store(true)
		assert.Equal(t, expected, actual, msgAndArgs...)
	}
}

func requireNotCalled(t *testing.T, msgAndArgs ...any) func(t *testing.T, expected, actual any, msgAndArgs ...any) {
	t.Helper()
	called := atomic.Bool{}
	t.Cleanup(func() {
		assert.False(t, called.Load(), msgAndArgs...)
	})
	return func(t *testing.T, expected, actual any, msgAndArgs ...any) {
		called.Store(true)
	}
}

func run(t *testing.T, givenManifests string, mock []mocksrv.Interaction) {
	t.Helper()

	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	srv := mocksrv.UncheckedMock(t, mock, cancel)

	manifests, err := parseManifests([]byte(givenManifests))
	require.NoError(t, err)
	dryrun := false

	cl, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	err = applyManifests(ctx, cl, manifests, dryrun)
	require.NoError(t, err)
}

var sampleConfig = `
{
  "id": "d867b700-9de6-11f0-b18d-1b1c0845fa26",
  "companyId": "a3be02b2-b008-48b4-8eb9-9aaa0e51ceed",
  "name": "mael",
  "policyIds": ["d7a09670-9de6-11f0-b18d-1b1c0845fa26"],
  "clientAuthentication": {
    "type": "JWT_JWKS",
    "urls": ["http://localhost:8000/.well-known/jwks.json"]
  },
  "clientAuthorization": {
    "customClaimsAliases": {
      "configuration": "",
      "allowAllPolicies": "",
      "allowedPolicies": ""
    }
  },
  "cloudProviders": {},
  "serviceAccountIds": ["d76c96de-9de6-11f0-823f-8edfda701dde"],
  "minTlsVersion": "TLS13",
  "advancedSettings": { "enableIssuanceAuditLog": true },
  "longLivedCertCount": 0,
  "shortLivedCertCount": 0,
  "ultraShortLivedCertCount": 0,
  "creationDate": "2025-09-30T10:18:44.722+00:00",
  "modificationDate": "2026-01-13T08:12:57.503+00:00",
  "subCaProvider": {
    "id": "d7f211d0-9de6-11f0-b18d-1b1c0845fa26",
    "companyId": "7cb55a54-f33e-40d0-93aa-2c4cf78ed9d3",
    "name": "mael",
    "caType": "BUILTIN",
    "caAccountId": "7665cba0-280e-11ee-abfe-69743765b4a4",
    "caProductOptionId": "7665cba1-280e-11ee-abfe-69743765b4a4",
    "validityPeriod": "P90D",
    "commonName": "mael",
    "organization": "foo",
    "organizationalUnit": "Engineering",
    "locality": "Toulouse",
    "stateOrProvince": "Occitanie",
    "country": "France",
    "keyAlgorithm": "EC_P256",
    "pkcs11": {
      "signingEnabled": false,
      "partitionLabel": "",
      "partitionSerialNumber": "",
      "allowedClientLibraries": []
    },
    "creationDate": "2025-09-30T10:18:43.954+00:00",
    "modificationDate": "2026-01-11T10:49:38.045+00:00"
  },
  "policyDefinitions": [
    {
      "id": "d7a09670-9de6-11f0-b18d-1b1c0845fa26",
      "companyId": "f2cfad46-cc77-4497-bde2-b355a56852bc",
      "name": "mael",
      "validityPeriod": "P90D",
      "subject": {
        "commonName": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "organization": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "organizationalUnit": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "locality": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "stateOrProvince": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "country": { "type": "OPTIONAL", "maxOccurrences": 10 }
      },
      "sans": {
        "dnsNames": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "ipAddresses": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "rfc822Names": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "uniformResourceIdentifiers": {
          "type": "OPTIONAL",
          "maxOccurrences": 10
        }
      },
      "keyUsages": ["digitalSignature"],
      "extendedKeyUsages": ["ANY"],
      "keyAlgorithm": {
        "allowedValues": ["EC_P256"],
        "defaultValue": "EC_P256"
      },
      "creationDate": "2025-09-30T10:18:43.415+00:00",
      "modificationDate": "2026-01-12T09:56:47.692+00:00"
    }
  ],
  "policies": [
    {
      "id": "d7a09670-9de6-11f0-b18d-1b1c0845fa26",
      "companyId": "deb54f5b-04a6-4742-b98c-a08358fa230d",
      "name": "mael",
      "validityPeriod": "P90D",
      "subject": {
        "commonName": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "organization": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "organizationalUnit": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "locality": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "stateOrProvince": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "country": { "type": "OPTIONAL", "maxOccurrences": 10 }
      },
      "sans": {
        "dnsNames": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "ipAddresses": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "rfc822Names": { "type": "OPTIONAL", "maxOccurrences": 10 },
        "uniformResourceIdentifiers": {
          "type": "OPTIONAL",
          "maxOccurrences": 10
        }
      },
      "keyUsages": ["digitalSignature"],
      "extendedKeyUsages": ["ANY"],
      "keyAlgorithm": {
        "allowedValues": ["EC_P256"],
        "defaultValue": "EC_P256"
      },
      "creationDate": "2025-09-30T10:18:43.415+00:00",
      "modificationDate": "2026-01-12T09:56:47.692+00:00"
    }
  ]
}
`

var sampleAPISubCA = `
{
  "id": "d7f211d0-9de6-11f0-b18d-1b1c0845fa26",
  "companyId": "19e21c57-8250-449a-a792-04d2007c7fa5",
  "name": "mael",
  "caType": "BUILTIN",
  "caAccountId": "c1ed7a40-ab9b-11ed-be60-59765e2a5c19",
  "caProductOptionId": "c1ed7a41-ab9b-11ed-be60-59765e2a5c19",
  "validityPeriod": "P90D",
  "commonName": "mael",
  "organization": "foo",
  "organizationalUnit": "Engineering",
  "locality": "Toulouse",
  "stateOrProvince": "Occitanie",
  "country": "France",
  "keyAlgorithm": "EC_P256",
  "pkcs11": {
    "signingEnabled": false,
    "partitionLabel": "",
    "partitionSerialNumber": "",
    "allowedClientLibraries": []
  },
  "creationDate": "2025-09-30T10:18:43.954+00:00",
  "modificationDate": "2026-01-11T10:49:38.045+00:00"
}
`

var sampleAPIPolicy = `
{
  "id": "d7a09670-9de6-11f0-b18d-1b1c0845fa26",
  "companyId": "04a2be00-8d4e-4b64-81a0-f5083f92dda0",
  "name": "mael",
  "validityPeriod": "P90D",
  "subject": {
    "commonName": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "organization": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "organizationalUnit": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "locality": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "stateOrProvince": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "country": { "type": "OPTIONAL", "maxOccurrences": 10 }
  },
  "sans": {
    "dnsNames": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "ipAddresses": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "rfc822Names": { "type": "OPTIONAL", "maxOccurrences": 10 },
    "uniformResourceIdentifiers": {
      "type": "OPTIONAL",
      "maxOccurrences": 10
    }
  },
  "keyUsages": ["digitalSignature"],
  "extendedKeyUsages": ["ANY"],
  "keyAlgorithm": {
    "allowedValues": ["EC_P256"],
    "defaultValue": "EC_P256"
  },
  "creationDate": "2025-09-30T10:18:43.415+00:00",
  "modificationDate": "2026-01-11T10:49:37.553+00:00",
  "configurations": [
    {
      "id": "d867b700-9de6-11f0-b18d-1b1c0845fa26",
      "companyId": "c55a5727-6536-43ee-b7d7-910125bb24f1",
      "name": "mael",
      "policyIds": ["d7a09670-9de6-11f0-b18d-1b1c0845fa26"],
      "clientAuthentication": {
        "type": "JWT_JWKS",
        "urls": ["http://localhost:8000/.well-known/jwks.json"]
      },
      "clientAuthorization": {
        "customClaimsAliases": {
          "configuration": "",
          "allowAllPolicies": "",
          "allowedPolicies": ""
        }
      },
      "cloudProviders": {},
      "serviceAccountIds": [],
      "minTlsVersion": "TLS13",
      "advancedSettings": { "enableIssuanceAuditLog": true },
      "longLivedCertCount": 0,
      "shortLivedCertCount": 0,
      "ultraShortLivedCertCount": 0,
      "creationDate": "2025-09-30T10:18:44.722+00:00",
      "modificationDate": "2026-01-11T10:48:30.434+00:00"
    }
  ]
}
`

var sampleSA = `
{
  "name": "mael",
  "authenticationType": "rsaKey",
  "companyId": "091f0939-c1af-4b57-ac59-7d3b1d0a014f",
  "createdBy": "76a126f0-280e-11ee-84fb-991f3177e2d0",
  "credentialLifetime": 365,
  "credentialsExpiringOn": "2025-06-13T16:13:11.236584Z",
  "enabled": true,
  "id": "d46f1f0d-299f-11ef-a8ac-2ea42f30fe31",
  "owner": "d2508300-3705-11ee-a17b-69a77fb429d7",
  "scopes": [
      "distributed-issuance"
  ],
  "updatedBy": "76a126f0-280e-11ee-84fb-991f3177e2d0",
  "updatedOn": "2024-06-13T16:13:11.238061Z"
}
`

var sampleTeam = `
{
  "id": "d2508300-3705-11ee-a17b-69a77fb429d7",
  "name": "mael",
  "companyId": "f40c5065-de20-4748-aad3-c4a92b3a9351",
  "creationDate": "2024-06-13T16:10:00.000Z",
  "modificationDate": "2024-06-13T16:10:00.000Z"
}
`

var sampleIssuingTemplate = `
{
  "id": "c1ed7a42-ab9b-11ed-be60-59765e2a5c19",
  "companyId": "24de529f-45e6-45e0-ba80-792f100450b3",
  "certificateAuthority": "BUILTIN",
  "name": "Default",
  "certificateAuthorityAccountId": "c1ed7a40-ab9b-11ed-be60-59765e2a5c19",
  "certificateAuthorityProductOptionId": "c1ed7a41-ab9b-11ed-be60-59765e2a5c19",
  "product": {
    "certificateAuthority": "BUILTIN",
    "productName": "Default Product",
    "productTypes": ["SSL", "CODESIGN"],
    "validityPeriod": "P90D"
  },
  "systemGenerated": true,
  "creationDate": "2023-02-13T12:41:36.539+00:00",
  "modificationDate": "2024-11-27T15:18:23.927+00:00",
  "status": "AVAILABLE",
  "reason": "",
  "referencingApplicationIds": [
    "ff1327b1-1cd4-449d-b9ff-896fa1310ef1"
  ],
  "subjectCNRegexes": [".*"],
  "subjectORegexes": [".*"],
  "subjectOURegexes": [".*"],
  "subjectSTRegexes": [".*"],
  "subjectLRegexes": [".*"],
  "subjectCValues": [".*"],
  "sanRegexes": [".*"],
  "sanDnsNameRegexes": [".*"],
  "keyTypes": [{ "keyType": "RSA", "keyLengths": [2048, 3072, 4096] }],
  "keyReuse": false,
  "extendedKeyUsageValues": [],
  "csrUploadAllowed": true,
  "keyGeneratedByVenafiAllowed": true,
  "resourceConsumerUserIds": [],
  "resourceConsumerTeamIds": [],
  "everyoneIsConsumer": true,
  "description": "",
  "driverGeneratedCsr": true,
  "driverId": "484dc747-dae0-4b19-b8d1-4f80e907d312",
  "locationId": "c0f2c691-ab9b-11ed-bfed-b3b2b59a7f20"
}
`

var sampleWIMConfiguration = `
kind: WIMConfiguration
name: mael
subCaProviderName: mael
clientAuthentication:
  type: JWT_JWKS
  urls:
    - http://localhost:8000/.well-known/jwks.json
cloudProviders: {}
minTlsVersion: TLS13
advancedSettings:
  enableIssuanceAuditLog: true
`

var sampleManifestSA = `
kind: ServiceAccount
name: mael
authenticationType: rsaKey
credentialLifetime: 365
enabled: true
scopes:
  - distributed-issuance
`
var sampleManifestSubCA = `
kind: WIMSubCAProvider
name: mael
issuingTemplateName: Default
validityPeriod: P90D
commonName: mael
organization: foo
country: France
locality: Toulouse
organizationalUnit: Engineering
stateOrProvince: Occitanie
keyAlgorithm: EC_P256
pkcs11:
  allowedClientLibraries: []
  partitionLabel: ""
  partitionSerialNumber: ""
  pin: ""
  signingEnabled: true
`

var sampleManifestPolicy = `
kind: WIMIssuerPolicy
name: mael
validityPeriod: P90D
subject:
  commonName: { type: OPTIONAL, minOccurrences: 0, maxOccurrences: 10 }
keyUsages:
  - digitalSignature
extendedKeyUsages:
  - ANY
keyAlgorithm:
  allowedValues:
    - EC_P256
  defaultValue: EC_P256
`

// You can have multiple modifications in a single withYAML() call by passing a
// slice of [path, value] pairs. Example:
//
//	modified := withYAML(yamlStr,
//	  "foo.bar", 42,
//	  "baz.qux", "hello",
//	)
func withYAML(yamlOrJSONStr string, changes ...any) string {
	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlOrJSONStr))
	if err != nil {
		panic(fmt.Sprintf("yaml to json: %v", err))
	}
	jsonStr := withJSON(string(jsonBytes), changes...)
	yamlOutput, err := yaml.JSONToYAML([]byte(jsonStr))
	if err != nil {
		panic(fmt.Sprintf("json to yaml: %v", err))
	}
	return string(yamlOutput)
}

func withJSON(jsonStr string, changes ...any) string {
	if len(changes)%2 != 0 {
		panic("with(): changes must be in pairs of [path, value]")
	}
	jsonBytes := []byte(jsonStr)

	var err error
	for i := 0; i < len(changes); i += 2 {
		jsonBytes, err = sjson.SetBytes(jsonBytes, changes[i].(string), changes[i+1])
		if err != nil {
			panic(fmt.Sprintf("sjson set: %v", err))
		}
	}

	return string(jsonBytes)
}

func testPatchFn(mock func(t *testing.T, existing, expectedPatch string) []mocksrv.Interaction) func(tc testPatch_tc) func(t *testing.T) {
	return func(tc testPatch_tc) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()
			mock := mock(t, tc.existing, tc.expectPatch)
			run(t, tc.desired, mock)
		}
	}
}

type testPatch_tc struct {
	name        string
	existing    string
	desired     string
	expectPatch string // "" = no call to PATCH expected
}
