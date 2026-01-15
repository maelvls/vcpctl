package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
)

func Test_applyManifests(t *testing.T) {
	t.Run("WIMConfiguration patching", func(t *testing.T) {
		existingConf := with(sampleConfig,
			"clientAuthentication.type", "JWT_JWKS", // <- EXISTING
			"clientAuthentication.urls", []string{"http://original/jwks.json"}, // <- EXISTING

			// Make sure that when patching WIMConfiguration, you can switch
			// advancedSettings.enableIssuanceAuditLog from true to false (it used to
			// not be possible due to 'omitzero'). Note that for slices and maps, this
			// is not an issue thanks to Go's nil vs. empty slice/map distinction.
			"advancedSettings.enableIssuanceAuditLog", true, // <- EXISTING
		)
		givenManifests := undent.Undent(`
			kind: WIMConfiguration
			name: mael
			subCaProviderName: mael
			clientAuthentication:
			  type: JWT_STANDARD_CLAIMS                      # <- CHANGED
			  clients:                                       # <- CHANGED
			    - name: client1                              # <- CHANGED
			      issuer: https://issuer.example.com         # <- CHANGED
			      jwksURI: http://changed/jwks.json          # <- CHANGED
			      subjects: [test]                           # <- CHANGED
			      allowedPolicies:                           # <- CHANGED
			        - ce32c0b7-b3f4-4718-a825-1e6f5b1bf681   # <- CHANGED
			cloudProviders: {}
			minTlsVersion: TLS13
			advancedSettings:
			  enableIssuanceAuditLog: false                  # <- CHANGED
		`)
		expectPatch := `{
			"advancedSettings":{"enableIssuanceAuditLog":false},
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
		}`
		mock := []mocksrv.Interaction{
			{Expect: "GET /v1/distributedissuers/subcaproviders", MockCode: 200, MockBody: `{"subCaProviders": [` + sampleSubCA + `]}`},
			{Expect: "GET /v1/distributedissuers/subcaproviders", MockCode: 200, MockBody: `{"subCaProviders": [` + sampleSubCA + `]}`},
			{Expect: "GET /v1/distributedissuers/policies/ce32c0b7-b3f4-4718-a825-1e6f5b1bf681", MockCode: 200, MockBody: samplePolicy},
			{Expect: "GET /v1/distributedissuers/configurations", MockCode: 200, MockBody: `{"configurations": [` + existingConf + `]}`},
			{Expect: "PATCH /v1/distributedissuers/configurations/d867b700-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200,
				MockBody: `{"configurations": [` + existingConf + `]}`,
				Assert: func(t *testing.T, r *http.Request, gotBody string) {
					require.JSONEq(t, expectPatch, gotBody)
				},
			},
		}
		run(t, givenManifests, mock)
	})

	// (1) In these tests, we verify that booleans can be switched from true to
	// false, and more generally, any value for which the zero value is a valid
	// value, we need to make sure the patch "detects" it.
	t.Run("WIMSubCA patching", func(t *testing.T) {
		existingSubCA := with(sampleSubCA,
			"subCAProvider.organizationalUnit", "FooBar", // <- EXISTING
			"organizationalUnit", "Engineering", // <- EXISTING
			"pkcs11.signingEnabled", true, // <- EXISTING, see (1)
		)
		givenManifests := undent.Undent(`
			kind: WIMSubCAProvider
			name: mael
			issuingTemplateName: Default
			validityPeriod: P90D
			commonName: mael
			organization: foo
			country: France
			locality: Toulouse
			organizationalUnit: Changed1		# <- CHANGED
			stateOrProvince: Changed2		    # <- CHANGED
			keyAlgorithm: EC_P256
			pkcs11:
			  allowedClientLibraries: []
			  partitionLabel: ""
			  partitionSerialNumber: ""
			  pin: ""
			  signingEnabled: false         # <- CHANGED, see (1)
		`)
		expectPatch := `{
			"organizationalUnit":"Changed1",
      "stateOrProvince":"Changed2",
      "pkcs11":{"signingEnabled":false}
		}`
		mock := []mocksrv.Interaction{
			{Expect: "GET /v1/certificateissuingtemplates", MockCode: 200, MockBody: `{"certificateIssuingTemplates": [` + sampleIssuingTemplate + `]}`},
			{Expect: "GET /v1/distributedissuers/subcaproviders", MockCode: 200, MockBody: `{"subCaProviders": [` + existingSubCA + `]}`},
			{Expect: "PATCH /v1/distributedissuers/subcaproviders/d7f211d0-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200,
				MockBody: `{"subCaProviders": [` + existingSubCA + `]}`,
				Assert: func(t *testing.T, r *http.Request, gotBody string) {
					require.JSONEq(t, expectPatch, gotBody)
				},
			},
		}
		run(t, givenManifests, mock)
	})

	t.Run("WIMIssuerPolicy patching", func(t *testing.T) {
		existingPolicy := with(samplePolicy,
			"subject.commonName.type", "REQUIRED", // <- EXISTING
			"subject.commonName.minOccurrences", 1, // <- EXISTING
			"subject.commonName.maxOccurrences", 5, // <- EXISTING
		)
		givenManifests := undent.Undent(`
      kind: WIMIssuerPolicy
      name: mael
      validityPeriod: P90D
      subject:
        commonName: { type: OPTIONAL, minOccurrences: 0, maxOccurrences: 5 }        # <- CHANGED
      keyUsages:
        - digitalSignature
      extendedKeyUsages:
        - ANY
      keyAlgorithm:
        allowedValues:
          - EC_P256
        defaultValue: EC_P256
    `)
		expectPatch := `{"subject":{"commonName":{"allowedValues":null,"defaultValues":null,"maxOccurrences":5,"minOccurrences":0,"type":"OPTIONAL"}}}`

		// Note that the logic for checking these fields ('type', 'maxOccurrences',
		// etc) does not show any explanation whenever an error is found. The only
		// way to know what the problem is is to look at the backend code...
		// See: https://gitlab.com/venafi/vaas/applications/tls-protect/outage/-/blob/master/vcamanagement-service/src/main/java/com/venafi/condor/vcamanagement/web/v1/resource/VenafiCaIssuerPoliciesResourceV1.java#L545

		mock := []mocksrv.Interaction{
			{Expect: "GET /v1/distributedissuers/policies", MockCode: 200, MockBody: `{"policies": [` + existingPolicy + `]}`},
			{Expect: "PATCH /v1/distributedissuers/policies/d7a09670-9de6-11f0-b18d-1b1c0845fa26", MockCode: 200,
				MockBody: `{"policies": [` + existingPolicy + `]}`,
				Assert: func(t *testing.T, r *http.Request, gotBody string) {
					require.Equal(t, expectPatch, gotBody)
				},
			},
		}
		run(t, givenManifests, mock)
	})

	t.Run("ServiceAccount patching", func(t *testing.T) {
		existingSA := with(sampleSA,
			"enabled", true, // <- EXISTING
		)
		givenManifests := undent.Undent(`
      kind: ServiceAccount
      name: mael
      authenticationType: rsaKey
      credentialLifetime: 365
      enabled: true              # <- CHANGED
      scopes:
        - distributed-issuance
    `)
		expectPatch := `{
      "owner": "d2508300-3705-11ee-a17b-69a77fb429d7", "scopes": ["distributed-issuance"]
    }`
		mock := []mocksrv.Interaction{
			{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[` + existingSA + `]`},
			{Expect: "GET /v1/teams", MockCode: 200, MockBody: `{"teams": [` + sampleTeam + `]}`},
			{Expect: "PATCH /v1/serviceaccounts/d46f1f0d-299f-11ef-a8ac-2ea42f30fe31", MockCode: 200,
				MockBody: existingSA,
				Assert: func(t *testing.T, r *http.Request, gotBody string) {
					require.JSONEq(t, expectPatch, gotBody)
				},
			},
			{Expect: "GET /v1/serviceaccounts", MockCode: 200, MockBody: `[` + existingSA + `]`},
		}
		run(t, givenManifests, mock)
	})

}

func run(t *testing.T, givenManifests string, mock []mocksrv.Interaction) {
	_, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	srv := mocksrv.Mock(t, mock, cancel)

	manifests, err := parseManifests([]byte(givenManifests))
	require.NoError(t, err)
	dryrun := false

	cl, err := api.NewClient(srv.URL)
	require.NoError(t, err)

	err = applyManifests(cl, manifests, dryrun)
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

var sampleSubCA = `
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

var samplePolicy = `
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

// You can have multiple modifications in a single with() call by passing a
// slice of [path, value] pairs. Example:
//
//	modified := with(originalJSON,
//	  "foo.bar", 42,
//	  "baz.qux", "hello",
//	)
func with(jsonStr string, pathAndValue ...any) string {
	if len(pathAndValue)%2 != 0 {
		panic("with: pathAndValue must have even length")
	}
	for i := 0; i < len(pathAndValue); i += 2 {
		var err error
		jsonStr, err = sjson.Set(jsonStr, pathAndValue[i].(string), pathAndValue[i+1])
		if err != nil {
			panic(err)
		}
	}
	return jsonStr
}

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
      "kubernetes-discovery"
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
