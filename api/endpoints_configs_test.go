package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/oapi-codegen/nullable"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffToPatchConfig_NoChanges(t *testing.T) {
	existing := baseConfig(t)
	desired := existing

	patch, changed, err := DiffToPatchConfig(existing, desired)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, ConfigurationUpdateRequest{}, patch)
}

func TestDiffToPatchConfig_AllowedFieldChanges(t *testing.T) {
	existing := baseConfig(t)
	desired := existing

	desired.AdvancedSettings.EnableIssuanceAuditLog = true
	desired.AdvancedSettings.IncludeRawCertDataInAuditLog = true
	desired.AdvancedSettings.RequireFIPSCompliantBuild = true

	desired.ClientAuthentication = clientAuthJwks(t, []string{"https://jwks.changed.example.com"})
	desired.ClientAuthorization = ClientAuthorizationInformation{
		CustomClaimsAliases: CustomClaimsAliasesInformation{
			Configuration:    "cfg",
			AllowAllPolicies: "allow-all",
			AllowedPolicies:  "allowed",
		},
	}

	desired.CloudProviders = CloudProvidersInformation{
		Aws: AwsCloudProviderInformation{
			AccountIds: []string{"999999999999"},
			Regions:    []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsEast1},
		},
	}

	desired.MinTlsVersion = ExtendedConfigurationInformationMinTlsVersionTLS13
	desired.Name = "new-name"
	desired.PolicyIds = []openapi_types.UUID{mustUUID(t, "11111111-1111-1111-1111-111111111111")}

	patch, changed, err := DiffToPatchConfig(existing, desired)
	require.NoError(t, err)
	require.True(t, changed)

	assertEqual(t, true, patch.AdvancedSettings.EnableIssuanceAuditLog)
	assertEqual(t, true, patch.AdvancedSettings.IncludeRawCertDataInAuditLog)
	assertEqual(t, true, patch.AdvancedSettings.RequireFIPSCompliantBuild)

	patchAuth, err := patch.ClientAuthentication.ValueByDiscriminator()
	require.NoError(t, err)
	patchJwks, ok := patchAuth.(JwtJwksAuthenticationInformation)
	require.True(t, ok)
	assert.Equal(t, []string{"https://jwks.changed.example.com"}, patchJwks.Urls)

	assert.Equal(t, "cfg", patch.ClientAuthorization.CustomClaimsAliases.Configuration)
	assert.Equal(t, "allow-all", patch.ClientAuthorization.CustomClaimsAliases.AllowAllPolicies)
	assert.Equal(t, "allowed", patch.ClientAuthorization.CustomClaimsAliases.AllowedPolicies)

	assert.Equal(t, []string{"999999999999"}, patch.CloudProviders.Aws.AccountIds)
	assert.Equal(t, []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsEast1}, patch.CloudProviders.Aws.Regions)

	assert.Equal(t, ConfigurationUpdateRequestMinTlsVersionTLS13, patch.MinTlsVersion)
	assert.Equal(t, "new-name", patch.Name)
	assert.Equal(t, []openapi_types.UUID{mustUUID(t, "11111111-1111-1111-1111-111111111111")}, patch.PolicyIds)
}

func assertEqual[V any](t *testing.T, expected V, actual nullable.Nullable[V]) {
	t.Helper()

	val, err := actual.Get()
	require.NoError(t, err)
	assert.Equal(t, expected, val)
}

func TestDiffToPatchConfig_ImmutableFieldErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(ExtendedConfigurationInformation) ExtendedConfigurationInformation
	}{
		{
			name: "companyId",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.CompanyId = mustUUID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
				return cfg
			},
		},
		{
			name: "controllerAllowedPolicyIds",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.ControllerAllowedPolicyIds = []openapi_types.UUID{mustUUID(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")}
				return cfg
			},
		},
		{
			name: "creationDate",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.CreationDate = "2025-01-01T00:00:00Z"
				return cfg
			},
		},
		{
			name: "id",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.Id = mustUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
				return cfg
			},
		},
		{
			name: "longLivedCertCount",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.LongLivedCertCount = 1
				return cfg
			},
		},
		{
			name: "modificationDate",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.ModificationDate = "2025-01-02T00:00:00Z"
				return cfg
			},
		},
		{
			name: "policies",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.Policies = []PolicyInformation{{Name: "policy"}}
				return cfg
			},
		},
		{
			name: "policyDefinitions",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.PolicyDefinitions = []PolicyInformation{{Name: "policy-def"}}
				return cfg
			},
		},
		{
			name: "shortLivedCertCount",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.ShortLivedCertCount = 1
				return cfg
			},
		},
		{
			name: "subCaProvider",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.SubCaProvider = SubCaProviderInformation{Name: "changed"}
				return cfg
			},
		},
		{
			name: "ultraShortLivedCertCount",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.UltraShortLivedCertCount = 1
				return cfg
			},
		},
		{
			name: "unixSocketAllowedPolicyIds",
			mutate: func(cfg ExtendedConfigurationInformation) ExtendedConfigurationInformation {
				cfg.UnixSocketAllowedPolicyIds = []openapi_types.UUID{mustUUID(t, "dddddddd-dddd-dddd-dddd-dddddddddddd")}
				return cfg
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := baseConfig(t)
			desired := tt.mutate(existing)

			_, changed, err := DiffToPatchConfig(existing, desired)
			require.Error(t, err)
			assert.False(t, changed)
		})
	}
}

func TestDiffToPatchConfig_ClientAuthenticationError(t *testing.T) {
	existing := baseConfig(t)
	desired := existing
	desired.ClientAuthentication = ClientAuthenticationInformation{}

	_, changed, err := DiffToPatchConfig(existing, desired)
	require.Error(t, err)
	assert.False(t, changed)
}

func baseConfig(t *testing.T) ExtendedConfigurationInformation {
	t.Helper()

	return ExtendedConfigurationInformation{
		AdvancedSettings: AdvancedSettingsInformation{
			EnableIssuanceAuditLog:       false,
			IncludeRawCertDataInAuditLog: false,
			RequireFIPSCompliantBuild:    false,
		},
		ClientAuthentication: clientAuthJwks(t, []string{"https://jwks.example.com"}),
		ClientAuthorization: ClientAuthorizationInformation{
			CustomClaimsAliases: CustomClaimsAliasesInformation{},
		},
		CloudProviders: CloudProvidersInformation{
			Aws: AwsCloudProviderInformation{
				AccountIds: []string{"123456789012"},
				Regions:    []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsWest2},
			},
		},
		MinTlsVersion: ExtendedConfigurationInformationMinTlsVersionTLS12,
		Name:          "base-name",
		PolicyIds:     []openapi_types.UUID{mustUUID(t, "00000000-0000-0000-0000-000000000001")},
	}
}

func clientAuthJwks(t *testing.T, urls []string) ClientAuthenticationInformation {
	t.Helper()

	var info ClientAuthenticationInformation
	err := info.FromJwtJwksAuthenticationInformation(JwtJwksAuthenticationInformation{Urls: urls})
	require.NoError(t, err)
	return info
}

func mustUUID(t *testing.T, s string) openapi_types.UUID {
	t.Helper()
	return openapi_types.UUID(uuid.MustParse(s))
}
