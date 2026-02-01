package api

import (
	"testing"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffToPatchConfig(t *testing.T) {
	tests := []struct {
		name          string
		existing      ExtendedConfigurationInformation
		desired       ExtendedConfigurationInformation
		expect        func(t *testing.T, patch ConfigurationUpdateRequest)
		expectChanged bool
		expectErr     string // empty string means no error expected
	}{
		{
			name:          "No changes",
			existing:      ExtendedConfigurationInformation{},
			desired:       ExtendedConfigurationInformation{},
			expect:        patch(ConfigurationUpdateRequest{}),
			expectChanged: false,
		},

		// ServiceAccountIds tests.
		{
			name: "ServiceAccountIds added",
			existing: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			},
			desired: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
					id("22222222-2222-2222-2222-222222222222"),
				},
			},
			expect: patch(ConfigurationUpdateRequest{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
					id("22222222-2222-2222-2222-222222222222"),
				},
			}),
			expectChanged: true,
		},
		{
			name: "ServiceAccountIds removed",
			existing: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
					id("22222222-2222-2222-2222-222222222222"),
				},
			},
			desired: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			},
			expect: patch(ConfigurationUpdateRequest{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			}),
			expectChanged: true,
		},
		{
			name: "ServiceAccountIds unchanged",
			existing: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			},
			desired: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			},
			expect:        patch(ConfigurationUpdateRequest{}),
			expectChanged: false,
		},
		{
			name: "ServiceAccountIds empty to non-empty",
			existing: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{},
			},
			desired: ExtendedConfigurationInformation{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			},
			expect: patch(ConfigurationUpdateRequest{
				ServiceAccountIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			}),
			expectChanged: true,
		},

		// AdvancedSettings tests.
		{
			name:     "AdvancedSettings EnableIssuanceAuditLog changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				AdvancedSettings: AdvancedSettingsInformation{
					EnableIssuanceAuditLog: true,
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				t.Helper()
				val, err := patch.AdvancedSettings.EnableIssuanceAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val)
			},
			expectChanged: true,
		},
		{
			name:     "AdvancedSettings IncludeRawCertDataInAuditLog changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				AdvancedSettings: AdvancedSettingsInformation{
					IncludeRawCertDataInAuditLog: true,
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				val, err := patch.AdvancedSettings.IncludeRawCertDataInAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val)
			},
			expectChanged: true,
		},
		{
			name:     "AdvancedSettings RequireFIPSCompliantBuild changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				AdvancedSettings: AdvancedSettingsInformation{
					RequireFIPSCompliantBuild: true,
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				val, err := patch.AdvancedSettings.RequireFIPSCompliantBuild.Get()
				require.NoError(t, err)
				assert.True(t, val)
			},
			expectChanged: true,
		},
		{
			name:     "AdvancedSettings all fields changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				AdvancedSettings: AdvancedSettingsInformation{
					EnableIssuanceAuditLog:       true,
					IncludeRawCertDataInAuditLog: true,
					RequireFIPSCompliantBuild:    true,
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				val1, err := patch.AdvancedSettings.EnableIssuanceAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val1)
				val2, err := patch.AdvancedSettings.IncludeRawCertDataInAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val2)
				val3, err := patch.AdvancedSettings.RequireFIPSCompliantBuild.Get()
				require.NoError(t, err)
				assert.True(t, val3)
			},
			expectChanged: true,
		},

		// ClientAuthentication tests.
		{
			name:     "ClientAuthentication changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ClientAuthentication: clientAuthJwks(t, []string{"https://jwks.changed.example.com"}),
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				patchAuth, err := patch.ClientAuthentication.ValueByDiscriminator()
				require.NoError(t, err)
				patchJwks, ok := patchAuth.(JwtJwksAuthenticationInformation)
				require.True(t, ok)
				assert.Equal(t, []string{"https://jwks.changed.example.com"}, patchJwks.Urls)
			},
			expectChanged: true,
		},
		{
			name:     "ClientAuthentication required fields copied",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ClientAuthentication: clientAuthJwks(t, []string{"https://jwks.changed.example.com"}),
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				patchAuth, err := patch.ClientAuthentication.ValueByDiscriminator()
				require.NoError(t, err)
				patchJwks, ok := patchAuth.(JwtJwksAuthenticationInformation)
				require.True(t, ok)
				assert.Equal(t, []string{"https://jwks.changed.example.com"}, patchJwks.Urls)
			},
			expectChanged: true,
		},
		{
			name:     "ClientAuthentication zero-valued",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ClientAuthentication: ClientAuthenticationInformation{},
			},
			expect:        patch(ConfigurationUpdateRequest{}),
			expectChanged: false,
		},

		// ClientAuthorization tests.
		{
			name:     "ClientAuthorization changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ClientAuthorization: ClientAuthorizationInformation{
					CustomClaimsAliases: CustomClaimsAliasesInformation{
						Configuration:    "cfg",
						AllowAllPolicies: "allow-all",
						AllowedPolicies:  "allowed",
					},
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				assert.Equal(t, "cfg", patch.ClientAuthorization.CustomClaimsAliases.Configuration)
				assert.Equal(t, "allow-all", patch.ClientAuthorization.CustomClaimsAliases.AllowAllPolicies)
				assert.Equal(t, "allowed", patch.ClientAuthorization.CustomClaimsAliases.AllowedPolicies)
			},
			expectChanged: true,
		},

		// CloudProviders tests.
		{
			name:     "CloudProviders AWS changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				CloudProviders: CloudProvidersInformation{
					Aws: AwsCloudProviderInformation{
						AccountIds: []string{"999999999999"},
						Regions:    []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsEast1},
					},
				},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				assert.Equal(t, []string{"999999999999"}, patch.CloudProviders.Aws.AccountIds)
				assert.Equal(t, []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsEast1}, patch.CloudProviders.Aws.Regions)
			},
			expectChanged: true,
		},

		// MinTlsVersion tests.
		{
			name:     "MinTlsVersion changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				MinTlsVersion: ExtendedConfigurationInformationMinTlsVersionTLS13,
			},
			expect: patch(ConfigurationUpdateRequest{
				MinTlsVersion: ConfigurationUpdateRequestMinTlsVersionTLS13,
			}),
			expectChanged: true,
		},

		// Name tests.
		{
			name:     "Name changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				Name: "new-name",
			},
			expect: patch(ConfigurationUpdateRequest{
				Name: "new-name",
			}),
			expectChanged: true,
		},

		// PolicyIds tests.
		{
			name:     "PolicyIds changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				PolicyIds: []openapi_types.UUID{id("11111111-1111-1111-1111-111111111111")},
			},
			expect: patch(ConfigurationUpdateRequest{
				PolicyIds: []openapi_types.UUID{
					id("11111111-1111-1111-1111-111111111111"),
				},
			}),
			expectChanged: true,
		},

		// Multiple fields changed.
		{
			name:     "Multiple fields changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				AdvancedSettings: AdvancedSettingsInformation{
					EnableIssuanceAuditLog:       true,
					IncludeRawCertDataInAuditLog: true,
					RequireFIPSCompliantBuild:    true,
				},
				ClientAuthentication: clientAuthJwks(t, []string{"https://jwks.changed.example.com"}),
				ClientAuthorization: ClientAuthorizationInformation{
					CustomClaimsAliases: CustomClaimsAliasesInformation{
						Configuration:    "cfg",
						AllowAllPolicies: "allow-all",
						AllowedPolicies:  "allowed",
					},
				},
				CloudProviders: CloudProvidersInformation{
					Aws: AwsCloudProviderInformation{
						AccountIds: []string{"999999999999"},
						Regions:    []AwsCloudProviderInformationRegions{AwsCloudProviderInformationRegionsUsEast1},
					},
				},
				MinTlsVersion: ExtendedConfigurationInformationMinTlsVersionTLS13,
				Name:          "new-name",
				PolicyIds:     []openapi_types.UUID{id("11111111-1111-1111-1111-111111111111")},
			},
			expect: func(t *testing.T, patch ConfigurationUpdateRequest) {
				val1, err := patch.AdvancedSettings.EnableIssuanceAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val1)
				val2, err := patch.AdvancedSettings.IncludeRawCertDataInAuditLog.Get()
				require.NoError(t, err)
				assert.True(t, val2)
				val3, err := patch.AdvancedSettings.RequireFIPSCompliantBuild.Get()
				require.NoError(t, err)
				assert.True(t, val3)

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
				assert.Equal(t, []openapi_types.UUID{id("11111111-1111-1111-1111-111111111111")}, patch.PolicyIds)
			},
			expectChanged: true,
		},

		// Immutable field error tests.
		{
			name:     "companyId cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				CompanyId: id("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
			},
			expectErr: "cannot change the 'companyId' field",
		},
		{
			name:     "controllerAllowedPolicyIds cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ControllerAllowedPolicyIds: []openapi_types.UUID{id("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")},
			},
			expectErr: "cannot change the 'controllerAllowedPolicyIds' field",
		},
		{
			name:     "creationDate cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				CreationDate: "2025-01-01T00:00:00Z",
			},
			expectErr: "cannot change the 'creationDate' field",
		},
		{
			name:     "id cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				Id: id("cccccccc-cccc-cccc-cccc-cccccccccccc"),
			},
			expectErr: "cannot change the 'id' field",
		},
		{
			name:     "longLivedCertCount cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				LongLivedCertCount: 1,
			},
			expectErr: "cannot change the 'longLivedCertCount' field",
		},
		{
			name:     "modificationDate cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ModificationDate: "2025-01-02T00:00:00Z",
			},
			expectErr: "cannot change ModificationDate",
		},
		{
			name:     "policies cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				Policies: []PolicyInformation{{Name: "policy"}},
			},
			expectErr: "cannot change the 'policies' field",
		},
		{
			name:     "policyDefinitions cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				PolicyDefinitions: []PolicyInformation{{Name: "policy-def"}},
			},
			expectErr: "cannot change the 'policyDefinitions' field",
		},
		{
			name:     "shortLivedCertCount cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				ShortLivedCertCount: 1,
			},
			expectErr: "cannot change the 'shortLivedCertCount' field",
		},
		{
			name:     "subCaProvider cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				SubCaProvider: SubCaProviderInformation{Name: "changed"},
			},
			expectErr: "cannot change the 'subCaProvider' field",
		},
		{
			name:     "ultraShortLivedCertCount cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				UltraShortLivedCertCount: 1,
			},
			expectErr: "cannot change the 'ultraShortLivedCertCount' field",
		},
		{
			name:     "unixSocketAllowedPolicyIds cannot be changed",
			existing: ExtendedConfigurationInformation{},
			desired: ExtendedConfigurationInformation{
				UnixSocketAllowedPolicyIds: []openapi_types.UUID{id("dddddddd-dddd-dddd-dddd-dddddddddddd")},
			},
			expectErr: "cannot change the 'unixSocketAllowedPolicyIds' field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch, changed, err := DiffToPatchConfig(tt.existing, tt.desired)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
				assert.False(t, changed)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectChanged, changed)
				if tt.expect != nil {
					tt.expect(t, patch)
				}
			}
		})
	}
}

func patch(expected ConfigurationUpdateRequest) func(t *testing.T, actual ConfigurationUpdateRequest) {
	return func(t *testing.T, actual ConfigurationUpdateRequest) {
		t.Helper()
		assert.Equal(t, expected, actual)
	}
}

func clientAuthJwks(t *testing.T, urls []string) ClientAuthenticationInformation {
	t.Helper()

	var info ClientAuthenticationInformation
	err := info.FromJwtJwksAuthenticationInformation(JwtJwksAuthenticationInformation{Urls: urls})
	require.NoError(t, err)
	return info
}

func id(s string) openapi_types.UUID {
	return openapi_types.UUID(uuid.MustParse(s))
}
