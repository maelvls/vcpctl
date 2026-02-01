package main

import (
	"context"
	"fmt"
	"testing"

	api "github.com/maelvls/vcpctl/api"
	manifest "github.com/maelvls/vcpctl/manifest"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_manifestToAPIClientAuthentication(t *testing.T) {
	mockResolvePolicy := func(ctx context.Context, name string) (api.ExtendedPolicyInformation, error) {
		if name == "test-policy" {
			uuid := openapi_types.UUID{}
			_ = uuid.UnmarshalText([]byte("d7a09670-9de6-11f0-b18d-1b1c0845fa26"))
			return api.ExtendedPolicyInformation{Id: uuid}, nil
		}
		return api.ExtendedPolicyInformation{}, fmt.Errorf("policy not found: %s", name)
	}

	tests := []struct {
		name        string
		input       manifest.ClientAuthentication
		wantErr     bool
		errContains string
		expectAuth  func(t *testing.T, result api.ClientAuthenticationInformation)
	}{
		{
			name:       "works on zero value",
			input:      manifest.ClientAuthentication{},
			expectAuth: expectZeroClientAuth,
		},
		{
			name: "empty type with URLs set should error",
			input: manifest.ClientAuthentication{
				Type: "",
				URLs: []string{"https://example.com/jwks.json"},
			},
			wantErr:     true,
			errContains: "clientAuthentication.type' should be set",
		},
		{
			name: "empty type with Audience set should error",
			input: manifest.ClientAuthentication{
				Type:     "",
				Audience: "https://api.example.com",
			},
			wantErr:     true,
			errContains: "clientAuthentication.type' should be set",
		},
		{
			name: "empty type with BaseURL set should error",
			input: manifest.ClientAuthentication{
				Type:    "",
				BaseURL: "https://oidc.example.com",
			},
			wantErr:     true,
			errContains: "clientAuthentication.type' should be set",
		},
		{
			name: "empty type with Clients set should error",
			input: manifest.ClientAuthentication{
				Type:    "",
				Clients: []manifest.ClientAuthenticationClient{{Name: "client1"}},
			},
			wantErr:     true,
			errContains: "clientAuthentication.type' should be set",
		},
		{
			name: "JWT_JWKS with URLs",
			input: manifest.ClientAuthentication{
				Type: "JWT_JWKS",
				URLs: []string{
					"http://localhost:8000/.well-known/jwks.json",
					"http://example.com/jwks.json",
				},
			},
			wantErr: false,
			expectAuth: expectJwtJwks(api.JwtJwksAuthenticationInformation{
				Urls: []string{
					"http://localhost:8000/.well-known/jwks.json",
					"http://example.com/jwks.json",
				},
			}),
		},
		{
			name: "JWT_JWKS with empty URLs",
			input: manifest.ClientAuthentication{
				Type: "JWT_JWKS",
				URLs: []string{},
			},
			wantErr: false,
			expectAuth: expectJwtJwks(api.JwtJwksAuthenticationInformation{
				Urls: nil,
			}),
		},
		{
			name: "JWT_STANDARD_CLAIMS with audience and clients",
			input: manifest.ClientAuthentication{
				Type:     "JWT_STANDARD_CLAIMS",
				Audience: "https://api.example.com",
				Clients: []manifest.ClientAuthenticationClient{{
					Name:            "client1",
					Issuer:          "https://issuer.example.com",
					JwksURI:         "https://issuer.example.com/.well-known/jwks.json",
					Subjects:        []string{"test-subject", "another-subject"},
					AllowedPolicies: []string{"test-policy"},
				}},
			},
			wantErr: false,
			expectAuth: expectJwtStandardClaims(api.JwtStandardClaimsAuthenticationInformation{
				Audience: "https://api.example.com",
				Clients: []api.JwtClientInformation{{
					Name:    "client1",
					Issuer:  "https://issuer.example.com",
					JwksUri: "https://issuer.example.com/.well-known/jwks.json",
					Subjects: []string{
						"test-subject",
						"another-subject",
					},
					AllowedPolicyIds: []openapi_types.UUID{
						mustParseUUID("d7a09670-9de6-11f0-b18d-1b1c0845fa26"),
					},
				}},
			}),
		},
		{
			name: "JWT_STANDARD_CLAIMS with empty clients",
			input: manifest.ClientAuthentication{
				Type:     "JWT_STANDARD_CLAIMS",
				Audience: "https://api.example.com",
				Clients:  []manifest.ClientAuthenticationClient{},
			},
			wantErr: false,
			expectAuth: expectJwtStandardClaims(api.JwtStandardClaimsAuthenticationInformation{
				Audience: "https://api.example.com",
				Clients:  nil,
			}),
		},
		{
			name: "JWT_STANDARD_CLAIMS with policy resolution error",
			input: manifest.ClientAuthentication{
				Type:     "JWT_STANDARD_CLAIMS",
				Audience: "https://api.example.com",
				Clients: []manifest.ClientAuthenticationClient{{
					Name:            "client1",
					Issuer:          "https://issuer.example.com",
					JwksURI:         "https://issuer.example.com/.well-known/jwks.json",
					Subjects:        []string{"test-subject"},
					AllowedPolicies: []string{"non-existent-policy"},
				}},
			},
			wantErr:     true,
			errContains: "policy not found: non-existent-policy",
		},
		{
			name: "JWT_OIDC with baseUrl and audience",
			input: manifest.ClientAuthentication{
				Type:     "JWT_OIDC",
				BaseURL:  "https://oidc.example.com",
				Audience: "https://api.example.com",
			},
			wantErr: false,
			expectAuth: expectJwtOidc(api.JwtOidcAuthenticationInformation{
				BaseUrl:  "https://oidc.example.com",
				Audience: "https://api.example.com",
			}),
		},
		{
			name: "unknown client authentication type",
			input: manifest.ClientAuthentication{
				Type: "UNKNOWN_TYPE",
			},
			wantErr:     true,
			errContains: "unknown ClientAuthentication type: UNKNOWN_TYPE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := manifestToAPIClientAuthentication(ctx, mockResolvePolicy, tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.expectAuth != nil {
				tt.expectAuth(t, result)
			}
		})
	}
}

func expectZeroClientAuth(t *testing.T, result api.ClientAuthenticationInformation) {
	t.Helper()
	assert.True(t, api.IsZero(result), "expected zero value for empty client authentication")
}

func expectJwtJwks(expected api.JwtJwksAuthenticationInformation) func(t *testing.T, result api.ClientAuthenticationInformation) {
	return func(t *testing.T, result api.ClientAuthenticationInformation) {
		t.Helper()
		v, err := result.ValueByDiscriminator()
		require.NoError(t, err)
		jwks, ok := v.(api.JwtJwksAuthenticationInformation)
		require.True(t, ok, "expected JwtJwksAuthenticationInformation type")
		assert.Equal(t, expected.Urls, jwks.Urls)
	}
}

func expectJwtOidc(expected api.JwtOidcAuthenticationInformation) func(t *testing.T, result api.ClientAuthenticationInformation) {
	return func(t *testing.T, result api.ClientAuthenticationInformation) {
		t.Helper()
		v, err := result.ValueByDiscriminator()
		require.NoError(t, err)
		oidc, ok := v.(api.JwtOidcAuthenticationInformation)
		require.True(t, ok, "expected JwtOidcAuthenticationInformation type")
		assert.Equal(t, expected.BaseUrl, oidc.BaseUrl)
		assert.Equal(t, expected.Audience, oidc.Audience)
	}
}

func expectJwtStandardClaims(expected api.JwtStandardClaimsAuthenticationInformation) func(t *testing.T, result api.ClientAuthenticationInformation) {
	return func(t *testing.T, result api.ClientAuthenticationInformation) {
		t.Helper()
		v, err := result.ValueByDiscriminator()
		require.NoError(t, err)
		standardClaims, ok := v.(api.JwtStandardClaimsAuthenticationInformation)
		require.True(t, ok, "expected JwtStandardClaimsAuthenticationInformation type")
		assert.Equal(t, expected.Audience, standardClaims.Audience)
		assert.Equal(t, expected.Clients, standardClaims.Clients)
	}
}

func mustParseUUID(s string) openapi_types.UUID {
	uuid := openapi_types.UUID{}
	if err := uuid.UnmarshalText([]byte(s)); err != nil {
		panic(fmt.Sprintf("failed to parse UUID %q: %v", s, err))
	}
	return uuid
}
