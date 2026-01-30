package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiffToPatchClientAuthentication(t *testing.T) {
	tests := []struct {
		name          string
		existing      ClientAuthenticationInformation
		desired       ClientAuthenticationInformation
		expectPatch   func(t *testing.T, patch ClientAuthenticationInformation)
		expectChanged bool
		expectErr     string // empty string means no error expected
	}{
		// No changes test cases
		{
			name:          "JWT_JWKS no changes",
			existing:      clientAuthJwks(t, []string{"https://jwks.example.com"}),
			desired:       clientAuthJwks(t, []string{"https://jwks.example.com"}),
			expectPatch:   emptyPatch,
			expectChanged: false,
		},
		{
			name:          "JWT_OIDC no changes",
			existing:      clientAuthOidc(t, "https://oidc.example.com", "my-audience"),
			desired:       clientAuthOidc(t, "https://oidc.example.com", "my-audience"),
			expectPatch:   emptyPatch,
			expectChanged: false,
		},
		{
			name:          "JWT_STANDARD_CLAIMS no changes",
			existing:      clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			desired:       clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			expectPatch:   emptyPatch,
			expectChanged: false,
		},
		{
			name:          "Zero-valued existing and desired",
			existing:      ClientAuthenticationInformation{},
			desired:       ClientAuthenticationInformation{},
			expectPatch:   emptyPatch,
			expectChanged: false,
		},

		// JWT_JWKS changes
		{
			name:     "JWT_JWKS URLs changed",
			existing: clientAuthJwks(t, []string{"https://jwks.example.com"}),
			desired:  clientAuthJwks(t, []string{"https://jwks.changed.example.com", "https://jwks2.example.com"}),
			expectPatch: isJwtJwks(JwtJwksAuthenticationInformation{
				Urls: []string{"https://jwks.changed.example.com", "https://jwks2.example.com"},
			}),
			expectChanged: true,
		},

		// JWT_OIDC changes
		{
			name:     "JWT_OIDC both BaseUrl and Audience changed",
			existing: clientAuthOidc(t, "https://oidc.example.com", "old-audience"),
			desired:  clientAuthOidc(t, "https://oidc.new.example.com", "new-audience"),
			expectPatch: isJwtOidc(JwtOidcAuthenticationInformation{
				BaseUrl:  "https://oidc.new.example.com",
				Audience: "new-audience",
			}),
			expectChanged: true,
		},
		{
			name:     "JWT_OIDC only BaseUrl changed",
			existing: clientAuthOidc(t, "https://oidc.example.com", "my-audience"),
			desired:  clientAuthOidc(t, "https://oidc.new.example.com", "my-audience"),
			expectPatch: isJwtOidc(JwtOidcAuthenticationInformation{
				BaseUrl:  "https://oidc.new.example.com",
				Audience: "my-audience",
			}),
			expectChanged: true,
		},
		{
			name:     "JWT_OIDC only Audience changed",
			existing: clientAuthOidc(t, "https://oidc.example.com", "old-audience"),
			desired:  clientAuthOidc(t, "https://oidc.example.com", "new-audience"),
			expectPatch: isJwtOidc(JwtOidcAuthenticationInformation{
				BaseUrl:  "https://oidc.example.com",
				Audience: "new-audience",
			}),
			expectChanged: true,
		},

		// JWT_STANDARD_CLAIMS changes
		{
			name:     "JWT_STANDARD_CLAIMS audience changed",
			existing: clientAuthStandardClaims(t, "old-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			desired:  clientAuthStandardClaims(t, "new-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			expectPatch: isJwtStandardClaims(JwtStandardClaimsAuthenticationInformation{
				Audience: "new-audience",
				Clients:  []JwtClientInformation{},
			}),
			expectChanged: true,
		},
		{
			name:     "JWT_STANDARD_CLAIMS clients changed",
			existing: clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			desired:  clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer2", JwksUri: "https://jwks2.example.com", Name: "client2"}}),
			expectPatch: isJwtStandardClaims(JwtStandardClaimsAuthenticationInformation{
				Audience: "",
				Clients:  []JwtClientInformation{{Issuer: "issuer2", JwksUri: "https://jwks2.example.com", Name: "client2"}},
			}),
			expectChanged: true,
		},
		{
			name:     "JWT_STANDARD_CLAIMS both audience and clients changed",
			existing: clientAuthStandardClaims(t, "old-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			desired:  clientAuthStandardClaims(t, "new-audience", []JwtClientInformation{{Issuer: "issuer2", JwksUri: "https://jwks2.example.com", Name: "client2"}}),
			expectPatch: isJwtStandardClaims(JwtStandardClaimsAuthenticationInformation{
				Audience: "new-audience",
				Clients:  []JwtClientInformation{{Issuer: "issuer2", JwksUri: "https://jwks2.example.com", Name: "client2"}},
			}),
			expectChanged: true,
		},

		// Type changes.
		{
			name:     "Type change: JWKS to OIDC",
			existing: clientAuthJwks(t, []string{"https://jwks.example.com"}),
			desired:  clientAuthOidc(t, "https://oidc.example.com", "my-audience"),
			expectPatch: isJwtOidc(JwtOidcAuthenticationInformation{
				BaseUrl:  "https://oidc.example.com",
				Audience: "my-audience",
			}),
			expectChanged: true,
		},
		{
			name:     "Type change: OIDC to STANDARD_CLAIMS",
			existing: clientAuthOidc(t, "https://oidc.example.com", "my-audience"),
			desired:  clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			expectPatch: isJwtStandardClaims(JwtStandardClaimsAuthenticationInformation{
				Audience: "my-audience",
				Clients:  []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}},
			}),
			expectChanged: true,
		},
		{
			name:     "Type change: STANDARD_CLAIMS to JWKS",
			existing: clientAuthStandardClaims(t, "my-audience", []JwtClientInformation{{Issuer: "issuer1", JwksUri: "https://jwks1.example.com", Name: "client1"}}),
			desired:  clientAuthJwks(t, []string{"https://jwks.example.com"}),
			expectPatch: isJwtJwks(JwtJwksAuthenticationInformation{
				Urls: []string{"https://jwks.example.com"},
			}),
			expectChanged: true,
		},

		// Zero to non-zero (when the existing 'clientAuthentication' was zero-valued, the patch is equal to the desired)
		{
			name:     "Zero to non-zero",
			existing: ClientAuthenticationInformation{},
			desired:  clientAuthJwks(t, []string{"https://jwks.example.com"}),
			expectPatch: isJwtJwks(JwtJwksAuthenticationInformation{
				Urls: []string{"https://jwks.example.com"},
			}),
			expectChanged: true,
		},

		// When the desired is zero-valued, let's do nothing.
		{
			name:          "Non-zero to zero returns error",
			existing:      clientAuthJwks(t, []string{"https://jwks.example.com"}),
			desired:       ClientAuthenticationInformation{},
			expectPatch:   emptyPatch,
			expectChanged: false,
		},

		// Required fields are copied (when one field changes in JWT_JWKS, all required fields should be copied)
		{
			name:     "JWT_JWKS required fields copied",
			existing: clientAuthJwks(t, []string{"https://jwks.example.com", "https://jwks2.example.com"}),
			desired:  clientAuthJwks(t, []string{"https://jwks.changed.example.com", "https://jwks2.example.com"}),
			expectPatch: isJwtJwks(JwtJwksAuthenticationInformation{
				Urls: []string{"https://jwks.changed.example.com", "https://jwks2.example.com"},
			}),
			expectChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch, changed, err := DiffToPatchClientAuthentication(tt.existing, tt.desired)

			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
				assert.False(t, changed)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectChanged, changed)
				if tt.expectPatch != nil {
					tt.expectPatch(t, patch)
				}
			}
		})
	}
}

func clientAuthOidc(t *testing.T, baseUrl, audience string) ClientAuthenticationInformation {
	t.Helper()

	var info ClientAuthenticationInformation
	err := info.FromJwtOidcAuthenticationInformation(JwtOidcAuthenticationInformation{
		BaseUrl:  baseUrl,
		Audience: audience,
	})
	require.NoError(t, err)
	return info
}

func clientAuthStandardClaims(t *testing.T, audience string, clients []JwtClientInformation) ClientAuthenticationInformation {
	t.Helper()

	var info ClientAuthenticationInformation
	err := info.FromJwtStandardClaimsAuthenticationInformation(JwtStandardClaimsAuthenticationInformation{
		Audience: audience,
		Clients:  clients,
	})
	require.NoError(t, err)
	return info
}

// Helper functions for expectPatch validation

func emptyPatch(t *testing.T, patch ClientAuthenticationInformation) {
	t.Helper()
	assert.True(t, IsZero(patch), "Expected patch to be zero-valued")
}

func isJwtJwks(expected JwtJwksAuthenticationInformation) func(t *testing.T, patch ClientAuthenticationInformation) {
	return func(t *testing.T, patch ClientAuthenticationInformation) {
		t.Helper()
		patchVal, err := patch.ValueByDiscriminator()
		require.NoError(t, err)
		patchJwks, ok := patchVal.(JwtJwksAuthenticationInformation)
		require.True(t, ok, "Expected patch to be JwtJwksAuthenticationInformation")
		// Compare only the meaningful fields (ignore Type discriminator)
		assert.Equal(t, expected.Urls, patchJwks.Urls)
	}
}

func isJwtOidc(expected JwtOidcAuthenticationInformation) func(t *testing.T, patch ClientAuthenticationInformation) {
	return func(t *testing.T, patch ClientAuthenticationInformation) {
		t.Helper()
		patchVal, err := patch.ValueByDiscriminator()
		require.NoError(t, err)
		patchOidc, ok := patchVal.(JwtOidcAuthenticationInformation)
		require.True(t, ok, "Expected patch to be JwtOidcAuthenticationInformation")
		// Compare only the meaningful fields (ignore Type discriminator)
		assert.Equal(t, expected.BaseUrl, patchOidc.BaseUrl)
		assert.Equal(t, expected.Audience, patchOidc.Audience)
	}
}

func isJwtStandardClaims(expected JwtStandardClaimsAuthenticationInformation) func(t *testing.T, patch ClientAuthenticationInformation) {
	return func(t *testing.T, patch ClientAuthenticationInformation) {
		t.Helper()
		patchVal, err := patch.ValueByDiscriminator()
		require.NoError(t, err)
		patchStdClaims, ok := patchVal.(JwtStandardClaimsAuthenticationInformation)
		require.True(t, ok, "Expected patch to be JwtStandardClaimsAuthenticationInformation")
		// Compare only the meaningful fields (ignore Type discriminator)
		if expected.Audience != "" {
			assert.Equal(t, expected.Audience, patchStdClaims.Audience)
		}
		// For Clients, compare only if expected is non-empty, and filter out zero-valued entries from patch
		if len(expected.Clients) > 0 {
			// Filter non-zero clients from patch
			var nonZeroClients []JwtClientInformation
			for _, c := range patchStdClaims.Clients {
				if c.Issuer != "" || c.JwksUri != "" || c.Name != "" {
					nonZeroClients = append(nonZeroClients, c)
				}
			}
			assert.Equal(t, expected.Clients, nonZeroClients)
		}
	}
}
