package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_registeredTenantURLPrefixFromTenantURL(t *testing.T) {
	tests := []struct {
		name      string
		tenantURL string
		want      string
		wantErr   bool
	}{
		{
			name:      "production tenant",
			tenantURL: "https://glow-in-the-dark.venafi.cloud",
			want:      "glow-in-the-dark",
			wantErr:   false,
		},
		{
			name:      "dev environment with ui-stack prefix",
			tenantURL: "https://ui-stack-dev210.qa.venafi.io",
			want:      "stack",
			wantErr:   false,
		},
		{
			name:      "dev environment with ui-stack prefix and different number",
			tenantURL: "https://ui-stack-dev247.qa.venafi.io",
			want:      "stack",
			wantErr:   false,
		},
		{
			name:      "another production tenant",
			tenantURL: "https://my-company",
			want:      "my-company",
			wantErr:   false,
		},
		{
			name:      "production tenant with hyphens",
			tenantURL: "https://my-special-tenant",
			want:      "my-special-tenant",
			wantErr:   false,
		},
		{
			name:      "ui-stack prefix with dev999",
			tenantURL: "https://ui-stack-dev999.qa.venafi.io",
			want:      "stack",
			wantErr:   false,
		},
		{
			name:      "ui-stack prefix with dev100",
			tenantURL: "https://ui-stack-dev100.qa.venafi.io",
			want:      "stack",
			wantErr:   false,
		},
		{
			name:      "tenant without domain but with trailing slash",
			tenantURL: "https://my-company/",
			want:      "my-company",
			wantErr:   false,
		},
		{
			name:      "production tenant with trailing slash",
			tenantURL: "https://glow-in-the-dark.venafi.cloud/",
			want:      "glow-in-the-dark",
			wantErr:   false,
		},
		{
			name:      "dev environment with trailing slash",
			tenantURL: "https://ui-stack-dev210.qa.venafi.io/",
			want:      "stack",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualTenantURLPrefix, err := prefixOf(tt.tenantURL)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error extracting actual tenant URL prefix: %v", err)
				}
				return
			}

			got, err := actualToRegistered(actualTenantURLPrefix)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_actualTenantURLPrefixFromRegisteredTenantURLPrefix(t *testing.T) {
	tests := []struct {
		name       string
		tenantName string
		apiURL     string
		want       string
		wantErr    bool
	}{
		{
			name:       "production tenant name returned as-is",
			tenantName: "my-company",
			apiURL:     "https://api.venafi.cloud",
			want:       "my-company",
			wantErr:    false,
		},
		{
			name:       "production tenant with hyphens returned as-is",
			tenantName: "glow-in-the-dark",
			apiURL:     "https://api.venafi.cloud",
			want:       "glow-in-the-dark",
			wantErr:    false,
		},
		{
			name:       "stack tenant with https devstack URL",
			tenantName: "stack",
			apiURL:     "https://api-dev210.qa.venafi.io",
			want:       "ui-stack-dev210",
			wantErr:    false,
		},
		{
			name:       "stack tenant with http devstack URL",
			tenantName: "stack",
			apiURL:     "http://api-dev247.qa.venafi.io",
			want:       "ui-stack-dev247",
			wantErr:    false,
		},
		{
			name:       "stack tenant without protocol",
			tenantName: "stack",
			apiURL:     "api-dev100.qa.venafi.io",
			want:       "ui-stack-dev100",
			wantErr:    false,
		},
		{
			name:       "stack tenant with different devstack number",
			tenantName: "stack",
			apiURL:     "https://api-dev999.qa.venafi.io",
			want:       "ui-stack-dev999",
			wantErr:    false,
		},
		{
			name:       "stack tenant with URL without dot returns error",
			tenantName: "stack",
			apiURL:     "https://api-dev210",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "stack tenant with URL without domain parts returns error",
			tenantName: "stack",
			apiURL:     "api-dev210",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "stack tenant with custom domain",
			tenantName: "stack",
			apiURL:     "https://api-dev123.example.com",
			want:       "ui-stack-dev123",
			wantErr:    false,
		},
		{
			name:       "another production tenant",
			tenantName: "my-special-tenant",
			apiURL:     "https://api.venafi.cloud",
			want:       "my-special-tenant",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registeredToActual(tt.tenantName, tt.apiURL)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
