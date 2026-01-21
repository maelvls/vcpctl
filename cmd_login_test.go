package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestConvertOldToNewConfig(t *testing.T) {
	tests := []struct {
		name string
		old  OldFileConf
		want FileConf
	}{
		{
			name: "basic conversion with single auth",
			old: OldFileConf{
				CurrentURL: "https://my-tenant.venafi.cloud",
				Auths: []OldAuth{
					{
						URL:      "https://my-tenant.venafi.cloud",
						APIURL:   "https://api.uk.venafi.cloud",
						APIKey:   "2e9c87e3-6ad7-4878-937c-111291dab6d0",
						TenantID: "c0f2c691-ab9b-11ed-bfed-b3b2b59a7f20",
					},
				},
			},
			want: FileConf{
				CurrentContext: "https://my-tenant.venafi.cloud",
				ToolContexts: []ToolContext{
					{
						Name:               "https://my-tenant.venafi.cloud",
						TenantURL:          "https://my-tenant.venafi.cloud",
						APIURL:             "https://api.uk.venafi.cloud",
						AuthenticationType: "apiKey",
						APIKey:             "2e9c87e3-6ad7-4878-937c-111291dab6d0",
						TenantID:           "c0f2c691-ab9b-11ed-bfed-b3b2b59a7f20",
					},
				},
			},
		},
		{
			name: "multiple auths",
			old: OldFileConf{
				CurrentURL: "https://tenant1.example.com",
				Auths: []OldAuth{
					{
						URL:      "https://tenant1.example.com",
						APIURL:   "https://api.example.com",
						APIKey:   "key-111",
						TenantID: "tenant-id-1",
					},
					{
						URL:      "https://tenant2.example.com",
						APIURL:   "https://api2.example.com",
						APIKey:   "key-222",
						TenantID: "tenant-id-2",
					},
				},
			},
			want: FileConf{
				CurrentContext: "https://tenant1.example.com",
				ToolContexts: []ToolContext{
					{
						Name:               "https://tenant1.example.com",
						TenantURL:          "https://tenant1.example.com",
						APIURL:             "https://api.example.com",
						AuthenticationType: "apiKey",
						APIKey:             "key-111",
						TenantID:           "tenant-id-1",
					},
					{
						Name:               "https://tenant2.example.com",
						TenantURL:          "https://tenant2.example.com",
						APIURL:             "https://api2.example.com",
						AuthenticationType: "apiKey",
						APIKey:             "key-222",
						TenantID:           "tenant-id-2",
					},
				},
			},
		},
		{
			name: "empty currentURL",
			old: OldFileConf{
				CurrentURL: "",
				Auths: []OldAuth{
					{
						URL:      "https://tenant.example.com",
						APIURL:   "https://api.example.com",
						APIKey:   "test-key",
						TenantID: "test-tenant",
					},
				},
			},
			want: FileConf{
				CurrentContext: "",
				ToolContexts: []ToolContext{
					{
						Name:               "https://tenant.example.com",
						TenantURL:          "https://tenant.example.com",
						APIURL:             "https://api.example.com",
						AuthenticationType: "apiKey",
						APIKey:             "test-key",
						TenantID:           "test-tenant",
					},
				},
			},
		},
		{
			name: "empty auths list",
			old: OldFileConf{
				CurrentURL: "https://tenant.example.com",
				Auths:      []OldAuth{},
			},
			want: FileConf{
				CurrentContext: "https://tenant.example.com",
				ToolContexts:   nil,
			},
		},
		{
			name: "auth without tenantID",
			old: OldFileConf{
				CurrentURL: "https://tenant.example.com",
				Auths: []OldAuth{
					{
						URL:      "https://tenant.example.com",
						APIURL:   "https://api.example.com",
						APIKey:   "test-key",
						TenantID: "",
					},
				},
			},
			want: FileConf{
				CurrentContext: "https://tenant.example.com",
				ToolContexts: []ToolContext{
					{
						Name:               "https://tenant.example.com",
						TenantURL:          "https://tenant.example.com",
						APIURL:             "https://api.example.com",
						AuthenticationType: "apiKey",
						APIKey:             "test-key",
						TenantID:           "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertOldToNewConfig(tt.old)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("convertOldToNewConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConvertOldToNewConfig_EmailAndUserIDNotSet(t *testing.T) {
	// Verify that Email and UserID fields are not set in converted config
	// since they didn't exist in the old format
	old := OldFileConf{
		CurrentURL: "https://tenant.example.com",
		Auths: []OldAuth{
			{
				URL:      "https://tenant.example.com",
				APIURL:   "https://api.example.com",
				APIKey:   "test-key",
				TenantID: "test-tenant",
			},
		},
	}

	got := convertOldToNewConfig(old)

	if len(got.ToolContexts) != 1 {
		t.Fatalf("expected 1 context, got %d", len(got.ToolContexts))
	}

	ctx := got.ToolContexts[0]
	if ctx.Email != "" {
		t.Errorf("expected Email to be empty, got %q", ctx.Email)
	}
	if ctx.UserID != "" {
		t.Errorf("expected UserID to be empty, got %q", ctx.UserID)
	}
}

func TestConvertOldToNewConfig_AuthenticationTypeIsAlwaysAPIKey(t *testing.T) {
	// The old format only supported API key authentication
	old := OldFileConf{
		CurrentURL: "https://tenant.example.com",
		Auths: []OldAuth{
			{
				URL:      "https://tenant1.example.com",
				APIURL:   "https://api1.example.com",
				APIKey:   "key-1",
				TenantID: "tenant-1",
			},
			{
				URL:      "https://tenant2.example.com",
				APIURL:   "https://api2.example.com",
				APIKey:   "key-2",
				TenantID: "tenant-2",
			},
		},
	}

	got := convertOldToNewConfig(old)

	for i, ctx := range got.ToolContexts {
		if ctx.AuthenticationType != "apiKey" {
			t.Errorf("context[%d].AuthenticationType = %q, want %q",
				i, ctx.AuthenticationType, "apiKey")
		}
	}
}

func TestConvertOldToNewConfig_ContextNameMatchesURL(t *testing.T) {
	// In the conversion, the context name should be set to the URL
	old := OldFileConf{
		CurrentURL: "https://my-tenant.venafi.cloud",
		Auths: []OldAuth{
			{
				URL:      "https://my-tenant.venafi.cloud",
				APIURL:   "https://api.uk.venafi.cloud",
				APIKey:   "test-key",
				TenantID: "test-tenant",
			},
			{
				URL:      "https://ui-stack-dev210.qa.venafi.io",
				APIURL:   "https://api.qa.venafi.io",
				APIKey:   "test-key-2",
				TenantID: "test-tenant-2",
			},
		},
	}

	got := convertOldToNewConfig(old)

	for i, ctx := range got.ToolContexts {
		expectedName := old.Auths[i].URL
		if ctx.Name != expectedName {
			t.Errorf("context[%d].Name = %q, want %q", i, ctx.Name, expectedName)
		}
		if ctx.Name != ctx.TenantURL {
			t.Errorf("context[%d].Name (%q) should match TenantURL (%q)",
				i, ctx.Name, ctx.TenantURL)
		}
	}
}

func TestConvertOldToNewConfig_CurrentContextMatchesCurrentURL(t *testing.T) {
	old := OldFileConf{
		CurrentURL: "https://my-tenant.venafi.cloud",
		Auths: []OldAuth{
			{
				URL:      "https://my-tenant.venafi.cloud",
				APIURL:   "https://api.venafi.cloud",
				APIKey:   "test-key",
				TenantID: "test-tenant",
			},
		},
	}

	got := convertOldToNewConfig(old)

	if got.CurrentContext != old.CurrentURL {
		t.Errorf("CurrentContext = %q, want %q", got.CurrentContext, old.CurrentURL)
	}
}

func TestConvertOldToNewConfig_AllFieldsPreserved(t *testing.T) {
	// Ensure all fields from the old format are preserved in the conversion
	old := OldFileConf{
		CurrentURL: "https://my-tenant.venafi.cloud",
		Auths: []OldAuth{
			{
				URL:      "https://my-tenant.venafi.cloud",
				APIURL:   "https://api.uk.venafi.cloud",
				APIKey:   "2e9c87e3-6ad7-4878-937c-111291dab6d0",
				TenantID: "c0f2c691-ab9b-11ed-bfed-b3b2b59a7f20",
			},
		},
	}

	got := convertOldToNewConfig(old)

	if len(got.ToolContexts) != 1 {
		t.Fatalf("expected 1 context, got %d", len(got.ToolContexts))
	}

	ctx := got.ToolContexts[0]

	// Check all fields were properly copied
	if ctx.TenantURL != old.Auths[0].URL {
		t.Errorf("TenantURL = %q, want %q", ctx.TenantURL, old.Auths[0].URL)
	}
	if ctx.APIURL != old.Auths[0].APIURL {
		t.Errorf("APIURL = %q, want %q", ctx.APIURL, old.Auths[0].APIURL)
	}
	if ctx.APIKey != old.Auths[0].APIKey {
		t.Errorf("APIKey = %q, want %q", ctx.APIKey, old.Auths[0].APIKey)
	}
	if ctx.TenantID != old.Auths[0].TenantID {
		t.Errorf("TenantID = %q, want %q", ctx.TenantID, old.Auths[0].TenantID)
	}
}
