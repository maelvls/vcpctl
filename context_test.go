package main

import (
	"strings"
	"testing"
)

func TestDeriveContextName(t *testing.T) {
	tests := []struct {
		name             string
		toolctx          ToolContext
		existingContexts []ToolContext
		wantFormat       string // "docker-style" or "docker-style-hash"
		checkCollision   bool
	}{
		{
			name: "API key - generates Docker-style name",
			toolctx: ToolContext{
				TenantURL:          "https://tenant.example.com",
				AuthenticationType: "apiKey",
				Email:              "admin.sa@qa.venafi.io",
				UserID:             "bb60ab68-9cb9-45bb-ab16-e3f09766f980",
			},
			existingContexts: []ToolContext{},
			wantFormat:       "docker-style",
		},
		{
			name: "API key - devstack domain Docker-style",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
				UserID:             "11111111-2222-3333-4444-555555555555",
			},
			existingContexts: []ToolContext{},
			wantFormat:       "docker-style",
		},
		{
			name: "API key - deterministic (same input, same output)",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
				UserID:             "11111111-2222-3333-4444-555555555555",
			},
			existingContexts: []ToolContext{},
			wantFormat:       "docker-style",
		},
		{
			name: "API key - with collision - adds hash suffix",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
				UserID:             "11111111-2222-3333-4444-555555555555",
			},
			existingContexts: []ToolContext{
				// Add a context with a name that might collide
				{Name: "some-context"},
			},
			wantFormat:     "docker-style-or-hash",
			checkCollision: true,
		},
		{
			name: "Service account rsaKeyFederated - Docker-style",
			toolctx: ToolContext{
				TenantURL:          "https://ven-cert-manager-uk.venafi.cloud",
				AuthenticationType: "rsaKeyFederated",
				ClientID:           "abc123",
			},
			existingContexts: []ToolContext{},
			wantFormat:       "docker-style",
		},
		{
			name: "Service account rsaKey - Docker-style",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "rsaKey",
				ClientID:           "xyz789",
			},
			existingContexts: []ToolContext{},
			wantFormat:       "docker-style",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateContextName(tt.toolctx, tt.existingContexts)

			// Check format
			switch tt.wantFormat {
			case "docker-style":
				// Should be in format: adjective-noun
				parts := strings.Split(result, "-")
				if len(parts) != 2 {
					t.Errorf("deriveContextName() = %v, expected Docker-style format (adjective-noun)", result)
				}
			case "docker-style-hash", "docker-style-or-hash":
				// Should be either adjective-noun or adjective-noun-hash
				parts := strings.Split(result, "-")
				if len(parts) != 2 && len(parts) != 3 {
					t.Errorf("deriveContextName() = %v, expected Docker-style format (adjective-noun or adjective-noun-hash)", result)
				}
			}

			// Check collision avoidance
			if tt.checkCollision {
				for _, existing := range tt.existingContexts {
					if result == existing.Name {
						t.Errorf("deriveContextName() = %v, should not collide with existing context %v", result, existing.Name)
					}
				}
			}

			// Test determinism: same input should produce same output
			result2 := generateContextName(tt.toolctx, tt.existingContexts)
			if result != result2 {
				t.Errorf("deriveContextName() not deterministic: first call = %v, second call = %v", result, result2)
			}
		})
	}

	// Test that different inputs produce different outputs
	t.Run("Different inputs produce different outputs", func(t *testing.T) {
		ctx1 := ToolContext{
			TenantURL:          "https://tenant1.example.com",
			AuthenticationType: "apiKey",
			UserID:             "11111111-1111-1111-1111-111111111111",
		}
		ctx2 := ToolContext{
			TenantURL:          "https://tenant1.example.com",
			AuthenticationType: "apiKey",
			UserID:             "22222222-2222-2222-2222-222222222222",
		}

		name1 := generateContextName(ctx1, []ToolContext{})
		name2 := generateContextName(ctx2, []ToolContext{})

		if name1 == name2 {
			t.Errorf("Different UserIDs produced same context name: %v", name1)
		}
	})
}
