package main

import "testing"

func TestDeriveContextName(t *testing.T) {
	tests := []struct {
		name             string
		toolctx          ToolContext
		existingContexts []ToolContext
		expected         string
	}{
		{
			name: "API key - domain + email",
			toolctx: ToolContext{
				TenantURL:          "https://tenant.example.com",
				AuthenticationType: "apiKey",
				Email:              "admin.sa@qa.venafi.io",
			},
			existingContexts: []ToolContext{},
			expected:         "tenant-admin.sa@qa.venafi.io",
		},
		{
			name: "API key - devstack domain",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
			},
			existingContexts: []ToolContext{},
			expected:         "ui-stack-dev210-user@example.com",
		},
		{
			name: "API key - with conflict - adds -2",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
			},
			existingContexts: []ToolContext{{Name: "ui-stack-dev210-user@example.com"}},
			expected:         "ui-stack-dev210-user@example.com-2",
		},
		{
			name: "API key - with multiple conflicts - adds -3",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "apiKey",
				Email:              "user@example.com",
			},
			existingContexts: []ToolContext{
				{Name: "ui-stack-dev210-user@example.com"},
				{Name: "ui-stack-dev210-user@example.com-2"},
			},
			expected: "ui-stack-dev210-user@example.com-3",
		},
		{
			name: "Service account rsaKeyFederated - domain + clientID",
			toolctx: ToolContext{
				TenantURL:          "https://ven-cert-manager-uk.venafi.cloud",
				AuthenticationType: "rsaKeyFederated",
				ClientID:           "abc123",
			},
			existingContexts: []ToolContext{},
			expected:         "ven-cert-manager-uk-abc123",
		},
		{
			name: "Service account rsaKey - domain + clientID",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "rsaKey",
				ClientID:           "xyz789",
			},
			existingContexts: []ToolContext{},
			expected:         "ui-stack-dev210-xyz789",
		},
		{
			name: "Service account - with conflict - adds -2",
			toolctx: ToolContext{
				TenantURL:          "https://ui-stack-dev210.qa.venafi.io",
				AuthenticationType: "rsaKey",
				ClientID:           "xyz789",
			},
			existingContexts: []ToolContext{{Name: "ui-stack-dev210-xyz789"}},
			expected:         "ui-stack-dev210-xyz789-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveContextName(tt.toolctx, tt.existingContexts)
			if result != tt.expected {
				t.Errorf("deriveContextName() = %v, want %v", result, tt.expected)
			}
		})
	}
}
