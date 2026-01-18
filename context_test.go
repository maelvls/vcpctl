package main

import "testing"

func TestDeriveContextName(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		existingContexts []ToolContext
		expected         string
	}{
		{
			name:             "simple domain",
			url:              "https://ven-cert-manager-uk.venafi.cloud",
			existingContexts: []ToolContext{},
			expected:         "ven-cert-manager-uk",
		},
		{
			name:             "devstack domain",
			url:              "https://ui-stack-dev210.qa.venafi.io",
			existingContexts: []ToolContext{},
			expected:         "ui-stack-dev210",
		},
		{
			name:             "with conflict - adds -2",
			url:              "https://ui-stack-dev210.qa.venafi.io",
			existingContexts: []ToolContext{{Name: "ui-stack-dev210"}},
			expected:         "ui-stack-dev210-2",
		},
		{
			name: "with multiple conflicts - adds -3",
			url:  "https://ui-stack-dev210.qa.venafi.io",
			existingContexts: []ToolContext{
				{Name: "ui-stack-dev210"},
				{Name: "ui-stack-dev210-2"},
			},
			expected: "ui-stack-dev210-3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveContextName(tt.url, tt.existingContexts)
			if result != tt.expected {
				t.Errorf("deriveContextName() = %v, want %v", result, tt.expected)
			}
		})
	}
}
