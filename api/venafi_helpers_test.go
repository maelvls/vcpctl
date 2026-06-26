package api

import "testing"

func TestLooksLikeAnID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid UUID",
			input:    "2babbd60-716f-11f1-914e-070a45d387aa",
			expected: true,
		},
		{
			name:     "valid UUID uppercase",
			input:    "2BABBD60-716F-11F1-914E-070A45D387AA",
			expected: true,
		},
		{
			name:     "name that happens to be 36 chars with 4 hyphens",
			input:    "ngts-integration-test-bob-1782485766",
			expected: false,
		},
		{
			name:     "another name with 36 chars and 4 hyphens",
			input:    "ngts-integration-test-alice-17824857",
			expected: false,
		},
		{
			name:     "short name",
			input:    "test-config",
			expected: false,
		},
		{
			name:     "name with many hyphens",
			input:    "test-config-name-with-many-parts",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LooksLikeAnID(tt.input)
			if result != tt.expected {
				t.Errorf("LooksLikeAnID(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
