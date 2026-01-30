package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFixURLPrefix(t *testing.T) {
	tests := []struct {
		name      string
		urlPrefix string
		apiURL    string
		want      string
		wantErr   bool
	}{
		{
			name:      "non-stack prefix is returned as-is",
			urlPrefix: "my-company",
			apiURL:    "https://api.venafi.cloud",
			want:      "my-company",
			wantErr:   false,
		},
		{
			name:      "stack prefix with https devstack URL",
			urlPrefix: "stack",
			apiURL:    "https://api-dev210.qa.venafi.io",
			want:      "ui-stack-dev210",
			wantErr:   false,
		},
		{
			name:      "stack prefix with http devstack URL",
			urlPrefix: "stack",
			apiURL:    "http://api-dev247.qa.venafi.io",
			want:      "ui-stack-dev247",
			wantErr:   false,
		},
		{
			name:      "stack prefix without protocol",
			urlPrefix: "stack",
			apiURL:    "api-dev100.qa.venafi.io",
			want:      "ui-stack-dev100",
			wantErr:   false,
		},
		{
			name:      "stack prefix with different devstack number",
			urlPrefix: "stack",
			apiURL:    "https://api-dev999.qa.venafi.io",
			want:      "ui-stack-dev999",
			wantErr:   false,
		},
		{
			name:      "stack prefix with URL without dot returns error",
			urlPrefix: "stack",
			apiURL:    "https://api-dev210",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "stack prefix with URL without domain parts returns error",
			urlPrefix: "stack",
			apiURL:    "api-dev210",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty prefix with stack urlPrefix",
			urlPrefix: "stack",
			apiURL:    "https://api-dev123.example.com",
			want:      "ui-stack-dev123",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fixURLPrefix(tt.urlPrefix, tt.apiURL)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
