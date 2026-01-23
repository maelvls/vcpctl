package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseField(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "simple field",
			input:     "name=value",
			wantKey:   "name",
			wantValue: "value",
			wantErr:   false,
		},
		{
			name:      "field with equals in value",
			input:     "query=a=b",
			wantKey:   "query",
			wantValue: "a=b",
			wantErr:   false,
		},
		{
			name:      "empty value",
			input:     "name=",
			wantKey:   "name",
			wantValue: "",
			wantErr:   false,
		},
		{
			name:    "missing equals",
			input:   "namevalue",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, err := parseField(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantKey, key)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}

func TestMagicFieldValue(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue interface{}
		wantErr   bool
	}{
		{
			name:      "string value",
			input:     "hello",
			wantValue: "hello",
			wantErr:   false,
		},
		{
			name:      "integer value",
			input:     "123",
			wantValue: 123,
			wantErr:   false,
		},
		{
			name:      "negative integer",
			input:     "-456",
			wantValue: -456,
			wantErr:   false,
		},
		{
			name:      "true boolean",
			input:     "true",
			wantValue: true,
			wantErr:   false,
		},
		{
			name:      "false boolean",
			input:     "false",
			wantValue: false,
			wantErr:   false,
		},
		{
			name:      "null value",
			input:     "null",
			wantValue: nil,
			wantErr:   false,
		},
		{
			name:      "string that looks like bool but capitalized",
			input:     "True",
			wantValue: "True",
			wantErr:   false,
		},
		{
			name:      "decimal number treated as string",
			input:     "3.14",
			wantValue: "3.14",
			wantErr:   false,
		},
		{
			name:      "empty string",
			input:     "",
			wantValue: "",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := magicFieldValue(context.Background(), tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, value)
		})
	}
}
