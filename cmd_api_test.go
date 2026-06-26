package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFields_Simple(t *testing.T) {
	tests := []struct {
		name      string
		rawFields []string
		wantValue map[string]any
		wantErr   bool
	}{
		{
			name:      "simple field",
			rawFields: []string{"name=value"},
			wantValue: map[string]any{"name": "value"},
			wantErr:   false,
		},
		{
			name:      "field with equals in value",
			rawFields: []string{"query=a=b"},
			wantValue: map[string]any{"query": "a=b"},
			wantErr:   false,
		},
		{
			name:      "empty value",
			rawFields: []string{"name="},
			wantValue: map[string]any{"name": ""},
			wantErr:   false,
		},
		{
			name:      "multiple fields",
			rawFields: []string{"name=value", "count=5"},
			wantValue: map[string]any{"name": "value", "count": "5"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &apiOptions{rawFields: tt.rawFields}
			result, err := parseFields(context.Background(), opts)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, result)
		})
	}
}

func TestParseFields_Nested(t *testing.T) {
	tests := []struct {
		name         string
		magicFields  []string
		expectedJSON string
	}{
		{
			name:         "nested object",
			magicFields:  []string{"config[timeout]=30", "config[retry]=true"},
			expectedJSON: `{"config":{"retry":true,"timeout":30}}`,
		},
		{
			name:         "array values",
			magicFields:  []string{"tags[]=prod", "tags[]=api", "tags[]=v1"},
			expectedJSON: `{"tags":["prod","api","v1"]}`,
		},
		{
			name:         "complex nested array (gh CLI style)",
			magicFields:  []string{"properties[][property_name]=environment", "properties[][default_value]=production", "properties[][allowed_values][]=staging", "properties[][allowed_values][]=production"},
			expectedJSON: `{"properties":[{"property_name":"environment","default_value":"production","allowed_values":["staging","production"]}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &apiOptions{magicFields: tt.magicFields}
			result, err := parseFields(context.Background(), opts)
			require.NoError(t, err)

			// Convert to JSON to compare
			jsonBytes, err := json.Marshal(result)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expectedJSON, string(jsonBytes))
		})
	}
}

func TestMagicFieldValue(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue any
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

func TestParseFields_FileInput(t *testing.T) {
	tests := []struct {
		name         string
		magicFields  []string
		expectedJSON string
	}{
		{
			name:         "file field with JSON content",
			magicFields:  []string{"file={\"test\":\"value\"}"},
			expectedJSON: `{"file":"{\"test\":\"value\"}"}`,
		},
		{
			name:         "nested field with file content",
			magicFields:  []string{"data[file]={\"nested\":true}", "data[name]=test"},
			expectedJSON: `{"data":{"file":"{\"nested\":true}","name":"test"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &apiOptions{magicFields: tt.magicFields}
			result, err := parseFields(context.Background(), opts)
			require.NoError(t, err)

			// Convert to JSON to compare
			jsonBytes, err := json.Marshal(result)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expectedJSON, string(jsonBytes))
		})
	}
}

func TestParseFields_FileFromDisk(t *testing.T) {
	// Create a temporary file with test content
	tmpfile := t.TempDir() + "/testfile.json"
	testContent := `{"test":"value","nested":{"key":123}}`
	err := os.WriteFile(tmpfile, []byte(testContent), 0644)
	require.NoError(t, err)

	opts := &apiOptions{
		magicFields: []string{"file=@" + tmpfile},
	}
	result, err := parseFields(context.Background(), opts)
	require.NoError(t, err)

	// The file content should be stored as a string in the "file" field
	assert.Equal(t, testContent, result["file"])

	// Verify it can be marshaled to JSON
	jsonBytes, err := json.Marshal(result)
	require.NoError(t, err)

	// Build expected JSON properly with escaped content
	expected := map[string]any{"file": testContent}
	expectedBytes, err := json.Marshal(expected)
	require.NoError(t, err)
	assert.JSONEq(t, string(expectedBytes), string(jsonBytes))
}

func TestExitError(t *testing.T) {
	tests := []struct {
		statusCode   int
		expectedCode int
	}{
		{404, 104},  // 404 - 300 = 104
		{500, 200},  // 500 - 300 = 200
		{403, 103},  // 403 - 300 = 103
		{401, 101},  // 401 - 300 = 101
		{400, 100},  // 400 - 300 = 100
		{502, 202},  // 502 - 300 = 202
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.statusCode), func(t *testing.T) {
			errCode := tt.statusCode - 300
			exitErr := ExitError{
				Code:    errCode,
				Message: fmt.Sprintf("HTTP %d", tt.statusCode),
			}
			assert.Equal(t, tt.expectedCode, exitErr.ExitCode())
			assert.Equal(t, fmt.Sprintf("HTTP %d", tt.statusCode), exitErr.Error())
		})
	}
}
