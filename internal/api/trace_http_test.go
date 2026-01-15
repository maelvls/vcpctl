package api

import (
	"testing"
)

func TestRedactSensitiveBody(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "redacts privateKey field",
			input:    `{"user":"john","privateKey":"secret123","email":"test@example.com"}`,
			expected: `{"user":"john","privateKey":"*********","email":"test@example.com"}`,
		},
		{
			name:     "redacts ociToken field",
			input:    `{"user":"john","ociToken":"token456","email":"test@example.com"}`,
			expected: `{"user":"john","ociToken":"********","email":"test@example.com"}`,
		},
		{
			name:     "redacts both privateKey and ociToken",
			input:    `{"privateKey":"secret123","ociToken":"token456","user":"john"}`,
			expected: `{"privateKey":"*********","ociToken":"********","user":"john"}`,
		},
		{
			name:     "handles empty privateKey value",
			input:    `{"privateKey":"","user":"john"}`,
			expected: `{"privateKey":"","user":"john"}`,
		},
		{
			name:     "handles empty ociToken value",
			input:    `{"ociToken":"","user":"john"}`,
			expected: `{"ociToken":"","user":"john"}`,
		},
		{
			name:     "handles body without sensitive fields",
			input:    `{"user":"john","email":"test@example.com"}`,
			expected: `{"user":"john","email":"test@example.com"}`,
		},
		{
			name:     "handles empty body",
			input:    ``,
			expected: ``,
		},
		{
			name:     "handles body with only privateKey",
			input:    `{"privateKey":"verylongsecretkey12345"}`,
			expected: `{"privateKey":"**********************"}`,
		},
		{
			name:     "handles body with only ociToken",
			input:    `{"ociToken":"verylongtoken12345"}`,
			expected: `{"ociToken":"******************"}`,
		},
		{
			name:     "handles privateKey in nested structure",
			input:    `{"config":{"privateKey":"secret"},"other":"value"}`,
			expected: `{"config":{"privateKey":"******"},"other":"value"}`,
		},
		{
			name:     "handles multiple privateKey fields (redacts first one)",
			input:    `{"privateKey":"secret1","other":"value","privateKey":"secret2"}`,
			expected: `{"privateKey":"*******","other":"value","privateKey":"secret2"}`,
		},
		{
			name:     "handles privateKey with special characters",
			input:    `{"privateKey":"sec\nret","user":"john"}`,
			expected: `{"privateKey":"********","user":"john"}`,
		},
		{
			name:     "handles malformed JSON without quotes after field",
			input:    `{"privateKey":secret}`,
			expected: `{"privateKey":secret}`,
		},
		{
			name:     "handles privateKey field with no closing quote",
			input:    `{"privateKey":"secret`,
			expected: `{"privateKey":"secret`,
		},
		{
			name:     "handles body with spaces around field",
			input:    `{ "privateKey" : "secret123" , "user" : "john" }`,
			expected: `{ "privateKey" : "secret123" , "user" : "john" }`,
		},
		{
			name:     "handles HTML response body",
			input:    `<!DOCTYPE html><html><body><h1>Error 404</h1><p>Not Found</p></body></html>`,
			expected: `<!DOCTYPE html><html><body><h1>Error 404</h1><p>Not Found</p></body></html>`,
		},
		{
			name:     "handles HTML with privateKey in text",
			input:    `<html><body>The privateKey is important</body></html>`,
			expected: `<html><body>The privateKey is important</body></html>`,
		},
		{
			name:     "handles XML response body",
			input:    `<?xml version="1.0"?><error><message>Something went wrong</message></error>`,
			expected: `<?xml version="1.0"?><error><message>Something went wrong</message></error>`,
		},
		{
			name:     "handles plain text response",
			input:    `Internal Server Error: Connection timeout`,
			expected: `Internal Server Error: Connection timeout`,
		},
		{
			name:     "handles plain text with privateKey word",
			input:    `Error: privateKey validation failed`,
			expected: `Error: privateKey validation failed`,
		},
		{
			name:     "handles incomplete JSON",
			input:    `{"user":"john","privateKey":"secret`,
			expected: `{"user":"john","privateKey":"secret`,
		},
		{
			name:     "handles JSON with syntax error (missing comma)",
			input:    `{"user":"john" "privateKey":"secret123"}`,
			expected: `{"user":"john" "privateKey":"*********"}`,
		},
		{
			name:     "handles JSON with unmatched braces",
			input:    `{"privateKey":"secret123","user":"john"`,
			expected: `{"privateKey":"*********","user":"john"`,
		},
		{
			name:     "handles mixed content (HTML with JSON-like text)",
			input:    `<html><body>{"privateKey":"not-real-json"}</body></html>`,
			expected: `<html><body>{"privateKey":"*************"}</body></html>`,
		},
		{
			name:     "handles URL-encoded response",
			input:    `error=invalid_request&error_description=privateKey+is+required`,
			expected: `error=invalid_request&error_description=privateKey+is+required`,
		},
		{
			name:     "handles binary-like gibberish",
			input:    string([]byte{0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03}),
			expected: string([]byte{0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03}),
		},
		{
			name:     "handles JSON array instead of object",
			input:    `["value1", "value2", "value3"]`,
			expected: `["value1", "value2", "value3"]`,
		},
		{
			name:     "handles JSON with privateKey in array",
			input:    `{"keys":["privateKey","ociToken"],"values":["secret","token"]}`,
			expected: `{"keys":["privateKey","ociToken"],"values":["secret","token"]}`,
		},
		{
			name:     "handles very long non-JSON text",
			input:    `This is a very long plain text response that doesn't contain any JSON structure at all but might contain words like privateKey or ociToken in the middle of sentences.`,
			expected: `This is a very long plain text response that doesn't contain any JSON structure at all but might contain words like privateKey or ociToken in the middle of sentences.`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactSensitiveBody(tt.input)
			if result != tt.expected {
				t.Errorf("redactSensitiveBody() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestRedactJSONField(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		field    string
		expected string
	}{
		{
			name:     "redacts field value",
			body:     `{"field":"value123"}`,
			field:    "field",
			expected: `{"field":"********"}`,
		},
		{
			name:     "handles field not present",
			body:     `{"other":"value"}`,
			field:    "field",
			expected: `{"other":"value"}`,
		},
		{
			name:     "redacts only first occurrence",
			body:     `{"field":"value1","other":"x","field":"value2"}`,
			field:    "field",
			expected: `{"field":"******","other":"x","field":"value2"}`,
		},
		{
			name:     "handles empty field value",
			body:     `{"field":""}`,
			field:    "field",
			expected: `{"field":""}`,
		},
		{
			name:     "handles no closing quote for value",
			body:     `{"field":"value`,
			field:    "field",
			expected: `{"field":"value`,
		},
		{
			name:     "handles field at the end of JSON",
			body:     `{"other":"x","field":"secret"}`,
			field:    "field",
			expected: `{"other":"x","field":"******"}`,
		},
		{
			name:     "redacts long value",
			body:     `{"field":"verylongsecretvaluewithmanychars"}`,
			field:    "field",
			expected: `{"field":"********************************"}`,
		},
		{
			name:     "handles empty body",
			body:     ``,
			field:    "field",
			expected: ``,
		},
		{
			name:     "handles field with no space",
			body:     `{"field":"value"}`,
			field:    "field",
			expected: `{"field":"*****"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactJSONField(tt.body, tt.field)
			if result != tt.expected {
				t.Errorf("redactJSONField() = %q, want %q", result, tt.expected)
			}
		})
	}
}
