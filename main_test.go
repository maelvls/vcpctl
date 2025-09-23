package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func Test_withoutANSI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\x1b[1;34mHello\x1b[0m", "Hello"},
		{"\x1b[1;34mHello\x1b[0m \x1b[1;34mWorld\x1b[0m", "Hello World"},
		{"\x1b[38;5;1m", ""},
		{"\x1b[1;31m", ""},
		{"\x1b[90m", ""},
		{"\x1b[1;34m", ""},
		{"\x1b[0m", ""},
		{"\x1b[38;5;34m foobar \x1b[0m", " foobar "},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := withoutANSI(test.input)
			if result != test.expected {
				t.Errorf("Expected %q but got %q", test.expected, result)
			}
		})
	}
}

func TestClientAuthenticationJWTStandardClaims(t *testing.T) {
	input := []byte(`clientAuthentication:
  type: JWT_STANDARD_CLAIMS
  audience: firefly.example.com
  clients:
    - issuer: https://example.com
      subjects:
        - sub-claim-value
        - system:serviceaccount:test-app-namespace:test-app-sa
      allowedPolicyIds:
        - Policy
    - issuer: "^https://.*\\.example\\.com$"
      jwksURI: https://example.com/.well-known/jwks.json
      subjects:
        - ^system:serviceaccount:test-app-namespace:.*$
      allowedPolicyIds:
        - Policy
`)

	var cfg FireflyConfig
	if err := yaml.UnmarshalWithOptions(input, &cfg, yaml.Strict()); err != nil {
		t.Fatalf("unexpected error while unmarshalling YAML: %v", err)
	}

	auth := cfg.ClientAuthentication
	if auth.Type != "JWT_STANDARD_CLAIMS" {
		t.Fatalf("unexpected type: %q", auth.Type)
	}
	if auth.Audience != "firefly.example.com" {
		t.Fatalf("unexpected audience: %q", auth.Audience)
	}
	if len(auth.Clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(auth.Clients))
	}
	if auth.Clients[0].Issuer != "https://example.com" {
		t.Fatalf("unexpected issuer for client[0]: %q", auth.Clients[0].Issuer)
	}
	if len(auth.Clients[0].AllowedPolicyIDs) != 1 || auth.Clients[0].AllowedPolicyIDs[0] != "Policy" {
		t.Fatalf("unexpected allowedPolicyIds for client[0]: %#v", auth.Clients[0].AllowedPolicyIDs)
	}
	if auth.Clients[1].JwksURI != "https://example.com/.well-known/jwks.json" {
		t.Fatalf("unexpected jwksURI for client[1]: %q", auth.Clients[1].JwksURI)
	}
	if len(auth.Clients[1].Subjects) != 1 || auth.Clients[1].Subjects[0] != "^system:serviceaccount:test-app-namespace:.*$" {
		t.Fatalf("unexpected subjects for client[1]: %#v", auth.Clients[1].Subjects)
	}

	data, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("unexpected error while marshalling JSON: %v", err)
	}
	jsonStr := string(data)
	for _, key := range []string{"\"audience\":", "\"clients\":", "\"allowedPolicyIds\":", "\"jwksURI\":"} {
		if !strings.Contains(jsonStr, key) {
			t.Fatalf("expected JSON output to contain %s, got %s", key, jsonStr)
		}
	}
}
