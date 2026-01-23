package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Useful to get the current company ID (also called 'tenant ID'). Also useful
// to check that the API key is valid. Only works when authenticated using an
// API key. Doesn't work for service accounts.
//
// The returned tenant URL looks like this:
//
//	https://glow-in-the-dark.venafi.cloud
func SelfCheckAPIKey(ctx context.Context, cl *Client) (_ UserAccountResponse, tenantURL string, _ error) {
	resp, err := cl.UseraccountsGetByAuth(ctx)
	if err != nil {
		return UserAccountResponse{}, "", fmt.Errorf("while making request to check API key: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	// The request was successful, the token is valid. Continue below.
	case http.StatusUnauthorized:
		return UserAccountResponse{}, "", HTTPErrorFrom(resp)
	case http.StatusForbidden:
		return UserAccountResponse{}, "", HTTPErrorFrom(resp)
	default:
		return UserAccountResponse{}, "", HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserAccountResponse{}, "", fmt.Errorf("while reading response body: %w", err)
	}

	var result UserAccountResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return UserAccountResponse{}, "", fmt.Errorf("while decoding response body: %w, body was: %s", err, string(body))
	}

	// Workaround the fact that all devstacks are created with the
	// URL prefix "stack" instead of "ui-stack-devXXX". For now,
	// let's just use the API URL, which looks like this:
	//   https://api-dev210.qa.venafi.io
	// and turn it into the tenant URL, like this:
	//   https://ui-stack-dev210.qa.venafi.io
	//
	// See:
	// https://gitlab.com/venafi/vaas/test-enablement/vaas-auto/-/merge_requests/738/diffs#note_2579353788
	tenantURL = fmt.Sprintf("https://%s.venafi.cloud", result.Company.UrlPrefix)
	if tenantURL == "stack" {
		tenantURL = strings.Replace(cl.Server, "api-", "ui-stack-", 1)
	}

	return result, tenantURL, nil
}

// When authenticating as key pair ("rsaKey") service accounts, the backend
// responds with a 500:
//
//	{"errors":[{"code":1000,"message":"Unable to find user for username firefly","args":["Unable to find user for username firefly"]}]}
//
// This allows us to figure out what the name of the service account is.
func SelfCheckServiceAccount(ctx context.Context, cl *Client) (saName string, _ error) {
	resp, err := cl.UseraccountsGetByAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("while making request to check service account: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("while reading response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusInternalServerError:
	// Expected, continue below.
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", HTTPErrorFrom(resp)
	default:
		return "", fmt.Errorf("expected status code 500, but got: when checking service account, but got: %w", HTTPErrorFrom(resp))
	}

	var result struct {
		Errors []struct {
			Code    int      `json:"code"`
			Message string   `json:"message"`
			Args    []string `json:"args"`
		} `json:"errors"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("while decoding response body: %w, body was: %s", err, string(body))
	}

	if len(result.Errors) == 0 {
		return "", fmt.Errorf("expected an error response when checking service account, but got none")
	}

	// Example of 'message':
	//
	//   Unable to find user for username Foo Bar Baz
	//
	// We want to extract the "Foo Bar Baz" part.
	parts := strings.SplitN(result.Errors[0].Message, "username ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected error message format: %q", result.Errors[0].Message)
	}

	return parts[1], nil
}
