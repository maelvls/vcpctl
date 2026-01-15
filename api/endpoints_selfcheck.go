package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func SelfCheck(ctx context.Context, cl *Client) (UserAccountResponse, error) {
	resp, err := cl.UseraccountsGetByAuth(ctx)
	if err != nil {
		return UserAccountResponse{}, fmt.Errorf("while making request to check API key: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	// The request was successful, the token is valid. Continue below.
	case http.StatusUnauthorized:
		return UserAccountResponse{}, HTTPErrorf(resp, "please check your API key")
	case http.StatusForbidden:
		return UserAccountResponse{}, HTTPErrorf(resp, "please check your API key and permissions")
	default:
		return UserAccountResponse{}, HTTPErrorf(resp, "while checking API key, got unexpected http %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UserAccountResponse{}, fmt.Errorf("while reading response body: %w", err)
	}

	var result UserAccountResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return UserAccountResponse{}, fmt.Errorf("while decoding response body: %w, body was: %s", err, string(body))
	}

	return result, nil
}
