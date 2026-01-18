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
		return UserAccountResponse{}, HTTPErrorFrom(resp)
	case http.StatusForbidden:
		return UserAccountResponse{}, HTTPErrorFrom(resp)
	default:
		return UserAccountResponse{}, HTTPErrorFrom(resp)
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
