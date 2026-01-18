package api

import (
	"context"
	"fmt"
	"net/http"
)

// URL: https://api-dev210.qa.venafi.io/v1/teams?includeSystemGenerated=true
func GetTeams(ctx context.Context, cl *Client) ([]TeamInformation, error) {
	resp, err := cl.TeamsGetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorFrom(resp)
	}

	var result struct {
		Teams []TeamInformation `json:"teams"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("while decoding response: %w", err)
	}
	return result.Teams, nil
}
