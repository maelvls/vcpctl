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
		return nil, fmt.Errorf("getTeams: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "getTeams: got http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		Teams []TeamInformation `json:"teams"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("getTeams: while decoding response: %w", err)
	}
	return result.Teams, nil
}
