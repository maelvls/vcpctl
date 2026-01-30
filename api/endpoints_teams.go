package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
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

func GetTeamByID(ctx context.Context, cl *Client, id uuid.UUID) (TeamInformation, error) {
	resp, err := cl.TeamsGetById(ctx, id)
	if err != nil {
		return TeamInformation{}, fmt.Errorf("while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return TeamInformation{}, fmt.Errorf("team with ID %s not found", id)
	default:
		return TeamInformation{}, HTTPErrorFrom(resp)
	}

	var result TeamInformation
	if err := decodeJSON(resp.Body, &result); err != nil {
		return TeamInformation{}, fmt.Errorf("while decoding response: %w", err)
	}
	return result, nil
}
