package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// GetUsers fetches all users from the API.
func GetUsers(ctx context.Context, cl *Client) ([]UserInformation, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cl.Server+"/v1/users", nil)
	if err != nil {
		return nil, fmt.Errorf("while creating request: %w", err)
	}

	resp, err := cl.Client.Do(req)
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
		Users []UserInformation `json:"users"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("while decoding response: %w", err)
	}
	return result.Users, nil
}

// GetUserByID fetches a user by their ID. Since the OpenAPI spec for /v1/users/{id}
// has issues, we fetch all users and filter by ID.
func GetUserByID(ctx context.Context, cl *Client, id uuid.UUID) (UserInformation, error) {
	users, err := GetUsers(ctx, cl)
	if err != nil {
		return UserInformation{}, fmt.Errorf("while getting users: %w", err)
	}

	for _, user := range users {
		if user.Id == id {
			return user, nil
		}
	}

	return UserInformation{}, fmt.Errorf("user with ID %s not found", id)
}

// GetOwnerName fetches the name of an owner (either a team or a user) by their ID.
// It first tries to fetch as a team, and if not found, tries as a user.
// Returns the name in the format "Firstname Lastname" for users or "TeamName" for teams.
func GetOwnerName(ctx context.Context, cl *Client, ownerID uuid.UUID) (string, error) {
	// Try as a team first.
	team, err := GetTeamByID(ctx, cl, ownerID)
	if err == nil {
		return team.Name, nil
	}

	// Try as a user.
	user, err := GetUserByID(ctx, cl, ownerID)
	if err == nil {
		// Format user name as "Firstname Lastname".
		if user.Firstname != "" && user.Lastname != "" {
			return user.Firstname + " " + user.Lastname, nil
		} else if user.Firstname != "" {
			return user.Firstname, nil
		} else if user.Lastname != "" {
			return user.Lastname, nil
		}
		// Fallback to email if no name is available.
		if user.EmailAddress != "" {
			return user.EmailAddress, nil
		}
		return "Unknown User", nil
	}

	return "", fmt.Errorf("owner with ID %s not found as team or user", ownerID)
}
