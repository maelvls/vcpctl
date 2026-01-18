package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func GetApplications(ctx context.Context, cl *Client) ([]ApplicationInformation, error) {
	resp, err := cl.ApplicationsGetAll(ctx, &ApplicationsGetAllParams{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	case http.StatusUnauthorized:
		return nil, HTTPErrorFrom(resp)
	case http.StatusForbidden:
		return nil, HTTPErrorFrom(resp)
	default:
		return nil, HTTPErrorFrom(resp)
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("while reading applications: %w", err)
	}

	var result ApplicationResponse
	err = json.Unmarshal(body.Bytes(), &result)
	if err != nil {
		return nil, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result.Applications, nil
}
