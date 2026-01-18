package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/maelvls/vcpctl/errutil"
)

// Get the API URL for the given tenant URL. May return errutil.NotFound if the
// tenant does not exist.
func GetAPIURLFromTenantURL(cl http.Client, tenantURL string) (string, error) {
	url := fmt.Sprintf("%s/single-spa-root-config/baseEnvironment.json", tenantURL)
	resp, err := cl.Get(url)
	if err != nil {
		return "", fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return "", errutil.NotFound{NameOrID: tenantURL}
	default:
		return "", HTTPErrorFrom(resp)
	}

	var respJSON struct {
		APIBaseURL string `json:"apiBaseUrl"`
		UIHost     string `json:"uiHost"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	if err := json.Unmarshal(body, &respJSON); err != nil {
		return "", fmt.Errorf("while unmarshalling response body: %w", err)
	}

	return respJSON.APIBaseURL, nil
}
