package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maelvls/vcpctl/errutil"
)

type TenantInfo struct {
	TenantID        string // e.g., "e74f4140-12a6-42f9-9f81-a6b538fa6804"
	TenantURL       string // e.g., "https://glow-in-the-dark.venafi.cloud"
	TenantURLPrefix string // e.g., "glow-in-the-dark"
	Region          string // e.g., "us"
	APIURL          string // e.g., "https://api.venafi.cloud"
}

// Get the API URL for the given tenant URL. May return errutil.NotFound if the
// tenant does not exist.
func GetTenantInfoFromTenantURL(cl http.Client, tenantURL string) (TenantInfo, error) {
	url := fmt.Sprintf("%s/single-spa-root-config/baseEnvironment.json", tenantURL)
	resp, err := cl.Get(url)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return TenantInfo{}, errutil.NotFound{NameOrID: tenantURL}
	default:
		return TenantInfo{}, HTTPErrorFrom(resp)
	}

	var respJSON struct {
		APIBaseURL string `json:"apiBaseUrl"` // Example: https://api.venafi.cloud
		UIHost     string `json:"uiHost"`     // Example: glow-in-the-dark.venafi.cloud
		Region     string `json:"region"`     // Example: us
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("reading response body: %w", err)
	}

	if err := json.Unmarshal(body, &respJSON); err != nil {
		return TenantInfo{}, fmt.Errorf("while unmarshalling response body: %w", err)
	}

	// Let's also get the tenant ID. Example:
	//  https://api.venafi.cloud/v1/companies/glow-in-the-dark/loginconfig
	//                                       <-------------->
	//										   tenant prefix
	res := strings.SplitN(respJSON.UIHost, ".", 2)
	if len(res) == 0 {
		return TenantInfo{}, fmt.Errorf("could not determine tenant prefix from UI host '%s'", respJSON.UIHost)
	}
	tenantPrefix := res[0]

	url = fmt.Sprintf("%s/v1/companies/%s/loginconfig", respJSON.APIBaseURL, tenantPrefix)
	resp, err = cl.Get(url)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("while getting tenant ID for tenant '%s': %w", tenantURL, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return TenantInfo{}, errutil.NotFound{NameOrID: tenantURL}
	default:
		return TenantInfo{}, HTTPErrorFrom(resp)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("reading loginconfig response body: %w", err)
	}

	var loginConfigResponse struct {
		CompanyID string `json:"companyId"`
		SSOLogin  bool   `json:"ssoLogin"`
	}
	err = json.Unmarshal(body, &loginConfigResponse)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("while unmarshalling loginconfig response body: %w", err)
	}

	return TenantInfo{
		TenantID:        loginConfigResponse.CompanyID,
		TenantURL:       tenantURL,
		TenantURLPrefix: tenantPrefix,
		Region:          respJSON.Region,
		APIURL:          respJSON.APIBaseURL,
	}, nil
}
