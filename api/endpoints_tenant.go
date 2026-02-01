package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maelvls/vcpctl/errutil"
)

// https://docs.venafi.cloud/vsatellite/r-VSatellite-deployNew-network-connections
var venafiRegions = []string{
	"https://api.venafi.cloud",
	"https://api.eu.venafi.cloud",
	"https://api.uk.venafi.cloud",
	"https://api.au.venafi.cloud",
	"https://api.ca.venafi.cloud",
	"https://api.sg.venafi.cloud",
}

// This doesn't need an authenticated client. The 'actual' tenant URL prefix is
// the first segment of the URL used when a customer opens the UI. E.g., with
// the UI at URL:
//
//	https://ven-cert-manager-uk.venafi.cloud
//	        <----------------->
//	       'actual' tenantURLPrefix
//
// Use errutil.IsNotFound to check if the tenant was not found.
func GetTenantID(ctx context.Context, actualTenantURLPrefix string) (tenantID string, _ error) {
	type result struct {
		res    CompanyLoginConfigResponse
		status int
		err    error
	}

	resultsCh := make(chan result, len(venafiRegions))

	for _, apiURL := range venafiRegions {
		go func(apiURL string) {
			anonClient, err := NewAnonymousClient()
			if err != nil {
				// In the sequential version we just "continue", i.e. ignore this region.
				// We still report the error so we can maybe return *some* error if all fail.
				resultsCh <- result{
					err: fmt.Errorf("while creating client for %s: %w", apiURL, err),
				}
				return
			}

			resp, err := anonClient.GetV1CompaniesByUrlPrefixLoginconfig(ctx, actualTenantURLPrefix)
			if err != nil {
				resultsCh <- result{
					err: fmt.Errorf("while looking up tenant ID for '%s' in %s: %w", actualTenantURLPrefix, apiURL, err),
				}
				return
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				var res CompanyLoginConfigResponse

				bytes, err := io.ReadAll(resp.Body)
				if err != nil {
					resultsCh <- result{
						err: fmt.Errorf("while reading response body from %s: %w", apiURL, err),
					}
					return
				}
				if err := json.Unmarshal(bytes, &res); err != nil {
					resultsCh <- result{
						err: fmt.Errorf("while unmarshaling response body from %s: %w", apiURL, err),
					}
					return
				}
				resultsCh <- result{
					res:    res,
					status: http.StatusOK,
				}

			case http.StatusNotFound:
				// Just signal "not found" for this region.
				resultsCh <- result{
					status: http.StatusNotFound,
				}

			default:
				resultsCh <- result{
					status: resp.StatusCode,
					err: fmt.Errorf("while looking up tenant ID for '%s' in %s: received unexpected status code %d",
						actualTenantURLPrefix, apiURL, resp.StatusCode),
				}
			}
		}(apiURL)
	}

	var firstErr error

	// Collect results from all regions.
	for range venafiRegions {
		r := <-resultsCh

		// If any region finds the tenant, return it immediately.
		if r.status == http.StatusOK && r.err == nil {
			return r.res.CompanyId.String(), nil
		}

		// Remember the first non-OK error in case they all fail.
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}

	// No region returned 200.
	if firstErr != nil {
		return "", firstErr
	}

	// All regions either 404'd or were skipped without detailed errors.
	return "", errutil.NotFound{NameOrID: actualTenantURLPrefix}
}

type TenantInfo struct {
	APIURL   string // e.g., "https://api.venafi.cloud"
	TenantID string // e.g., "e74f4140-12a6-42f9-9f81-a6b538fa6804"
}

// Unauthenticated. Gets the API URL, tenant ID, and 'registered' tenant URL prefix for
// the given tenant URL. May return errutil.NotFound if the tenant does not
// exist. Client's Server must be set to the API URL.
func GetTenantInfo(anonClient HttpRequestDoer, tenantURL string) (TenantInfo, error) {
	tenantURL = strings.TrimSuffix(tenantURL, "/")

	baseEnv, err := GetBaseEnvironment(anonClient, tenantURL)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("while getting base environment for tenant '%s': %w", tenantURL, err)
	}

	loginInfo, err := GetLoginInfo(anonClient, baseEnv.APIBaseURL, tenantURL)
	if err != nil {
		return TenantInfo{}, fmt.Errorf("while getting login info for tenant '%s': %w", tenantURL, err)
	}

	return TenantInfo{
		APIURL:   baseEnv.APIBaseURL,
		TenantID: loginInfo.CompanyID,
	}, nil
}

type BaseEnvironment struct {
	APIBaseURL string `json:"apiBaseUrl"` // e.g., "https://api.venafi.cloud"
	UIHost     string `json:"uiHost"`     // e.g., "glow-in-the-dark.venafi.cloud"
	Region     string `json:"region"`     // e.g., "us"
}

// Endpoint: <tenant-url>/single-spa-root-config/baseEnvironment.json.
// Unauthenticated. Gets the tenant hostname and API URL for the given tenant
// URL. Client's Server must be set to the tenant URL.
func GetBaseEnvironment(client HttpRequestDoer, tenantURL string) (BaseEnvironment, error) {
	url := fmt.Sprintf("%s/single-spa-root-config/baseEnvironment.json", tenantURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return BaseEnvironment{}, fmt.Errorf("while creating request to get API URL for tenant '%s': %w", tenantURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return BaseEnvironment{}, fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return BaseEnvironment{}, errutil.NotFound{NameOrID: tenantURL}
	default:
		return BaseEnvironment{}, HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return BaseEnvironment{}, fmt.Errorf("reading response body: %w", err)
	}

	// Example 1 (production):
	//
	//  curl https://glow-in-the-dark.venafi.cloud/single-spa-root-config/baseEnvironment.json
	//  {
	//    "apiBaseUrl" : "https://api.venafi.cloud",
	//    "uiHost" : "glow-in-the-dark.venafi.cloud",
	//    "region" : "us"
	//  }
	//
	// Example 2 (devstack):
	//
	//  curl https://ui-stack-dev247.qa.venafi.io/single-spa-root-config/baseEnvironment.json | jq
	//  {
	//    "apiBaseUrl": "https://api-dev247.qa.venafi.io",
	//    "apiTenantHost": "stack-dev247.machineidentity.qa.venafi.io",
	//    "uiHost": "ui-stack-dev247.qa.venafi.io",
	//    "region": "us"
	// }
	//
	var baseEnvironment struct {
		APIBaseURL string `json:"apiBaseUrl"` // Example: https://api.venafi.cloud
		UIHost     string `json:"uiHost"`     // Example: glow-in-the-dark.venafi.cloud
		Region     string `json:"region"`     // Example: us

		// Not sure what 'apiTenantHost' is useful for, so ignoring it for now
		// as it doesn't seem to be a valid domain anyways.
	}
	err = json.Unmarshal(body, &baseEnvironment)
	if err != nil {
		return BaseEnvironment{}, fmt.Errorf("while unmarshalling response body: %w", err)
	}

	return baseEnvironment, nil
}

type LoginInfo struct {
	CompanyID string `json:"companyId"`
	SSOLogin  bool   `json:"ssoLogin"`
}

// Call: <api-url>/v1/companies/<registered-tenant-url-prefix>/loginconfig
// Unauthenticated. Gets the tenant ID (company ID) for the given tenant URL.
func GetLoginInfo(client HttpRequestDoer, apiURL, tenantURL string) (LoginInfo, error) {
	// We already have the 'actual' tenantURLPrefix (it's the subdomain of the
	// tenant URL). But what we actually need is the 'registered' tenantURLPrefix.
	registeredTenantURLPrefix, err := registeredTenantURLPrefixFromTenantURL(tenantURL)
	if err != nil {
		return LoginInfo{}, fmt.Errorf("while getting tenant URL prefix from tenant URL '%s': %w", tenantURL, err)
	}

	url := fmt.Sprintf("%s/v1/companies/%s/loginconfig", apiURL, registeredTenantURLPrefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return LoginInfo{}, fmt.Errorf("while creating request to get tenant ID for tenant '%s': %w", tenantURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return LoginInfo{}, fmt.Errorf("while getting tenant ID for tenant '%s': %w", tenantURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return LoginInfo{}, errutil.NotFound{NameOrID: tenantURL}
	default:
		return LoginInfo{}, HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return LoginInfo{}, fmt.Errorf("reading loginconfig response body: %w", err)
	}

	var loginInfo LoginInfo
	err = json.Unmarshal(body, &loginInfo)
	if err != nil {
		return LoginInfo{}, fmt.Errorf("while unmarshalling loginconfig response body: %w", err)
	}

	return loginInfo, nil
}

// If you have a tenant URL, this func gives you the 'registered' UI tenant URL
// prefix to be used in the loginconfig URL.
//
// The 'registered' tenant URL prefix comes from the 'company.urlPrefix' field
// when querying /v1/useraccounts. It is what needs to be used in the
// /loginconfig endpoint.
//
// The 'actual' tenant URL prefix is what the actual UI host is. Both
// 'registered' and 'actual' prefixes refer to UI tenant URLs, not API URLs. In
// production tenants, both are equal:
//
//	apiURL:                                 "https://api.venafi.cloud"
//	uiHost (also called 'tenantURL'):       "glow-in-the-dark.venafi.cloud"
//	'registered' UI tenantURLPrefix:        "glow-in-the-dark"
//	'actual' UI tenantURLPrefix:            "glow-in-the-dark"
//
// But in dev environments, the 'registered' and 'actual' tenant URL prefixes
// don't match. That's because all devstacks are created with the same
// 'registered' tenant URL prefix "stack", but since the same gateway is used
// for all devstacks, the 'actual' tenant URL prefix must be different to
// distinguish between them. For example:
//
//	apiURL:                                 "https://api-dev210.qa.venafi.io"
//	uiHost:                                 "ui-stack-dev210.qa.venafi.io"
//	'registered' UI tenantURLPrefix:        "stack"
//	'actual' UI tenantURLPrefix:            "ui-stack-dev210"
//
// As a result, the /loginconfig URL is:
//
//	https://api-dev210.qa.venafi.io/v1/companies/stack/loginconfig
//	                                            <-->
//	                                  'registered' tenant URL prefix
//
// Examples:
//
//	registeredTenantURLPrefixFromTenantURL("https://glow-in-the-dark.venafi.cloud") -> "glow-in-the-dark"
//	registeredTenantURLPrefixFromTenantURL("https://ui-stack-dev210.qa.venafi.io")  -> "stack"
func registeredTenantURLPrefixFromTenantURL(tenantURL string) (string, error) {
	parts := strings.SplitN(tenantURL, ".", 2)
	if len(parts) == 0 {
		return "", fmt.Errorf("could not extract URL prefix from tenant URL, could not find a dot in '%s'", tenantURL)
	}
	actualTenantURLPrefix := rmProtocolPrefix(parts[0])
	actualTenantURLPrefix = strings.TrimSuffix(actualTenantURLPrefix, "/")

	// For dev environments, the 'actual' tenantURLPrefix might be something
	// like "ui-stack-dev210". The 'registered' tenantURLPrefix is always just "stack".
	if strings.HasPrefix(actualTenantURLPrefix, "ui-stack-") {
		return "stack", nil
	}

	// For regular production tenants, the 'registered' tenantURLPrefix is the same as
	// the 'actual' tenantURLPrefix.
	return actualTenantURLPrefix, nil
}

// actualTenantURLPrefixFromRegisteredTenantURLPrefix computes the 'actual' UI
// tenant URL prefix from the 'registered' UI tenant URL prefix and the API URL.
//
// For dev environments, the 'registered' tenant URL prefix is always "stack",
// but the 'actual' tenant URL prefix looks like "ui-stack-devXXX". That's
// because all devstacks are created with the 'registered' tenant URL prefix
// "stack", which means all of the tenant URLs would be the same:
//
//	https://stack.qa.venafi.io
//
// Since we use a single gateway for all UIs, we need to distinguish between
// devstacks. Thus, a different URL prefix is used that I call 'actual' tenant
// URL prefix.
//
// The 'registered' tenant URL prefix is what is returned by /v1/useraccounts in
// 'company.urlPrefix'. Both 'registered' and 'actual' prefixes refer to UI
// tenant URLs, not API URLs. Example:
//
//	$ curl https://api-dev247.qa.venafi.io/v1/useraccounts
//	{
//	  "company": {
//	    "id": "81a097b0-fd28-11f0-b61b-15194c3359c5",
//	    "name": "qa.venafi.io",
//	    "urlPrefix": "stack",             <-- The 'registered' tenant URL prefix
//	    ...                                   does not match with the 'actual'
//											  tenant URL (see below).
//
// In the above example, "ui-stack-dev247" is the 'actual' tenant URL prefix,
// even though its 'registered' tenant URL prefix is "stack".
//
// For any other regular tenant, the tenant URL prefix is correct. Example:
//
//	$ curl https://api.venafi.cloud/v1/useraccounts
//	{
//	  "company": {
//	    "id": "e74f4140-12a6-42f9-9f81-a6b538fa6804",
//	    "name": "glow-in-the-dark",
//	    "urlPrefix": "glow-in-the-dark",   <-- The 'registered' tenant URL prefix
//	    ...                                    matches the 'actual' tenant URL
//	                                           prefix.
//
// For example, "ui-stack-dev247" is the actual tenant URL prefix for the
// devstack running at 'api-dev247.qa.venafi.io', but its 'registered' tenant URL
// prefix is "stack".
//
// Examples:
//
//	actualTenantURLPrefixFromRegisteredTenantURLPrefix("stack", "https://api-dev210.qa.venafi.io") -> "ui-stack-dev210"
//	actualTenantURLPrefixFromRegisteredTenantURLPrefix("glow-in-the-dark", "https://api.venafi.cloud") -> "glow-in-the-dark"
//
// See:
// https://gitlab.com/venafi/vaas/test-enablement/vaas-auto/-/merge_requests/738/diffs#note_2579353788
func actualTenantURLPrefixFromRegisteredTenantURLPrefix(registeredTenantURLPrefix, apiURL string) (string, error) {
	if registeredTenantURLPrefix != "stack" {
		return registeredTenantURLPrefix, nil
	}

	apiURLParts := strings.SplitN(apiURL, ".", 2)
	if len(apiURLParts) != 2 {
		return "", fmt.Errorf("unexpected API URL format. Expected a URL with a dot somewhere, but got: %q", apiURL)
	}
	devstack := apiURLParts[0]                             // e.g. "https://api-dev210"
	devstack = rmProtocolPrefix(devstack)                  // e.g. "api-dev210"
	devstack = strings.TrimPrefix(devstack, "api-")        // e.g. "dev210"
	registeredTenantURLPrefix = "ui-stack-" + devstack     // e.g. "ui-stack-dev210"
	return registeredTenantURLPrefix, nil
}

func rmProtocolPrefix(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// GetTenantIDFromUsername gets the tenant ID (company ID) for the given
// username. This call doesn't need to be authenticated. For context, here is
// what a sample response looks like:
//
//	$ curl https://api.venafi.cloud/v1/users/username/mael.valais@venafi.com/loginconfig
//	{"companyId":"b5ed6d60-22c4-11e7-ac27-035f0608fd2c","ssoLogin":true,"localLogin":false}
func GetTenantIDFromUsername(cl Client, username string) (string, error) {
	url := fmt.Sprintf("%s/v1/users/username/%s/loginconfig", cl.Server, username)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("while creating request to get tenant ID for username '%s': %w", username, err)
	}
	resp, err := cl.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while getting tenant ID for username '%s': %w", username, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return "", errutil.NotFound{NameOrID: username}
	default:
		return "", HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading loginconfig response body: %w", err)
	}

	var loginConfigResponse struct {
		CompanyID string `json:"companyId"`
		SSOLogin  bool   `json:"ssoLogin"`
	}
	err = json.Unmarshal(body, &loginConfigResponse)
	if err != nil {
		return "", fmt.Errorf("while unmarshalling loginconfig response body: %w", err)
	}

	return loginConfigResponse.CompanyID, nil
}

// GetTenantURLPrefixFromTenantID gets the tenant URL prefix for the given
// tenant ID (company ID). For context, here is what a sample response looks
// like:
//
//	$ curl https://api.venafi.cloud/v1/companies/b5ed6d60-22c4-11e7-ac27-035f0608fd2c/urlPrefix
//	{"urlPrefix":"prod"}
func GetTenantURLPrefixFromTenantID(cl Client, tenantID string) (string, error) {
	url := fmt.Sprintf("%s/v1/companies/%s/urlPrefix", cl.Server, tenantID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("while creating request to get tenant URL prefix for tenant ID '%s': %w", tenantID, err)
	}
	resp, err := cl.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while getting tenant URL prefix for tenant ID '%s': %w", tenantID, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return "", errutil.NotFound{NameOrID: tenantID}
	default:
		return "", HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading urlPrefix response body: %w", err)
	}

	var urlPrefixResponse struct {
		URLPrefix string `json:"urlPrefix"`
	}
	err = json.Unmarshal(body, &urlPrefixResponse)
	if err != nil {
		return "", fmt.Errorf("while unmarshalling urlPrefix response body: %w", err)
	}

	return urlPrefixResponse.URLPrefix, nil
}

// Example responses for reference:
//
//	$ curl https://api-dev247.qa.venafi.io/v1/companies/stack/baseenv
//	{"apiBaseUrl":"https://api-dev247.qa.venafi.io","uiHost":"ui-stack-dev247.qa.venafi.io"}
//
//	$ curl https://api.venafi.cloud/v1/companies/prod/baseenv
//	{"apiBaseUrl":"https://api.venafi.cloud","uiHost":"prod.venafi.cloud"}
func GetBaseEnv(cl Client, registeredTenantURLPrefix string) (apiURL string, tenantURL string, err error) {
	url := fmt.Sprintf("%s/v1/companies/%s/baseenv", cl.Server, registeredTenantURLPrefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", fmt.Errorf("while creating request to get tenant info for tenant ID '%s': %w", registeredTenantURLPrefix, err)
	}
	resp, err := cl.Client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("while getting tenant info for tenant ID '%s': %w", registeredTenantURLPrefix, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return "", "", errutil.NotFound{NameOrID: registeredTenantURLPrefix}
	default:
		return "", "", HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("reading baseenv response body: %w", err)
	}

	var baseEnv struct {
		APIBaseURL string `json:"apiBaseUrl"` // e.g., "https://api.venafi.cloud" or "https://api-dev247.qa.venafi.io"
		UIHost     string `json:"uiHost"`     // e.g., "prod.venafi.cloud" or "ui-stack-dev247.qa.venafi.io"
	}
	err = json.Unmarshal(body, &baseEnv)
	if err != nil {
		return "", "", fmt.Errorf("while unmarshalling baseenv response body: %w", err)
	}

	tenantURL = fmt.Sprintf("https://%s", baseEnv.UIHost)
	return baseEnv.APIBaseURL, tenantURL, nil
}
