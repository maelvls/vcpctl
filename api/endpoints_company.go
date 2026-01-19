package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

// This doesn't need an authenticated client. The tenant prefix is the first
// segment of the URL used when a customer opens the UI. E.g., with the UI at
// URL:
//
//	https://ven-cert-manager-uk.venafi.cloud
//	        <----------------->
//	           tenantPrefix
func GetTenantFromURLPrefix(ctx context.Context, tenantPrefix string) (CompanyLoginConfigResponse, error) {
	tenantName := tenantPrefix

	type result struct {
		res    CompanyLoginConfigResponse
		status int
		err    error
	}

	resultsCh := make(chan result, len(venafiRegions))

	for _, apiURL := range venafiRegions {
		apiURL := apiURL // capture range variable

		go func() {
			anonymousClient, err := NewUnauthenticatedClient(apiURL)
			if err != nil {
				// In the sequential version we just "continue", i.e. ignore this region.
				// We still report the error so we can maybe return *some* error if all fail.
				resultsCh <- result{
					err: fmt.Errorf("while creating client for %s: %w", apiURL, err),
				}
				return
			}

			resp, err := anonymousClient.GetV1CompaniesByUrlPrefixLoginconfig(ctx, tenantPrefix)
			if err != nil {
				resultsCh <- result{
					err: fmt.Errorf("while looking up tenant ID for '%s' in %s: %w", tenantPrefix, apiURL, err),
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
						tenantName, apiURL, resp.StatusCode),
				}
			}
		}()
	}

	var firstErr error

	// Collect results from all regions.
	for range venafiRegions {
		r := <-resultsCh

		// If any region finds the tenant, return it immediately.
		if r.status == http.StatusOK && r.err == nil {
			return r.res, nil
		}

		// Remember the first non-OK error in case they all fail.
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}

	// No region returned 200.
	if firstErr != nil {
		return CompanyLoginConfigResponse{}, firstErr
	}

	// All regions either 404'd or were skipped without detailed errors.
	return CompanyLoginConfigResponse{}, errutil.NotFound{NameOrID: tenantName}
}
