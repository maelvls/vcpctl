package api

import "context"

type ApplicationInformation struct {
	Id                                  string            `json:"id,omitempty"`
	Name                                string            `json:"name,omitempty"`
	CertificateIssuingTemplateAliasIdMap map[string]string `json:"certificateIssuingTemplateAliasIdMap,omitempty"`
}

// GetApplications returns a list of available applications.
// Note: This is a stub implementation as the API endpoint is not yet available in the OpenAPI spec.
func GetApplications(ctx context.Context, cl *Client) ([]ApplicationInformation, error) {
	// TODO: Replace with actual API call once the endpoint is available
	return []ApplicationInformation{}, nil
}
