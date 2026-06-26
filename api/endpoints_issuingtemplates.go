package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/maelvls/vcpctl/errutil"
)

func GetIssuingTemplates(ctx context.Context, cl *Client) ([]CertificateIssuingTemplateInformation, error) {
	resp, err := cl.CertificateissuingtemplateGetAll(ctx, nil)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("while reading response body: %w", err)
	}

	var result struct {
		CertificateIssuingTemplates []CertificateIssuingTemplateInformation `json:"certificateIssuingTemplates"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result.CertificateIssuingTemplates, nil
}

func GetIssuingTemplateByName(ctx context.Context, cl *Client, name string) (CertificateIssuingTemplateInformation, error) {
	templates, err := GetIssuingTemplates(ctx, cl)
	if err != nil {
		return CertificateIssuingTemplateInformation{}, err
	}

	// Find the template with the desired name.
	for _, template := range templates {
		if template.Name == name {
			return template, nil
		}
	}

	return CertificateIssuingTemplateInformation{}, errutil.NotFound{NameOrID: name}
}
