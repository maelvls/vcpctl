package api

import (
	"context"
	"net/http"
)

const (
	userAgent = "vcpctl/v0.0.1"
)

// Configures the User-Agent and tppl-api-key headers as well as logging. Prefer
// using this over api.NewClient.
func NewAPIKeyClient(apiURL, apiKey string, opts ...ClientOption) (*Client, error) {
	opts = append(opts,
		WithHTTPClient(&http.Client{Transport: LogTransport}),
		withTpplAPIKey(apiKey),
		withUserAgent(),
	)
	return NewClient(apiURL, opts...)
}

// withTpplAPIKey returns a copy of the provided http.Client that adds the
// header "tppl-api-key" with the provided token.
func withTpplAPIKey(token string) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("tppl-api-key", token)
			return nil
		})
		return nil
	}
}

func withUserAgent() ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("User-Agent", userAgent)
			return nil
		})
		return nil
	}
}
