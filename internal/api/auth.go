package api

import (
	"context"
	"net/http"
)

const (
	userAgent = "vcpctl/v0.0.1"
)

// WithBearerToken returns a copy of the provided http.Client that adds the header
// "tppl-api-key" with the provided token.
func WithBearerToken(token string) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("tppl-api-key", token)
			return nil
		})
		return nil
	}
}

func WithUserAgent() ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("User-Agent", userAgent)
			return nil
		})
		return nil
	}
}
