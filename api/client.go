package api

import (
	"context"
	"net/http"
	"runtime/debug"
)

var (
	UserAgent = "vcpctl/" + buildVersion()
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

// Configures the User-Agent and Authorization headers as well as logging.
// Uses Bearer access token authentication.
func NewAccessTokenClient(apiURL, accessToken string, opts ...ClientOption) (*Client, error) {
	opts = append(opts,
		WithHTTPClient(&http.Client{Transport: LogTransport}),
		withBearerToken(accessToken),
		withUserAgent(),
	)
	return NewClient(apiURL, opts...)
}

// Useful for /v1/companies/{urlPrefix}/loginconfig which does not require
// authentication nor requires an explicit API URL. The api.Client's Server is
// left empty, the user must provide full URLs to the endpoints.
func NewAnonymousClient() (http.Client, error) {
	return http.Client{Transport: &transportWithUserAgent{transport: LogTransport}}, nil
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

// withBearerToken returns a copy of the provided http.Client that adds the
// header "Authorization: Bearer <token>" with the provided access token.
func withBearerToken(token string) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		})
		return nil
	}
}

func withUserAgent() ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, func(ctx context.Context, req *http.Request) error {
			req.Header.Set("User-Agent", UserAgent)
			return nil
		})
		return nil
	}
}

const shaLen = 7

func buildVersion() string {
	commit := ""
	version := ""
	if version == "" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
			version = info.Main.Version
			commit = getKey(info, "vcs.revision")
		} else {
			version = "unknown (built from source)"
		}
	}
	if len(commit) >= shaLen {
		version += " (" + commit[:shaLen] + ")"
	}
	return version
}

func getKey(info *debug.BuildInfo, key string) string {
	if info == nil {
		return ""
	}
	for _, iter := range info.Settings {
		if iter.Key == key {
			return iter.Value
		}
	}
	return ""
}

type transportWithUserAgent struct {
	transport http.RoundTripper
}

func (t *transportWithUserAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", UserAgent)
	return t.transport.RoundTrip(req)
}
