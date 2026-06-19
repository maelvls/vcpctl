package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/mocksrv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshingAccessTokenTransport_IAM401(t *testing.T) {
	t.Run("NGTS IAM_401 triggers token refresh", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"IAM_401","message":"Invalid Request Token.","_request_id":"test-123"}}`,
			},
			{
				Expect:   "GET /v1/test",
				MockCode: 200,
				MockBody: `{"success":true}`,
				Assert: func(t *testing.T, r *http.Request, body string) {
					assert.Equal(t, "Bearer new-token", r.Header.Get("Authorization"))
				},
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, refreshCalled, "refresh function should have been called")
		assert.Equal(t, "new-token", source.Token())
	})

	t.Run("NGTS non-IAM_401 error doesn't trigger refresh", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"FORBIDDEN","message":"Access denied.","_request_id":"test-456"}}`,
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode)
		assert.False(t, refreshCalled, "refresh function should NOT have been called for non-IAM_401 error")
		assert.Equal(t, "old-token", source.Token())
	})

	t.Run("refresh failure includes helpful error message", func(t *testing.T) {
		refreshFunc := func(ctx context.Context) (string, error) {
			return "", assert.AnError
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"IAM_401","message":"Invalid Request Token.","_request_id":"test-789"}}`,
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		_, err = client.Do(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to refresh access token after receiving 401 Unauthorized")
	})

	t.Run("Venafi 401 still triggers refresh for backward compatibility", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 401,
				MockBody: `{"errors":[{"code":1000,"message":"Unauthorized"}]}`,
			},
			{
				Expect:   "GET /v1/test",
				MockCode: 200,
				MockBody: `{"success":true}`,
				Assert: func(t *testing.T, r *http.Request, body string) {
					assert.Equal(t, "Bearer new-token", r.Header.Get("Authorization"))
				},
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, refreshCalled, "refresh function should have been called for Venafi 401")
		assert.Equal(t, "new-token", source.Token())
	})

	t.Run("successful initial request doesn't trigger refresh", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 200,
				MockBody: `{"success":true}`,
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("valid-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		assert.False(t, refreshCalled, "refresh function should NOT have been called for successful request")
		assert.Equal(t, "valid-token", source.Token())
	})

	t.Run("no refresh function means no retry", func(t *testing.T) {
		interactions := []mocksrv.Interaction{
			{
				Expect:   "GET /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"IAM_401","message":"Invalid Request Token."}}`,
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: nil, // No refresh function
		}

		client := &http.Client{Transport: transport}
		req, err := http.NewRequest("GET", server.URL+"/v1/test", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode)
	})

	t.Run("request with body that has GetBody works with retry", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "POST /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"IAM_401","message":"Invalid Request Token."}}`,
				Assert: func(t *testing.T, r *http.Request, body string) {
					assert.Equal(t, `{"data":"test"}`, body)
				},
			},
			{
				Expect:   "POST /v1/test",
				MockCode: 200,
				MockBody: `{"success":true}`,
				Assert: func(t *testing.T, r *http.Request, body string) {
					assert.Equal(t, "Bearer new-token", r.Header.Get("Authorization"))
					assert.Equal(t, `{"data":"test"}`, body)
				},
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}
		bodyContent := `{"data":"test"}`
		req, err := http.NewRequest("POST", server.URL+"/v1/test", strings.NewReader(bodyContent))
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)
		assert.True(t, refreshCalled)
	})

	t.Run("request with body but no GetBody doesn't retry", func(t *testing.T) {
		refreshCalled := false
		refreshFunc := func(ctx context.Context) (string, error) {
			refreshCalled = true
			return "new-token", nil
		}

		interactions := []mocksrv.Interaction{
			{
				Expect:   "POST /v1/test",
				MockCode: 401,
				MockBody: `{"_error":{"code":"IAM_401","message":"Invalid Request Token."}}`,
			},
		}

		server := mocksrv.Mock(t, interactions, nil)

		source := newAccessTokenSource("old-token")
		transport := &refreshingAccessTokenTransport{
			base:    http.DefaultTransport,
			source:  source,
			refresh: refreshFunc,
		}

		client := &http.Client{Transport: transport}

		// Create a body reader without GetBody
		bodyReader := io.NopCloser(strings.NewReader(`{"data":"test"}`))
		req, err := http.NewRequest("POST", server.URL+"/v1/test", bodyReader)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, 401, resp.StatusCode)
		assert.False(t, refreshCalled, "should not retry when body has no GetBody")
	})
}

func TestIsNGTSError(t *testing.T) {
	t.Run("detects NGTS error", func(t *testing.T) {
		ngtsErr := api.NGTSError{}
		ngtsErr.Err.Code = "IAM_401"

		httpErr := api.HTTPError{
			StatusCode: 401,
			Status:     "401 Unauthorized",
			Err:        ngtsErr,
		}

		assert.True(t, isNGTSError(httpErr))
	})

	t.Run("rejects Venafi error", func(t *testing.T) {
		venafiErr := api.VenafiError{}
		venafiErr.Errors = append(venafiErr.Errors, struct {
			Code    int           `json:"code"`
			Message string        `json:"message"`
			Args    []any `json:"args,omitempty"`
		}{Code: 1000, Message: "Error"})

		httpErr := api.HTTPError{
			StatusCode: 401,
			Status:     "401 Unauthorized",
			Err:        venafiErr,
		}

		assert.False(t, isNGTSError(httpErr))
	})

	t.Run("rejects non-HTTPError", func(t *testing.T) {
		ngtsErr := api.NGTSError{}
		ngtsErr.Err.Code = "IAM_401"

		assert.False(t, isNGTSError(ngtsErr))
	})
}
