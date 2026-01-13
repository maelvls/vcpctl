package mocksrv

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Interaction struct {
	Expect   string // e.g. "GET /v1/distributedissuers/configurations/sa"
	MockCode int    // e.g. 200
	MockBody string // e.g. `{"id": "a860aca0","status": "ISSUED", "certificate": ""}`

	// Optional. Don't read r.Body, use the `body` argument instead.
	Assert func(t *testing.T, r *http.Request, body string)

	// Optional. If set, uses that instead of MockBody. Useful when building a
	// dynamic response. Don't read r.Body, use the `body` argument instead.
	MockBodyFunc func(t *testing.T, r *http.Request, body string) string
}

func Mock(t *testing.T, mock []Interaction, cancel func(error)) *httptest.Server {
	t.Helper()

	if cancel == nil {
		cancel = func(err error) {}
	}

	count := atomic.Int32{}

	// Remember that t.Fatal, t.FailNow and such must be only ever called from
	// the goroutine running the Test function, cf https://pkg.go.dev/testing#T.
	// Thus, you must not call them from the handler function since it'll be
	// running in a different goroutine. That's why we have cancel() to stop
	// things. You can call t.Log and t.Error, though.
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := int(count.Add(1))
		if n > len(mock) {
			w.WriteHeader(432) // Ad-hoc status code just so that we don't get confused with real status codes.
			err := fmt.Errorf("mocksrv: too many requests received, #%d: %v %v", n, r.Method, r.URL.Path)
			fmt.Fprintf(w, "%v", err)
			t.Error(err)
			cancel(err)
			return
		}

		interaction := mock[n-1]
		if interaction.Expect != fmt.Sprintf("%v %v", r.Method, r.URL.Path) {
			w.WriteHeader(432)
			err := fmt.Errorf("mocksrv: unexpected request #%d: expected '%v', got '%v %v'", n, interaction.Expect, r.Method, r.URL.Path)
			fmt.Fprintf(w, "%v", err)
			t.Error(err)
			cancel(err)
			return
		}

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		if interaction.Assert != nil {
			interaction.Assert(t, r, string(body))
		}

		t.Logf("received request #%d: '%v %v'", n, r.Method, r.URL.Path)
		w.WriteHeader(interaction.MockCode)
		if interaction.MockBodyFunc != nil {
			interaction.MockBody = interaction.MockBodyFunc(t, r, string(body))
		}
		fmt.Fprintln(w, interaction.MockBody)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		assert.Equal(t, int32(len(mock)), count.Load(), "the actual number of requests made to the mock server does not match the expected number")
	})

	return server
}

func UnorderedMock(t *testing.T, mock []Interaction, cancel func(error)) *httptest.Server {
	t.Helper()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Search for the interaction that matches the request.
		var n int
		var found bool
		for i, interaction := range mock {
			if interaction.Expect == fmt.Sprintf("%v %v", r.Method, r.URL.Path) {
				n = i + 1 // +1 because we want to use 1-based indexing for the error messages.
				found = true
				break
			}
		}

		if !found {
			w.WriteHeader(432)
			err := fmt.Errorf("mocksrv: unexpected request: %v %v", r.Method, r.URL.Path)
			fmt.Fprintf(w, "%v", err)
			t.Error(err)
			cancel(err)
			return
		}

		interaction := mock[n-1] // n is 1-based, so we need to subtract 1 to get the index.

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		if interaction.Assert != nil {
			interaction.Assert(t, r, string(body))
		}

		t.Logf("received request: '%v %v'", r.Method, r.URL.Path)
		w.WriteHeader(interaction.MockCode)
		if interaction.MockBodyFunc != nil {
			interaction.MockBody = interaction.MockBodyFunc(t, r, string(body))
		}
		fmt.Fprintln(w, interaction.MockBody)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)

	return server
}
