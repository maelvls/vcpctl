package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/spf13/cobra"
)

type apiOptions struct {
	method              string
	methodPassed        bool
	magicFields         []string
	rawFields           []string
	headers             []string
	showResponseHeaders bool
}

func apiCmd() *cobra.Command {
	opts := &apiOptions{}

	cmd := &cobra.Command{
		Use:   "api <path>",
		Short: "Make an authenticated HTTP request to the API",
		Long: `Make an authenticated HTTP request to the API and print the response.

The path should start with a slash and can optionally include /v1/ prefix.
If /v1/ is not present, it will be automatically prepended.

Field value conversions:
  - Numeric values are converted to integers: -F count=123
  - Boolean literals are converted: -F enabled=true
  - Null is converted: -F value=null
  - Files can be read: -F data=@filename or -F data=@- (stdin)
  - Everything else is a string: -F name="value"

Use -f/--raw-field to always send values as strings without conversion.
`,
		Example: undent.Undent(`
			# GET request
			vcpctl api /v1/serviceaccounts

			# POST request with fields
			vcpctl api /v1/serviceaccounts -F name=mysa -F description="My Service Account"

  			# Include response headers
  			vcpctl api /v1/serviceaccounts -i

  			# Custom method
  			vcpctl api -X DELETE /v1/serviceaccounts/abc123
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAPI(cmd, opts, args[0])
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringVarP(&opts.method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringArrayVarP(&opts.magicFields, "field", "F", nil, "Add a parameter with type conversion (key=value)")
	cmd.Flags().StringArrayVarP(&opts.rawFields, "raw-field", "f", nil, "Add a string parameter (key=value)")
	cmd.Flags().StringArrayVarP(&opts.headers, "header", "H", nil, "Add a request header (key:value)")
	cmd.Flags().BoolVarP(&opts.showResponseHeaders, "include", "i", false, "Include HTTP response headers in output")

	// Track if method was explicitly set
	cmd.Flags().Lookup("method").Changed = false
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		opts.methodPassed = cmd.Flags().Changed("method")
		return nil
	}

	return cmd
}

func runAPI(cmd *cobra.Command, opts *apiOptions, path string) error {
	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	params := make(map[string]any)

	// Process raw fields (strings only).
	for _, f := range opts.rawFields {
		key, value, err := parseField(f)
		if err != nil {
			return err
		}
		params[key] = value
	}

	// Process magic fields (with type conversion).
	for _, f := range opts.magicFields {
		key, strValue, err := parseField(f)
		if err != nil {
			return err
		}
		value, err := magicFieldValue(cmd.Context(), strValue)
		if err != nil {
			return err
		}
		params[key] = value
	}

	// Auto-detect method if not explicitly set.
	method := opts.method
	if len(params) > 0 && !opts.methodPassed {
		method = "POST"
	}

	cl, err := newAPIClient(conf)
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}
	resp, err := makeAPIRequest(cmd.Context(), cl, method, path, params, opts.headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Show response headers if requested.
	if opts.showResponseHeaders {
		fmt.Fprintf(os.Stderr, "%s %s\r\n", resp.Proto, resp.Status)
		for name, vals := range resp.Header {
			for _, val := range vals {
				fmt.Fprintf(os.Stderr, "%s: %s\r\n", name, val)
			}
		}
		fmt.Fprintf(os.Stderr, "\r\n")
	}

	// Output response body (skip for 204 No Content).
	if resp.StatusCode != http.StatusNoContent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}

		os.Stdout.Write(body)

		// Add a newline if the output doesn't end with one.
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Println()
		}
	}

	// Exit with error for non-2xx status codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}

// parseField splits a "key=value" string into key and value parts.
func parseField(f string) (string, string, error) {
	idx := strings.IndexRune(f, '=')
	if idx == -1 {
		return "", "", fmt.Errorf("field %q requires a value separated by '='", f)
	}
	return f[0:idx], f[idx+1:], nil
}

// magicFieldValue converts a string value to its appropriate type:
// - @filename or @- reads from file or stdin
// - Numeric strings become integers
// - "true", "false", "null" become boolean or nil
// - Everything else remains a string
func magicFieldValue(ctx context.Context, v string) (any, error) {
	// File reading: @filename or @- for stdin
	if strings.HasPrefix(v, "@") {
		filename := v[1:]
		var data []byte
		var err error

		var fd io.Reader
		if filename == "-" {
			fd = os.Stdin
		} else {
			fdCloser, err := os.Open(filename)
			if err != nil {
				return nil, fmt.Errorf("opening file %q: %w", filename, err)
			}
			defer fdCloser.Close()
			fd = fdCloser
		}

		data, err = io.ReadAll(New(ctx, fd))
		if err != nil {
			return nil, fmt.Errorf("reading file %q: %w", filename, err)
		}
		return string(data), nil
	}

	// Integer conversion
	if n, err := strconv.Atoi(v); err == nil {
		return n, nil
	}

	// Boolean and null literals
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}

	// Default: return as string
	return v, nil
}

func makeAPIRequest(ctx context.Context, cl *api.Client, method, path string, params map[string]any, headers []string) (*http.Response, error) {
	// The 'Server' field of the api.Client always has a trailing slash. Which
	// means we need to remove any leading slash from 'path'. Also, since we
	// allow the user to skip the leading '/v1/' part, we add it if missing.
	path = strings.TrimPrefix(path, "/")
	if !strings.HasPrefix(path, "v1/") {
		if strings.HasPrefix(path, "/") {
			path = "/v1" + path
		}
	}

	url := cl.Server + path

	var body io.Reader
	var bodyIsJSON bool

	if len(params) > 0 {
		jsonData, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		body = bytes.NewReader(jsonData)
		bodyIsJSON = true
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Since we aren't using the generated client's methods, we need to apply
	// the request editors manually (for the tppl-api-key and user-agent
	// headers, among others).
	for i, edit := range cl.RequestEditors {
		if err := edit(ctx, req); err != nil {
			return nil, fmt.Errorf("applying request edit %d: %w", i, err)
		}
	}

	if bodyIsJSON {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, h := range headers {
		idx := strings.IndexRune(h, ':')
		if idx == -1 {
			return nil, fmt.Errorf("header %q requires a value separated by ':'", h)
		}
		key := h[0:idx]
		value := strings.TrimSpace(h[idx+1:])
		req.Header.Set(key, value)
	}

	return cl.Client.Do(req)
}

type CancelableReader struct {
	ctx  context.Context
	data chan []byte
	err  error
	r    io.Reader
}

func (c *CancelableReader) begin() {
	buf := make([]byte, 1024)
	for {
		n, err := c.r.Read(buf)
		if n > 0 {
			tmp := make([]byte, n)
			copy(tmp, buf[:n])
			c.data <- tmp
		}
		if err != nil {
			c.err = err
			close(c.data)
			return
		}
	}
}

func (c *CancelableReader) Read(p []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case d, ok := <-c.data:
		if !ok {
			return 0, c.err
		}
		copy(p, d)
		return len(d), nil
	}
}

func New(ctx context.Context, r io.Reader) *CancelableReader {
	c := &CancelableReader{
		r:    r,
		ctx:  ctx,
		data: make(chan []byte),
	}
	go c.begin()
	return c
}
