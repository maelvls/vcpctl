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

Examples:
  # GET request
  vcpctl api /v1/serviceaccounts

  # POST request with fields
  vcpctl api /v1/serviceaccounts -F name=mysa -F description="My Service Account"

  # Include response headers
  vcpctl api /v1/serviceaccounts -i

  # Custom method
  vcpctl api -X DELETE /v1/serviceaccounts/abc123

Field value conversions:
  - Numeric values are converted to integers: -F count=123
  - Boolean literals are converted: -F enabled=true
  - Null is converted: -F value=null
  - Files can be read: -F data=@filename or -F data=@- (stdin)
  - Everything else is a string: -F name="value"

Use -f/--raw-field to always send values as strings without conversion.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAPI(cmd, opts, args[0])
		},
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

	// Build request parameters
	params := make(map[string]interface{})

	// Process raw fields (strings only)
	for _, f := range opts.rawFields {
		key, value, err := parseField(f)
		if err != nil {
			return err
		}
		params[key] = value
	}

	// Process magic fields (with type conversion)
	for _, f := range opts.magicFields {
		key, strValue, err := parseField(f)
		if err != nil {
			return err
		}
		value, err := magicFieldValue(strValue)
		if err != nil {
			return err
		}
		params[key] = value
	}

	// Auto-detect method if not explicitly set
	method := opts.method
	if len(params) > 0 && !opts.methodPassed {
		method = "POST"
	}

	cl, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
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
func magicFieldValue(v string) (interface{}, error) {
	// File reading: @filename or @- for stdin
	if strings.HasPrefix(v, "@") {
		filename := v[1:]
		var data []byte
		var err error

		if filename == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(filename)
		}

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

// makeAPIRequest constructs and executes an HTTP request to the API.
func makeAPIRequest(ctx context.Context, cl *api.Client, method, path string, params map[string]interface{}, headers []string) (*http.Response, error) {
	// Normalize path: ensure it starts with /v1/.
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasPrefix(path, "/v1/") {
		// If path starts with / but not /v1/, insert v1.
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

	if bodyIsJSON {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
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
