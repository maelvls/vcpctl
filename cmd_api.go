package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/spf13/cobra"
)

//go:embed api/genschema/openapi.json
var openapiSchema []byte

type apiOptions struct {
	method              string
	methodPassed        bool
	requestInputFile    string
	magicFields         []string
	rawFields           []string
	headers             []string
	showResponseHeaders bool
}

func apiCmd(groupID string) *cobra.Command {
	opts := &apiOptions{}

	cmd := &cobra.Command{
		Use:   "api [path]",
		Short: "Make an authenticated HTTP request to the API",
		Long: `Make an authenticated HTTP request to the API and print the response.

Without a path argument, lists all available API endpoints.

The path should start with a slash and can optionally include /v1/ prefix.
If /v1/ is not present, it will be automatically prepended.

Field value conversions:
  - Numeric values are converted to integers: -F count=123
  - Boolean literals are converted: -F enabled=true
  - Null is converted: -F value=null
  - Files can be read: -F data=@filename or -F data=@- (stdin)
  - Everything else is a string: -F name="value"

Nested parameters:
  - Use bracket syntax for nested objects: -F config[timeout]=30
  - Use empty brackets for arrays: -F tags[]=prod -F tags[]=api
  - Combine for complex structures: -F items[0][name]=first -F items[0][count]=5

Use -f/--raw-field to always send values as strings without conversion.

Request body:
  - Use --input to read request body from a file or stdin
  - When --input is used, field flags are added as query parameters
`,
		Example: undent.Undent(`
			# List all available endpoints
			vcpctl api

			# GET request
			vcpctl api /v1/serviceaccounts

			# POST request with fields
			vcpctl api /v1/serviceaccounts -F name=mysa -F description="My Service Account"

			# Nested parameters
			vcpctl api /v1/config -F settings[timeout]=30 -F settings[retry]=true

			# Array parameters
			vcpctl api /v1/resource -F tags[]=prod -F tags[]=api -F tags[]=v1

			# Complex nested structure
			vcpctl api /v1/items -F items[0][name]=first -F items[0][count]=5

			# Request body from file
			vcpctl api /v1/serviceaccounts --input payload.json

			# Request body from stdin
			echo '{"name":"mysa"}' | vcpctl api /v1/serviceaccounts --input -

  			# Include response headers
  			vcpctl api /v1/serviceaccounts -i

  			# Custom method
  			vcpctl api -X DELETE /v1/serviceaccounts/abc123
		`),
		Args:    cobra.MaximumNArgs(1),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return listEndpoints()
			}
			return runAPI(cmd, opts, args[0])
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringVarP(&opts.method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringVar(&opts.requestInputFile, "input", "", "Read request body from file (use \"-\" for stdin)")
	cmd.Flags().StringArrayVarP(&opts.magicFields, "field", "F", nil, "Add a parameter with type conversion (key=value)")
	cmd.Flags().StringArrayVarP(&opts.rawFields, "raw-field", "f", nil, "Add a string parameter (key=value)")
	cmd.Flags().StringArrayVarP(&opts.headers, "header", "H", nil, "Add a request header (key:value)")
	cmd.Flags().BoolVarP(&opts.showResponseHeaders, "include", "i", false, "Include HTTP response headers in output")

	// Track if method was explicitly set.
	cmd.Flags().Lookup("method").Changed = false
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		opts.methodPassed = cmd.Flags().Changed("method")
		return nil
	}

	return cmd
}

// listEndpoints parses the embedded OpenAPI schema and lists all available
// endpoints.
func listEndpoints() error {
	var schema struct {
		Paths map[string]map[string]any `json:"paths"`
	}

	if err := json.Unmarshal(openapiSchema, &schema); err != nil {
		return fmt.Errorf("parsing OpenAPI schema: %w", err)
	}

	// Collect all endpoint paths with their methods.
	type endpoint struct {
		path    string
		methods []string
	}

	var endpoints []endpoint
	for path, methods := range schema.Paths {
		ep := endpoint{path: path}
		for method := range methods {
			// Filter out non-HTTP methods (OpenAPI can have extensions).
			switch strings.ToUpper(method) {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
				ep.methods = append(ep.methods, strings.ToUpper(method))
			}
		}
		sort.Strings(ep.methods)
		endpoints = append(endpoints, ep)
	}

	// Sort endpoints by path.
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].path < endpoints[j].path
	})

	// Print endpoints.
	for _, ep := range endpoints {
		fmt.Printf("%-10s %s\n", strings.Join(ep.methods, ","), ep.path)
	}

	return nil
}

func runAPI(cmd *cobra.Command, opts *apiOptions, path string) error {
	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	params, err := parseFields(cmd.Context(), opts)
	if err != nil {
		return err
	}

	// Auto-detect method if not explicitly set.
	method := opts.method
	if (len(params) > 0 || opts.requestInputFile != "") && !opts.methodPassed {
		method = "POST"
	}

	cl, err := newAPIClient(conf)
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	var requestBody any = params
	if opts.requestInputFile != "" {
		// When using --input, read body from file and add fields as query
		// params.
		file, err := openUserFile(opts.requestInputFile)
		if err != nil {
			return err
		}
		defer file.Close()
		requestBody = file
	}

	resp, err := makeAPIRequest(cmd.Context(), cl, method, path, requestBody, opts.headers)
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

	var last byte
	tee := io.TeeReader(resp.Body, &lastByteWriter{&last})

	// Stream response body to stdout.
	_, err = io.Copy(os.Stdout, tee)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}
	if last != '\n' {
		fmt.Fprintln(os.Stdout)
	}

	// Exit with error for non-2xx status codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}

const (
	keyStart     = '['
	keyEnd       = ']'
	keySeparator = '='
)

// parseFields parses all field flags (both raw and magic) into a nested map structure.
// Supports nested syntax like key[subkey]=value and array syntax like key[]=value.
func parseFields(ctx context.Context, opts *apiOptions) (map[string]any, error) {
	params := make(map[string]any)

	parseField := func(f string, isMagic bool) error {
		var valueIndex int
		var keystack []string
		keyStartAt := 0
	parseLoop:
		for i, r := range f {
			switch r {
			case keyStart:
				if keyStartAt == 0 {
					keystack = append(keystack, f[0:i])
				}
				keyStartAt = i + 1
			case keyEnd:
				keystack = append(keystack, f[keyStartAt:i])
			case keySeparator:
				if keyStartAt == 0 {
					keystack = append(keystack, f[0:i])
				}
				valueIndex = i + 1
				break parseLoop
			}
		}

		if len(keystack) == 0 {
			return fmt.Errorf("invalid key: %q", f)
		}

		key := f
		var value any = nil
		if valueIndex == 0 {
			if keystack[len(keystack)-1] != "" {
				return fmt.Errorf("field %q requires a value separated by '='", key)
			}
		} else {
			key = f[0 : valueIndex-1]
			value = f[valueIndex:]
		}

		if isMagic && value != nil {
			var err error
			value, err = magicFieldValue(ctx, value.(string))
			if err != nil {
				return fmt.Errorf("error parsing %q value: %w", key, err)
			}
		}

		destMap := params
		isArray := false
		var subkey string
		for _, k := range keystack {
			if k == "" {
				isArray = true
				continue
			}
			if subkey != "" {
				var err error
				if isArray {
					destMap, err = addParamsSlice(destMap, subkey, k)
					isArray = false
				} else {
					destMap, err = addParamsMap(destMap, subkey)
				}
				if err != nil {
					return err
				}
			}
			subkey = k
		}

		if isArray {
			if value == nil {
				destMap[subkey] = []any{}
			} else {
				if v, exists := destMap[subkey]; exists {
					if existSlice, ok := v.([]any); ok {
						destMap[subkey] = append(existSlice, value)
					} else {
						return fmt.Errorf("expected array type under %q, got %T", subkey, v)
					}
				} else {
					destMap[subkey] = []any{value}
				}
			}
		} else {
			if _, exists := destMap[subkey]; exists {
				return fmt.Errorf("unexpected override of existing field %q", subkey)
			}
			destMap[subkey] = value
		}
		return nil
	}

	for _, f := range opts.rawFields {
		if err := parseField(f, false); err != nil {
			return params, err
		}
	}
	for _, f := range opts.magicFields {
		if err := parseField(f, true); err != nil {
			return params, err
		}
	}
	return params, nil
}

func addParamsMap(m map[string]any, key string) (map[string]any, error) {
	if v, exists := m[key]; exists {
		if existMap, ok := v.(map[string]any); ok {
			return existMap, nil
		}
		return nil, fmt.Errorf("expected map type under %q, got %T", key, v)
	}
	newMap := make(map[string]any)
	m[key] = newMap
	return newMap, nil
}

func addParamsSlice(m map[string]any, prevkey, newkey string) (map[string]any, error) {
	if v, exists := m[prevkey]; exists {
		if existSlice, ok := v.([]any); ok {
			if len(existSlice) > 0 {
				lastItem := existSlice[len(existSlice)-1]
				if lastMap, ok := lastItem.(map[string]any); ok {
					if _, keyExists := lastMap[newkey]; !keyExists {
						// Key doesn't exist in last map, reuse it.
						return lastMap, nil
					} else if existVal, ok := lastMap[newkey].([]any); ok {
						// Key exists and is an array, reuse the map to append
						// to the array.
						_ = existVal // just to use the variable
						return lastMap, nil
					}
					// Key exists but is not an array, need a new map element.
				}
			}
			newMap := make(map[string]any)
			m[prevkey] = append(existSlice, newMap)
			return newMap, nil
		}
		return nil, fmt.Errorf("expected array type under %q, got %T", prevkey, v)
	}
	newMap := make(map[string]any)
	m[prevkey] = []any{newMap}
	return newMap, nil
}

func openUserFile(fn string) (io.ReadCloser, error) {
	if fn == "-" {
		return io.NopCloser(os.Stdin), nil
	}

	r, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", fn, err)
	}
	return r, nil
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

		data, err = cancellablereader.ReadAllWithContext(ctx, fd)
		if err != nil {
			return nil, fmt.Errorf("reading file %q: %w", filename, err)
		}
		return string(data), nil
	}

	// Integer conversion.
	if n, err := strconv.Atoi(v); err == nil {
		return n, nil
	}

	// Boolean and null literals.
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}

	// Default: return as string.
	return v, nil
}

func makeAPIRequest(ctx context.Context, cl *api.Client, method, path string, requestBody any, headers []string) (*http.Response, error) {
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

	switch v := requestBody.(type) {
	case map[string]any:
		if strings.EqualFold(method, "GET") && len(v) > 0 {
			// Add fields as query parameters for GET requests
			url = addQueryParams(url, v)
		} else if len(v) > 0 {
			jsonData, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("marshaling request body: %w", err)
			}
			body = bytes.NewReader(jsonData)
			bodyIsJSON = true
		}
	case io.Reader:
		body = v
	case nil:
		// No body
	default:
		return nil, fmt.Errorf("unrecognized request body type: %T", requestBody)
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

func addQueryParams(path string, params map[string]any) string {
	if len(params) == 0 {
		return path
	}

	var parts []string
	for key, value := range params {
		switch v := value.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s=%s", key, v))
		case int:
			parts = append(parts, fmt.Sprintf("%s=%d", key, v))
		case bool:
			parts = append(parts, fmt.Sprintf("%s=%v", key, v))
		case nil:
			parts = append(parts, fmt.Sprintf("%s=", key))
		case []any:
			for _, item := range v {
				parts = append(parts, fmt.Sprintf("%s[]=%v", key, item))
			}
		default:
			// For complex types, try to marshal as JSON
			if jsonBytes, err := json.Marshal(v); err == nil {
				parts = append(parts, fmt.Sprintf("%s=%s", key, string(jsonBytes)))
			}
		}
	}

	sep := "?"
	if strings.ContainsRune(path, '?') {
		sep = "&"
	}
	return path + sep + strings.Join(parts, "&")
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

type lastByteWriter struct {
	last *byte
}

func (w *lastByteWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		*w.last = p[len(p)-1]
	}
	return len(p), nil
}
