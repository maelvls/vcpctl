package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maelvls/vcpctl/logutil"
	"github.com/motemen/go-loghttp"
)

var (
	Transport = &loghttp.Transport{LogRequest: LogRequest, LogResponse: LogResponse, Transport: http.DefaultTransport}
)

func LogRequest(req *http.Request) {
	if !logutil.EnableDebug {
		return
	}

	// Redact the 80% first characters of the API key in the header for
	// security. Replace the same number of chars.
	headers := req.Header.Clone()
	apiKey := req.Header.Get("tppl-api-key")
	if len(apiKey) > 0 {
		headers.Set("tppl-api-key", strings.Repeat("*", len(apiKey)-len(apiKey)*1/5)+apiKey[len(apiKey)*4/5:])
	}
	var s []string
	for k, v := range headers {
		s = append(s, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
	}
	headersStr := strings.Join(s, " ")

	var body string
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			logutil.Errorf("Failed to read request body: %v", err)
			body = "<error reading body>"
		} else {
			body = string(bodyBytes)

			// Restore the body for further use.
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	// Replace newlines with spaces and fold repeated spaces for better
	// readability.
	body = strings.Join(strings.Fields(body), " ")

	if body == "" {
		body = ", no body"
	} else if len(body) > 100 {
		// Truncate long bodies for readability.
		body = ", body:" + body[:100] + "..."
	} else {
		body = ", body:" + body
	}
	logutil.Debugf("req:  %s %s %s%s", req.Method, req.URL, headersStr, body)
}

func LogResponse(resp *http.Response) {
	if !logutil.EnableDebug {
		return
	}

	var body string
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logutil.Errorf("Failed to read response body: %v", err)
		body = "<error reading body>"
	} else {
		body = string(bodyBytes)

		// Restore the body for further use.
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	var s []string
	for k, v := range resp.Header {
		s = append(s, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
	}

	// Replace newlines with spaces and fold repeated spaces for better
	// readability.
	body = strings.Join(strings.Fields(body), " ")

	if body == "" {
		body = ", no body"
	} else if len(body) > 100 {
		// Truncate long bodies for readability.
		body = ", body:" + body[:100] + "..."
	} else {
		body = ", body:" + body
	}
	logutil.Debugf("resp: %d %v%s", resp.StatusCode, strings.Join(s, " "), body)
}
