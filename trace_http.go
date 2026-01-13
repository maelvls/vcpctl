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

// Redact the 90% first characters of the API key in the header for security.
// Replace the same number of chars. Creates a new copy of the headers.
func redactSensitiveHeaders(headers http.Header) http.Header {
	redacted := headers.Clone()

	apiKey := redacted.Get("tppl-api-key")
	if len(apiKey) > 0 {
		redacted.Set("tppl-api-key", strings.Repeat("*", len(apiKey)-len(apiKey)*1/10)+apiKey[len(apiKey)*9/10:])
	}

	authorization := redacted.Get("Authorization")
	if len(authorization) > 0 {
		redacted.Set("Authorization", strings.Repeat("*", len(authorization)-len(authorization)*1/10)+authorization[len(authorization)*9/10:])
	}

	return redacted
}

// Body might contain the 'privateKey' and 'ociToken' fields. Let's redact them.
func redactSensitiveBody(body string) string {
	redacted := body
	redacted = redactJSONField(redacted, "privateKey")
	redacted = redactJSONField(redacted, "ociToken")
	return redacted
}

func redactJSONField(body string, field string) string {
	// This is a very naive implementation but should be sufficient for logging
	// purposes.
	prefix := fmt.Sprintf(`"%s":"`, field)
	start := strings.Index(body, prefix)
	if start == -1 {
		return body
	}
	start += len(prefix)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		return body
	}
	end += start
	redactedValue := strings.Repeat("*", end-start)
	return body[:start] + redactedValue + body[end:]
}

func LogRequest(req *http.Request) {
	if !logutil.EnableDebug {
		return
	}

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

	// Debug string: format headers as key=value pairs.
	headers := redactSensitiveHeaders(req.Header)
	var s []string
	for k, v := range headers {
		s = append(s, fmt.Sprintf("%s=%s", k, strings.Join(v, ",")))
	}
	headersStr := strings.Join(s, " ")

	// Debug string: replace newlines with spaces and fold repeated spaces for
	// better readability.
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
