package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maelvls/vcpctl/errutil"
)

// Use errors.Is(err, APIKeyInvalid{}) to check if the error is due to the API
// key having a problem.
var APIKeyInvalid = errors.New("API key is invalid")

func ParseJSONErrorOrDumpBody(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	// For some reason, CyberArk Certificate Manager, SaaS returns a plain text
	// error message when the API key is invalid.
	if resp.Header.Get("Content-Type") == "text/plain" && bytes.Equal(body, []byte("Invalid api key")) {
		return errutil.Fixable(APIKeyInvalid)
	}

	var v VenafiError
	err := json.Unmarshal(body, &v)
	if err != nil {
		return fmt.Errorf("unexpected error: '%s'", string(body))
	}

	return v
}

// Examples:
//
//	{"errors":[{"code":1006,"message":"request object parsing failed","args":["request object parsing failed"]}]}
//	{"errors":[{"code":10051,"message":"Unable to find VenafiCaIssuerPolicy for key [c549e230-454c-11f0-906f-19aebcf83bb8]","args":["VenafiCaIssuerPolicy",["c549e230-454c-11f0-906f-19aebcf83bb8"]]}]}
type VenafiError struct {
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (e VenafiError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d: %s", err.Code, err.Message))
	}
	return fmt.Sprintf("\n* %s", strings.Join(msgs, "\n* "))
}
