package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Returns a VenafiError if it can be parsed from the JSON body, or a generic
// error containing the raw body otherwise. err.Error() might be empty if the
// body is empty!
func ErrFromJSONBody(body io.Reader) error {
	bodyBytes, _ := io.ReadAll(body)

	// For some reason, CyberArk Certificate Manager, SaaS returns a plain text
	// error message when the API key is invalid.
	if bytes.Equal(bodyBytes, []byte("Invalid api key")) {
		return fmt.Errorf("%s", bodyBytes)
	}

	var v VenafiError
	err := json.Unmarshal(bodyBytes, &v)
	if err != nil {
		return fmt.Errorf("%s", string(bodyBytes))
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

func (e VenafiError) HasCode(code int) bool {
	for _, err := range e.Errors {
		if err.Code == code {
			return true
		}
	}
	return false
}

func (e VenafiError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d: %s", err.Code, err.Message))
	}
	return fmt.Sprintf("\n* %s", strings.Join(msgs, "\n* "))
}
