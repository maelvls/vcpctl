package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type HTTPError struct {
	Err error

	Status     string
	StatusCode int

	Resp *http.Response
}

// Body must not have been read yet. The return error looks like this:
//
// When the response body is empty, we just show the status:
//
//	HTTP 401 Unauthorized
//
// When the response body is JSON but can't be parsed as VenafiError:
//
//	HTTP 400 Bad Request: {"unexpected":"error message"}
//
// When the response body isn't JSON (e.g., because some middle proxy returned
// some HTML instead), we just show it as is:
//
//	HTTP 500 Internal Server Error: <html>Gateway Error</html>
func HTTPErrorFrom(resp *http.Response) error {
	original := resp.Body
	copy := &bytes.Buffer{}
	resp.Body = io.NopCloser(copy)
	return HTTPError{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Err:        ErrFromJSONBody(io.TeeReader(original, copy)),
		Resp:       resp,
	}
}

func (e HTTPError) Error() string {
	if e.Err.Error() == "" {
		return fmt.Sprintf("HTTP %s", e.Status)
	}
	return fmt.Sprintf("HTTP %s: %s", e.Status, e.Err.Error())
}

func (e HTTPError) Unwrap() error {
	return e.Err
}

func ErrIsHTTPBadRequest(err error) bool {
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusBadRequest
	}
	return false
}

func ErrIsHTTPUnauthorized(err error) bool {
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusUnauthorized
	}
	return false
}
