package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

type HTTPError struct {
	Err error

	Status     string
	StatusCode int
	Body       string
}

// Body must not have been read yet.
func HTTPErrorf(resp *http.Response, format string, values ...any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading response body: %w", err)
	}

	return HTTPError{
		Err:        fmt.Errorf(format, values...),
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
}

func ErrIsHTTPBadRequest(err error) bool {
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusBadRequest
	}
	return false
}

func (e HTTPError) Error() string {
	return e.Err.Error()
}
