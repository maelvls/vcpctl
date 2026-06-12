package api

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNGTSError(t *testing.T) {
	t.Run("parses IAM_401 error", func(t *testing.T) {
		body := `{"_error":{"code":"IAM_401","message":"Invalid Request Token.","_request_id":"test-123"}}`
		err := ErrFromJSONBody(strings.NewReader(body))

		var ngtsErr NGTSError
		require.True(t, errors.As(err, &ngtsErr), "expected NGTSError type")
		assert.True(t, ngtsErr.HasCode("IAM_401"))
		assert.Equal(t, "IAM_401: Invalid Request Token.", ngtsErr.Error())
		assert.Equal(t, "test-123", ngtsErr.Err.RequestID)
	})

	t.Run("parses NGTS error without request ID", func(t *testing.T) {
		body := `{"_error":{"code":"SOME_ERROR","message":"Something went wrong"}}`
		err := ErrFromJSONBody(strings.NewReader(body))

		var ngtsErr NGTSError
		require.True(t, errors.As(err, &ngtsErr))
		assert.True(t, ngtsErr.HasCode("SOME_ERROR"))
		assert.Equal(t, "SOME_ERROR: Something went wrong", ngtsErr.Error())
	})

	t.Run("still parses Venafi errors", func(t *testing.T) {
		body := `{"errors":[{"code":1006,"message":"request object parsing failed"}]}`
		err := ErrFromJSONBody(strings.NewReader(body))

		var venafiErr VenafiError
		require.True(t, errors.As(err, &venafiErr), "expected VenafiError type")
		assert.True(t, venafiErr.HasCode(1006))
	})

	t.Run("handles empty NGTS error structure", func(t *testing.T) {
		body := `{"_error":{}}`
		err := ErrFromJSONBody(strings.NewReader(body))

		// Should fall back to VenafiError parsing since IsEmpty() returns true
		var venafiErr VenafiError
		require.True(t, errors.As(err, &venafiErr))
		assert.Equal(t, "\n* ", err.Error())
	})

	t.Run("handles plain text error", func(t *testing.T) {
		body := `Invalid api key`
		err := ErrFromJSONBody(strings.NewReader(body))

		assert.Equal(t, "Invalid api key", err.Error())
	})

	t.Run("handles invalid JSON", func(t *testing.T) {
		body := `not valid json`
		err := ErrFromJSONBody(strings.NewReader(body))

		assert.Equal(t, "not valid json", err.Error())
	})

	t.Run("NGTSError IsEmpty works correctly", func(t *testing.T) {
		empty := NGTSError{}
		assert.True(t, empty.IsEmpty())

		notEmpty := NGTSError{}
		notEmpty.Err.Code = "IAM_401"
		assert.False(t, notEmpty.IsEmpty())

		notEmpty2 := NGTSError{}
		notEmpty2.Err.Message = "Some message"
		assert.False(t, notEmpty2.IsEmpty())
	})
}

func TestHTTPError_NGTSFormat(t *testing.T) {
	t.Run("ErrIsNGTSIAM401 detects IAM_401", func(t *testing.T) {
		ngtsErr := NGTSError{}
		ngtsErr.Err.Code = "IAM_401"
		ngtsErr.Err.Message = "Invalid Request Token."

		httpErr := HTTPError{
			StatusCode: 401,
			Status:     "401 Unauthorized",
			Err:        ngtsErr,
		}

		assert.True(t, ErrIsNGTSIAM401(httpErr))
	})

	t.Run("ErrIsNGTSIAM401 rejects other NGTS errors", func(t *testing.T) {
		ngtsErr := NGTSError{}
		ngtsErr.Err.Code = "SOME_OTHER_ERROR"
		ngtsErr.Err.Message = "Some other message"

		httpErr := HTTPError{
			StatusCode: 401,
			Status:     "401 Unauthorized",
			Err:        ngtsErr,
		}

		assert.False(t, ErrIsNGTSIAM401(httpErr))
	})

	t.Run("ErrIsNGTSIAM401 rejects Venafi errors", func(t *testing.T) {
		venafiErr := VenafiError{}
		venafiErr.Errors = append(venafiErr.Errors, struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{Code: 1000, Message: "Some error"})

		httpErr := HTTPError{
			StatusCode: 401,
			Status:     "401 Unauthorized",
			Err:        venafiErr,
		}

		assert.False(t, ErrIsNGTSIAM401(httpErr))
	})

	t.Run("ErrIsNGTSIAM401 rejects non-HTTP errors", func(t *testing.T) {
		ngtsErr := NGTSError{}
		ngtsErr.Err.Code = "IAM_401"

		assert.False(t, ErrIsNGTSIAM401(ngtsErr))
	})
}
