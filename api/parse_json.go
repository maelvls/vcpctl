package api

import (
	"encoding/json"
	"fmt"
	"io"
)

func decodeJSON(r io.Reader, dst any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("reading JSON response body: %w", err)
	}

	err = json.Unmarshal(data, dst)
	if err != nil {
		return fmt.Errorf("decoding JSON response body: %w, body was: %s", err, string(data))
	}
	return nil
}
