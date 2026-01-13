package main

import (
	jsontext "encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
)

func marshalIndent(v any, prefix, indent string) ([]byte, error) {
	opts := []json.Options{jsontext.Multiline(true)}
	if indent != "" {
		opts = append(opts, jsontext.WithIndent(indent))
	}
	if prefix != "" {
		opts = append(opts, jsontext.WithIndentPrefix(prefix))
	}
	return json.Marshal(v, opts...)
}

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
