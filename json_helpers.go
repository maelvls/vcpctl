package main

import (
	jsontext "encoding/json/jsontext"
	json "encoding/json/v2"
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
		return err
	}
	return json.Unmarshal(data, dst)
}
