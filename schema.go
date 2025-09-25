package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// To update schema.json, run `go generate ./...`.

//go:embed "genschema/schema.json"
var schemaJSON []byte

func validateFireflyConfig(input FireflyConfig) error {
	// Work around some issues with the OpenAPI schema:
	// 	- at '/cloudProviders': got null, want object
	// 	- at '/serviceAccountIds': got null, want array
	if input.CloudProviders == nil {
		input.CloudProviders = make(map[string]any)
	}
	if input.ServiceAccountIDs == nil {
		input.ServiceAccountIDs = make([]string, 0)
	}

	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshalling JSON: %w", err)
	}

	schemaCompiler := jsonschema.NewCompiler()

	schemaParsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return fmt.Errorf("unmarshalling JSON: %w", err)
	}
	err = schemaCompiler.AddResource("mem://schema.json", schemaParsed)
	if err != nil {
		return fmt.Errorf("programmer mistake: failed to add schema: %w", err)
	}

	schema, err := schemaCompiler.Compile("mem://schema.json")
	if err != nil {
		return fmt.Errorf("programmer mistake: failed to compile schema: %w", err)
	}

	j, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("unmarshalling JSON: %w", err)
	}

	err = schema.Validate(j)
	if err == nil {
		return nil
	}

	// The error message is confusing as it talks about "mem://schema.json".
	// Let's make it clearer.
	var errAs *jsonschema.ValidationError
	if ok := errors.As(err, &errAs); !ok {
		return Fixable(fmt.Errorf("validating JSON: %w", err))
	}
	var str []string
	for _, cause := range errAs.Causes {
		str = append(str, cause.Error())
	}
	if len(str) == 1 {
		return Fixable(fmt.Errorf("%s", str[0]))
	}
	return Fixable(fmt.Errorf("\n* %s", strings.Join(str, "\n *")))
}
