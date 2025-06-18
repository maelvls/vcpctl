package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed "schema.json"
var schemaJSON []byte

func validateYAMLFireflyConfig(input []byte) error {
	jsonBytes, err := yaml.YAMLToJSON(input)
	if err != nil {
		return fmt.Errorf("converting YAML to JSON: %w", err)
	}

	schemaCompiler := jsonschema.NewCompiler()

	schemaParsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return fmt.Errorf("unmarshalling JSON: %w", err)
	}
	err = schemaCompiler.AddResource("mem://firefly-config-schema.json", schemaParsed)
	if err != nil {
		return fmt.Errorf("programmer mistake: failed to add schema: %w", err)
	}

	schema, err := schemaCompiler.Compile("mem://firefly-config-schema.json")
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

	var errAs *jsonschema.ValidationError
	if ok := errors.As(err, &errAs); !ok {
		return fmt.Errorf("validating JSON: %w", err)
	}

	var str []string
	for _, cause := range errAs.Causes {
		str = append(str, cause.Error())
	}
	if len(str) == 1 {
		return fmt.Errorf(str[0])
	}
	return fmt.Errorf("\n* %s", strings.Join(str, "\n *"))
}
