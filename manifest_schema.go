package main

import (
	"bytes"
	_ "embed"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed "genschema/schema.json"
var schemaJSON []byte

var (
	manifestSchemaOnce sync.Once
	manifestSchema     *jsonschema.Schema
	manifestSchemaErr  error
)

func validateManifestDocument(index int, kind string, manifestYAML []byte) error {
	schema, err := compileManifestSchema()
	if err != nil {
		return fmt.Errorf("programmer mistake: %w", err)
	}

	var manifest any
	if err := yaml.Unmarshal(manifestYAML, &manifest); err != nil {
		return fmt.Errorf("while preparing manifest #%d for validation: %w", index, err)
	}

	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("while marshalling manifest #%d to JSON: %w", index, err)
	}

	j, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("while decoding manifest #%d as JSON: %w", index, err)
	}

	if err := schema.Validate(j); err != nil {
		return formatManifestValidationError(index, kind, err)
	}

	return nil
}

func compileManifestSchema() (*jsonschema.Schema, error) {
	manifestSchemaOnce.Do(func() {
		schemaCompiler := jsonschema.NewCompiler()

		schemaParsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			manifestSchemaErr = fmt.Errorf("unmarshalling JSON schema: %w", err)
			return
		}
		if err := schemaCompiler.AddResource("mem://schema.json", schemaParsed); err != nil {
			manifestSchemaErr = fmt.Errorf("failed to add schema resource: %w", err)
			return
		}

		compiled, err := schemaCompiler.Compile("mem://schema.json")
		if err != nil {
			manifestSchemaErr = fmt.Errorf("failed to compile schema: %w", err)
			return
		}
		manifestSchema = compiled
	})

	return manifestSchema, manifestSchemaErr
}

func formatManifestValidationError(index int, kind string, err error) error {
	var validationErr *jsonschema.ValidationError
	if !errors.As(err, &validationErr) {
		return Fixable(fmt.Errorf("manifest #%d (%s): validating manifest with schema: %w", index, nonEmptyKind(kind), err))
	}

	var messages []string
	for _, cause := range validationErr.Causes {
		messages = append(messages, cause.Error())
	}

	switch len(messages) {
	case 0:
		return Fixable(fmt.Errorf("manifest #%d (%s): %s", index, nonEmptyKind(kind), validationErr.Error()))
	case 1:
		return Fixable(fmt.Errorf("manifest #%d (%s): %s", index, nonEmptyKind(kind), messages[0]))
	default:
		return Fixable(fmt.Errorf("manifest #%d (%s):\n* %s", index, nonEmptyKind(kind), strings.Join(messages, "\n *")))
	}
}

func nonEmptyKind(kind string) string {
	if kind == "" {
		return "unknown kind"
	}
	return kind
}
