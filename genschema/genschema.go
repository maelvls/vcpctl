package main

import (
	"bytes"
	jsontext "encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"

	"dario.cat/mergo"
	"github.com/maelvls/vcpctl/logutil"
)

const (
	// At first, I was using the combined
	// https://developer.venafi.com/tlsprotectcloud/openapi/63869db3ff852b006f5cd0ec
	// link that I found by visiting
	// https://developer.venafi.com/tlsprotectcloud/openapi/. But I found that
	// this OpenAPI spec is outdated. Instead, I use some dev URLs and combine
	// the relevant parts from the two services that I need.
	vcamanagementOpenAPIURL = "https://api.venafi.cloud/v3/api-docs/vcamanagement-service"
	accountOpenAPIURL       = "https://api.venafi.cloud/v3/api-docs/account-service"
	unifiedOpenAPIURL       = "https://developer.venafi.com/tlsprotectcloud/openapi/63869db3ff852b006f5cd0ec"
)

// Usage:ServiceAccountDetails
//
//	go run ./genschema
func main() {
	if len(os.Args) != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: genschema\n")
		os.Exit(1)
	}

	oapi1, err := fetchSchema(unifiedOpenAPIURL)
	if err != nil {
		panic(err)
	}

	// Fetch and filter only relevant schema definitions from the upstream
	// OpenAPI spec.
	oapi2, err := fetchSchema(vcamanagementOpenAPIURL)
	if err != nil {
		panic(err)
	}

	oapi3, err := fetchSchema(accountOpenAPIURL)
	if err != nil {
		panic(err)
	}

	// Step 1: Generate JSON schemas. First off, let's merge the
	// components.schemas from all three OpenAPI specs.
	schemas := mergeDefs(
		oapi1["components"].(map[string]any)["schemas"].(map[string]any),
		oapi2["components"].(map[string]any)["schemas"].(map[string]any),
		oapi3["components"].(map[string]any)["schemas"].(map[string]any),
	)

	err = createSchemaWithTemplate("serviceaccount.schema.tmpl.json", schemas, []string{"ServiceAccountBaseObject"}, "serviceaccount.schema.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = createSchemaWithTemplate("wimconfiguration.schema.tmpl.json", schemas, []string{"ExtendedConfigurationInformation"}, "wimconfiguration.schema.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = createSchemaWithTemplate("wimissuerpolicy.schema.tmpl.json", schemas, []string{"PolicyInformation"}, "wimissuerpolicy.schema.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = createSchemaWithTemplate("wimsubcaprovider.schema.tmpl.json", schemas, []string{"SubCaProviderInformation"}, "wimsubcaprovider.schema.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Merge all 3 OpenAPI specs into one big OpenAPI spec.
	merged := make(map[string]any)
	err = mergo.MergeWithOverwrite(&merged, oapi1)
	if err != nil {
		panic(fmt.Errorf("merging oapi1: %w", err))
	}
	err = mergo.MergeWithOverwrite(&merged, oapi2)
	if err != nil {
		panic(fmt.Errorf("merging oapi2: %w", err))
	}
	err = mergo.MergeWithOverwrite(&merged, oapi3)
	if err != nil {
		panic(fmt.Errorf("merging oapi3: %w", err))
	}

	// Fix a bug in the ClientAuthenticationOpenApi schema where it doesn't have
	// a mapping in its discriminator, and the individual items don't have a
	// reference the discriminator. See:
	// https://venafi.atlassian.net/browse/VC-45818
	err = mergo.Merge(&merged, map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"ClientAuthenticationInformation": map[string]any{
					"discriminator": map[string]any{
						"mapping": map[string]string{
							"JWT_JWKS":            "#/components/schemas/JwtStandardClaimsAuthenticationInformation",
							"JWT_OIDC":            "#/components/schemas/JwtJwksAuthenticationInformation",
							"JWT_STANDARD_CLAIMS": "#/components/schemas/JwtOidcAuthenticationInformation",
						},
					},
				},
				"JwtStandardClaimsAuthenticationInformation": map[string]any{
					"allOf": []any{
						map[string]any{
							"$ref": "#/components/schemas/ClientAuthenticationInformation",
						},
					},
				},
				"JwtJwksAuthenticationInformation": map[string]any{
					"allOf": []any{
						map[string]any{
							"$ref": "#/components/schemas/ClientAuthenticationInformation",
						},
					},
				},
				"JwtOidcAuthenticationInformation": map[string]any{
					"allOf": []any{
						map[string]any{
							"$ref": "#/components/schemas/ClientAuthenticationInformation",
						},
					},
				},
			},
		},
	}, mergo.WithOverride)
	if err != nil {
		panic(fmt.Errorf("merging discriminator fix: %w", err))
	}

	// For some reason, the ClientAuthenticationInformationRequestOpenApi is a
	// duplicate of ClientAuthenticationInformation. We just replace all
	// references to the former with references to the latter. See:
	// https://venafi.atlassian.net/browse/VC-45818
	err = changeRef(merged, "#/components/schemas/ClientAuthenticationRequestOpenApi", "#/components/schemas/ClientAuthenticationInformation")
	if err != nil {
		panic(fmt.Errorf("changing ref: %w", err))
	}
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any), "ClientAuthenticationRequestOpenApi")
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any), "ClientAuthenticationOpenApi")
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any), "JwtJwksAuthenticationOpenApi")
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any), "JwtOidcAuthenticationOpenApi")
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any), "JwtStandardClaimsAuthenticationOpenApi")

	// Make sure that ExtendedConfigurationInformation is a allOf of
	// ConfigurationInformation and some extra fields.
	err = changeRef(merged, "#/components/schemas/ExtendedConfigurationInformation", "#/components/schemas/ConfigurationInformationRespExtended")
	if err != nil {
		panic(fmt.Errorf("changing ref: %w", err))
	}
	err = changeRef(merged, "#/components/schemas/ConfigurationInformation", "#/components/schemas/ConfigurationInformationResp")
	if err != nil {
		panic(fmt.Errorf("changing ref: %w", err))
	}
	err = mergo.Merge(&merged, map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"ConfigurationInformationBase": merged["components"].(map[string]any)["schemas"].(map[string]any)["ConfigurationCreateRequest"],

				// Request you send in PATCH.
				"ConfigurationUpdateRequest": map[string]any{
					"$ref": "#/components/schemas/ConfigurationInformationBase",
				},

				// Request you send in POST.
				"ConfigurationCreateRequest": map[string]any{
					"$ref": "#/components/schemas/ConfigurationInformationBase",
				},

				// Response you get from GET /intermediatecertificates and /intermediatecertificates/{id}.
				"ConfigurationInformationResp": map[string]any{
					"allOf": []any{
						map[string]any{
							"$ref": "#/components/schemas/ConfigurationInformationBase",
						},
						map[string]any{
							"type": "object",
							"properties": map[string]any{
								"id": map[string]any{
									"type":   "string",
									"format": "uuid",
								},
							},
						},
					},
				},

				// Response you get from GET, POST, and PATCH /
				"ConfigurationInformationRespExtended": map[string]any{
					"allOf": []any{
						map[string]any{
							"$ref": "#/components/schemas/ConfigurationInformationResp",
						},
						map[string]any{
							"type": "object",
							"properties": map[string]any{
								"policies": map[string]any{
									"type": "array",
									"items": map[string]any{
										"$ref": "#/components/schemas/PolicyInformation",
									},
								},
								"policyDefinitions": map[string]any{
									"type": "array",
									"items": map[string]any{
										"$ref": "#/components/schemas/PolicyInformation",
									},
								},
								"subCaProvider": map[string]any{
									"$ref": "#/components/schemas/SubCaProviderInformation",
								},
							},
						},
					},
				},
			},
		},
	}, mergo.WithOverride)
	if err != nil {
		panic(fmt.Errorf("merging ExtendedConfigurationInformation fix: %w", err))
	}

	raw, err := json.Marshal(merged, jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err != nil {
		panic(fmt.Errorf("marshalling updated OpenAPI spec: %w", err))
	}

	// Rewrite all $ref paths to use local $defs instead of components.
	err = os.WriteFile("openapi.json", raw, 0644)
	if err != nil {
		panic(fmt.Errorf("writing to openapi.json file: %w", err))
	}
	logutil.Infof("./genschema/openapi.json updated.")
}

func createSchemaWithTemplate(templatePath string, defs map[string]any, onlyRefs []string, outputPath string) error {
	keep := make(map[string]struct{})
	collectRefs(defs, keep, onlyRefs...)

	var str []string
	for k := range keep {
		str = append(str, k)
	}

	logutil.Infof("reachable schemas: %s", strings.Join(str, ", "))

	// drop everything else
	remaining := make(map[string]any)
	for k := range keep {
		remaining[k] = defs[k]
	}

	schema, err := readSchema(templatePath)
	if err != nil {
		panic(fmt.Errorf("reading template from '%s': %w", templatePath, err))
	}

	// Replace or add the $defs block with filtered upstream definitions.
	if existing, ok := schema["$defs"].(map[string]any); ok {
		for k, v := range remaining {
			existing[k] = v
		}
	} else {
		schema["$defs"] = remaining
	}

	// Remove the cyclic references to ClientAuthenticationInformation. See:
	// https://github.com/oasdiff/oasdiff/issues/442 and
	// https://venafi.atlassian.net/browse/VC-42247. Note that it's a bug in the
	// Go implementation of the openapi parser rather than a fault in the
	// OpenAPI spec itself.
	removeAllOfFirst(schema, "JwtJwksAuthenticationInformation")
	removeAllOfFirst(schema, "JwtOidcAuthenticationInformation")
	removeAllOfFirst(schema, "JwtStandardClaimsAuthenticationInformation")

	// Since we are hiding the `allowedPolicyIds` field in 'get', 'put', and
	// 'edit' commands, we also need to remove it from the `required` list in
	// the schema so that it doesn't cause validation errors.
	removeFromRequired(schema, "allowedPolicyIds")

	// Re-encode as JSON and rewrite all $ref paths to use local $defs instead
	// of components.
	raw, err := json.Marshal(schema, jsontext.Multiline(true), jsontext.WithIndent("  "))
	if err != nil {
		panic(fmt.Errorf("marshalling updated schema: %w", err))
	}
	updated := bytes.ReplaceAll(raw, []byte("#/components/schemas/"), []byte("#/$defs/"))

	if err := os.WriteFile(outputPath, updated, 0644); err != nil {
		panic(fmt.Errorf("writing to %s file: %w", outputPath, err))
	}

	fmt.Printf("%v updated.\n", outputPath)
	return nil
}

// removeAllOfFirst deletes the first element of the `allOf` array from a given
// $defs type. Used to work around the cyclic reference found in
// JwtJwksAuthenticationInformation and JwtOidcAuthenticationInformation and
// JwtStandardClaimsAuthenticationInformation.
func removeAllOfFirst(schema map[string]any, defName string) {
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		return
	}
	target, ok := defs[defName].(map[string]any)
	if !ok {
		return
	}
	allOf, ok := target["allOf"].([]any)
	if !ok || len(allOf) < 1 {
		return
	}
	target["allOf"] = allOf[1:]
}

// readSchema loads and unmarshals the local JSON Schema from a file path.
func readSchema(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, err
	}
	return schema, nil
}

func mergeDefs(defs1, defs2, defs3 map[string]any) map[string]any {
	merged := make(map[string]any)
	maps.Copy(merged, defs1)
	maps.Copy(merged, defs2)
	maps.Copy(merged, defs3)

	return merged
}

// Fetches and parses the OpenAPI schema from the given URL.
func fetchSchema(url string) (map[string]any, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http fetch: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]any
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return result, nil
}

// Recursively finds all $ref dependencies from a root schema. A schema name is,
// for example, "MySchema" in the reference "#/components/schemas/MySchema". The
// `schemas` value must be the value of the key "schemas" in the OpenAPI spec.
//
// The `seen` map is the output of the function.
func collectRefs(schemas map[string]any, seen map[string]struct{}, names ...string) {
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		node, ok := schemas[name]
		if !ok {
			return
		}

		walk(node, func(ref string) {
			if target, isARef := strings.CutPrefix(ref, "#/components/schemas/"); isARef {
				collectRefs(schemas, seen, target)
			}
		})
	}

	// Check that all names were found.
	for _, name := range names {
		if _, ok := seen[name]; !ok {
			logutil.Errorf("warning: schema for %q not found", name)
		}
	}
}

func changeRef(node any, from, to string) error {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if ref, ok := v.(string); ok && ref == from {
					logutil.Infof("node %v: changing $ref from %q to %q", n, from, to)
					n[k] = to
				}
			} else {
				if err := changeRef(v, from, to); err != nil {
					return err
				}
			}
		}
	case map[string]string:
		for k, v := range n {
			if k == "$ref" && v == from {
				n[k] = to
			}
		}
	case []any:
		for _, item := range n {
			if err := changeRef(item, from, to); err != nil {
				return err
			}
		}
	case string, float64, bool, nil:
		// do nothing
	default:
		return fmt.Errorf("unexpected type %T in changeRef", n)
	}
	return nil
}

// walks arbitrary JSON for $ref strings
func walk(node any, visit func(string)) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if k == "$ref" {
				if ref, ok := v.(string); ok {
					visit(ref)
				}
			} else {
				walk(v, visit)
			}
		}
	case []any:
		for _, item := range n {
			walk(item, visit)
		}
	}
}

func removeFromRequired(schema any, fieldToRemove string) {
	switch v := schema.(type) {
	case map[string]any:
		// Check if this object has a "required" array.
		if required, ok := v["required"].([]any); ok {
			v["required"] = slices.DeleteFunc(required, func(req any) bool {
				reqStr, ok := req.(string)
				return ok && reqStr == fieldToRemove
			})
		}

		// Recursively process all nested objects
		for _, value := range v {
			removeFromRequired(value, fieldToRemove)
		}
	case []any:
		// Recursively process array elements
		for _, item := range v {
			removeFromRequired(item, fieldToRemove)
		}
	}
}
