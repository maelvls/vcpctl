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

	// First, we need to fetch the HTML page to fetch the latest OpenAPI spec.
	// The HTML contains somthing like this:
	//  <div class="item"><a href="/tlsprotectcloud/openapi/691235c38218c38bed9afb9b" class="link">Certificate Manager - SaaS API - v1.0</a></div>
	unifiedOpenAPIRootURL = "https://developer.venafi.com/tlsprotectcloud/openapi/"
)

// Usage:ServiceAccountDetails
//
//	go run ./genschema
func main() {
	if len(os.Args) != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: genschema\n")
		os.Exit(1)
	}

	// Step 0: Fetch the HTML from the root OpenAPI URL to find the latest
	// OpenAPI spec URL.
	body, err := http.Get(unifiedOpenAPIRootURL)
	if err != nil {
		panic(err)
	}
	defer body.Body.Close()
	data, err := io.ReadAll(body.Body)
	if err != nil {
		panic(err)
	}

	html := string(data)
	prefix := `href="/tlsprotectcloud/openapi/`
	suffix := `"`
	start := strings.Index(html, prefix)
	if start == -1 {
		panic("could not find '" + prefix + "' in HTML: " + html)
	}
	start += len(prefix)
	end := strings.Index(html[start:], suffix)
	if end == -1 {
		panic("could not find '" + suffix + "' after '" + prefix + "' in HTML: " + html)
	}
	unifiedOpenAPIURL := "https://developer.venafi.com/tlsprotectcloud/openapi/" + html[start:start+end]
	logutil.Infof("latest unified OpenAPI URL: %s", unifiedOpenAPIURL)

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

	// Fix a few bugs in the ClientAuthenticationInformation schema:
	//
	//  - as explained in [1], the parent discriminated object should not
	//    contain the discriminating field (here, 'type'); the 'type' field should
	//    be defined in the individual items instead.
	//  - the 'mapping' field under the 'discriminator' field is missing.
	//
	// [1]: https://swagger.io/docs/specification/v3_0/data-models/inheritance-and-polymorphism/
	//
	// See: https://venafi.atlassian.net/browse/VC-45818
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any)["ClientAuthenticationInformation"].(map[string]any), "properties")
	delete(merged["components"].(map[string]any)["schemas"].(map[string]any)["ClientAuthenticationInformation"].(map[string]any), "required")
	err = mergo.Merge(&merged, map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"ClientAuthenticationInformation": map[string]any{
					"discriminator": map[string]any{
						"mapping": map[string]string{
							"JWT_JWKS":            "#/components/schemas/JwtJwksAuthenticationInformation",
							"JWT_OIDC":            "#/components/schemas/JwtOidcAuthenticationInformation",
							"JWT_STANDARD_CLAIMS": "#/components/schemas/JwtStandardClaimsAuthenticationInformation",
						},
					},
				},
				"JwtStandardClaimsAuthenticationInformation": map[string]any{
					"allOf": []any{map[string]any{
						"type": "object",
						"properties": map[string]any{
							"type": map[string]any{
								"type": "string",
							},
						},
					}},
					"required": []any{"type"},
				},
				"JwtJwksAuthenticationInformation": map[string]any{
					"allOf": []any{map[string]any{
						"type": "object",
						"properties": map[string]any{
							"type": map[string]any{
								"type": "string",
							},
						},
					}},
					"required": []any{"type"},
				},
				"JwtOidcAuthenticationInformation": map[string]any{
					"allOf": []any{map[string]any{
						"type": "object",
						"properties": map[string]any{
							"type": map[string]any{
								"type": "string",
							},
						},
					}},
					"required": []any{"type"},
				},
			},
		},
	}, mergo.WithOverride, mergo.WithAppendSlice)
	if err != nil {
		panic(fmt.Errorf("merging discriminator fix: %w", err))
	}

	// Some fields' zero values are meaningful; when PATCHing, we want to be
	// able to set them to the zero value without it being omitted.
	setNullableOnProperty(merged, "PatchServiceAccountByClientIDRequestBody", "enabled")

	// GET and PATCH share the same AdvancedSettingsInformation schema...
	// 'nullable' should realistically only be applied to the PATCH schema, but
	// since both use the same schema, we apply it to both.
	copySchema(merged, "AdvancedSettingsInformation", "PatchAdvancedSettingsInformation")
	set(merged, "components.schemas.ConfigurationUpdateRequest.properties.advancedSettings.$ref", "#/components/schemas/PatchAdvancedSettingsInformation")
	setNullableOnProperty(merged, "PatchAdvancedSettingsInformation", "enableIssuanceAuditLog")
	setNullableOnProperty(merged, "PatchAdvancedSettingsInformation", "includeRawCertDataInAuditLog")
	setNullableOnProperty(merged, "PatchAdvancedSettingsInformation", "requireFIPSCompliantBuild")

	// Same story for SubCaProviderPkcs11ConfigurationInformation.
	copySchema(merged, "SubCaProviderPkcs11ConfigurationInformation", "PatchSubCaProviderPkcs11ConfigurationInformation")
	set(merged, "components.schemas.SubCaProviderUpdateRequest.properties.pkcs11.$ref", "#/components/schemas/PatchSubCaProviderPkcs11ConfigurationInformation")
	setNullableOnProperty(merged, "PatchSubCaProviderPkcs11ConfigurationInformation", "signingEnabled")

	// For some reason, the 'ClientAuthenticationInformationRequestOpenApi' is a
	// duplicate of 'ClientAuthenticationInformation'. We just replace all
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

func mustChangeRef(node any, from, to string) {
	if err := changeRef(node, from, to); err != nil {
		panic(err)
	}
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

// For example, if I have the following object (this is the JSON representation,
// but what the func accepts is a map[string]any):
//
//  {
//   "components": {
//     "schemas": {
//       "YourSuperObject": {
//          "allOf": [
//            {"$ref": "#/components/schemas/BaseObject"},
//            {
//              "properties": {
//                "enabled": {
//                  "type": "boolean",
//                  "nullable": true                       <----- adds this
//                }
//              },
//              "type": "object"
//            }
//          ],
//       }
//     }
//   }
//
// And if I give:
//
//  setNullableOnProperty("YourSuperObject", "enabled")
//
// Then the property "enabled" should now have "nullable": true.
//
// This func should also work for "allOf" as well as properties directly under
// the schema, for example:
//
//  {
//   "components": {
//     "schemas": {
//       "YourSuperObject": {
//         "properties": {
//           "enabled": {
//             "type": "boolean",
//             "nullable": true                            <----- adds this
//           }
//         },
//         "type": "object"
//       }
//     }
//   }

// setNullableOnProperty finds the schema `schemaName` under components.schemas
// and sets nullable: true on the property `propName`.
//
// It works both when the property is directly under "properties" and when it is
// nested inside an "allOf" item of that schema.
func setNullableOnProperty(doc map[string]any, schemaName, propName string) error {
	componentsRaw, ok := doc["components"]
	if !ok {
		return fmt.Errorf(`no "components" key in document`)
	}
	components, ok := componentsRaw.(map[string]any)
	if !ok {
		return fmt.Errorf(`"components" is not an object`)
	}

	schemasRaw, ok := components["schemas"]
	if !ok {
		return fmt.Errorf(`no "schemas" under "components"`)
	}
	schemas, ok := schemasRaw.(map[string]any)
	if !ok {
		return fmt.Errorf(`"components.schemas" is not an object`)
	}

	schemaRaw, ok := schemas[schemaName]
	if !ok {
		return fmt.Errorf(`schema %q not found under components.schemas`, schemaName)
	}
	schema, ok := schemaRaw.(map[string]any)
	if !ok {
		return fmt.Errorf(`schema %q is not an object`, schemaName)
	}

	if !setNullableOnPropertyInSchema(schema, propName) {
		return fmt.Errorf(`property %q not found (directly or in allOf) in schema %q`, propName, schemaName)
	}

	return nil
}

// setNullableOnPropertyInSchema mutates the given schema map in place and
// returns true if it found and updated the property.
//
// It looks for:
//   - schema.properties[propName]
//   - any item in schema.allOf that is an object and has that property
func setNullableOnPropertyInSchema(schema map[string]any, propName string) bool {
	// 1. Look for the property directly under "properties"
	if propsRaw, ok := schema["properties"]; ok {
		if props, ok := propsRaw.(map[string]any); ok {
			if propRaw, ok := props[propName]; ok {
				if propSchema, ok := propRaw.(map[string]any); ok {
					propSchema["nullable"] = true
					// map mutation is in-place, but assigning back is harmless
					props[propName] = propSchema
					schema["properties"] = props
					return true
				}
			}
		}
	}

	// 2. Look into "allOf" items
	if allOfRaw, ok := schema["allOf"]; ok {
		if allOfSlice, ok := allOfRaw.([]any); ok {
			changed := false
			for i, item := range allOfSlice {
				itemSchema, ok := item.(map[string]any)
				if !ok {
					// could be {"$ref": ...} or something else; skip
					continue
				}
				if setNullableOnPropertyInSchema(itemSchema, propName) {
					// store back the modified item
					allOfSlice[i] = itemSchema
					changed = true
				}
			}
			if changed {
				schema["allOf"] = allOfSlice
				return true
			}
		}
	}

	return false
}

// It should deep-copy. Otherwise, if I edit one schema, it would affect the
// other one as well.
func copySchema(schema map[string]any, existing string, to string) {
	defs, ok := schema["components"].(map[string]any)["schemas"].(map[string]any)
	if !ok {
		panic("no components.schemas in schema")
	}
	source, ok := defs[existing]
	if !ok {
		panic(fmt.Sprintf("no such schema %q in components.schemas", existing))
	}

	// Deep copy the map.
	data, err := json.Marshal(source)
	if err != nil {
		panic(fmt.Sprintf("marshalling schema %q: %v", existing, err))
	}
	var dest any
	if err := json.Unmarshal(data, &dest); err != nil {
		panic(fmt.Sprintf("unmarshalling schema %q: %v", existing, err))
	}

	defs[to] = dest
}

// Sets a value in a nested map given a dot-separated path. Example:
//
//	set(schema, "components.schemas.MySuperObject.properties.type", "string")
// func set(schema map[string]any, path string, value any) {
// 	parts := strings.Split(path, ".")
// 	current := schema
// 	for i, part := range parts {
// 		if i == len(parts)-1 {
// 			// last part
// 			current[part] = value
// 			return
// 		}
// 		nextRaw, ok := current[part]
// 		if !ok {
// 			next := make(map[string]any)
// 			current[part] = next
// 			current = next
// 		}
// 		if nextRaw == nil {
// 			panic(fmt.Sprintf("segment '%v' in path %v doesn't exist in the given schema", part, path))
// 		}
// 		next, ok := nextRaw.(map[string]any)
// 		if !ok {
// 			panic(fmt.Sprintf("cannot set path %v: %v is not an object; it's a %T", path, part, nextRaw))
// 		}
// 		current = next
// 	}
// }

func set(schema map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := schema
	for i, part := range parts {
		if i == len(parts)-1 {
			// last part
			logutil.Infof("setting %v to %v in %+v", path, value, current)
			current[part] = value
			return
		}
		nextRaw, ok := current[part]
		if !ok {
			next := make(map[string]any)
			current[part] = next
			current = next
		} else {
			next, ok := nextRaw.(map[string]any)
			if !ok {
				panic(fmt.Sprintf("cannot set path %v: %v is not an object; it's a %T", path, part, nextRaw))
			}
			current = next
		}
	}
}
