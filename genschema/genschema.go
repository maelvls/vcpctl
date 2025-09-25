package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"

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
//	 go run ./genschema schema.tmpl.json schema.json
//		                <---input----->  <--output-->
func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: genschema template.json output.json\n")
		os.Exit(1)
	}
	templateFile := os.Args[1]
	outputFile := os.Args[2]

	root0, err := fetchSchema(unifiedOpenAPIURL)
	if err != nil {
		panic(err)
	}

	// Fetch and filter only relevant schema definitions from the upstream
	// OpenAPI spec.
	root1, err := fetchSchema(vcamanagementOpenAPIURL)
	if err != nil {
		panic(err)
	}

	root2, err := fetchSchema(accountOpenAPIURL)
	if err != nil {
		panic(err)
	}

	// Merge the "schemas" blocks from all three specs.
	schemas := mergeDefs(
		root0["components"].(map[string]any)["schemas"].(map[string]any),
		root1["components"].(map[string]any)["schemas"].(map[string]any),
		root2["components"].(map[string]any)["schemas"].(map[string]any),
	)

	keep := make(map[string]struct{})
	collectRefs(schemas, keep, "ExtendedConfigurationInformation", "ServiceAccountBaseObject")

	var str []string
	for k := range keep {
		str = append(str, k)
	}

	logutil.Infof("reachable schemas: %s", strings.Join(str, ", "))

	// drop everything else
	remaining := make(map[string]any)
	for k := range keep {
		remaining[k] = schemas[k]
	}

	schema, err := readSchema(templateFile)
	if err != nil {
		panic(fmt.Errorf("reading template from '%s': %w", templateFile, err))
	}

	// Replace or add the $defs block with filtered upstream definitions.
	schema["$defs"] = remaining

	// Remove the cyclic references to ClientAuthenticationInformation. See:
	// https://github.com/oasdiff/oasdiff/issues/442 and
	// https://venafi.atlassian.net/browse/VC-42247. Note that it's a bug in the
	// Go implementation of the openapi parser rather than a fault in the
	// OpenAPI spec itself.
	removeAllOfFirst(schema, "JwtJwksAuthenticationInformation")
	removeAllOfFirst(schema, "JwtOidcAuthenticationInformation")
	removeAllOfFirst(schema, "JwtStandardClaimsAuthenticationInformation")

	// Re-encode as JSON and rewrite all $ref paths to use local $defs instead
	// of components.
	raw, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		panic(fmt.Errorf("marshalling updated schema: %w", err))
	}
	updated := bytes.ReplaceAll(raw, []byte("#/components/schemas/"), []byte("#/$defs/"))

	if err := os.WriteFile(outputFile, updated, 0644); err != nil {
		panic(fmt.Errorf("writing to %s file: %w", outputFile, err))
	}

	fmt.Println("schema.json updated.")
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
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
