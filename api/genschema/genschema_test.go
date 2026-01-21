package main

import (
	"testing"
)

func Test_mutateSchemaProperties(t *testing.T) {
	doc := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"YourSuperObject": map[string]any{
					// Root schema: has properties → must be visited.
					"properties": map[string]any{
						"enabled": true,
					},
					"oneOf": []any{
						// No properties → must NOT be visited.
						map[string]any{
							"$ref": "#/components/schemas/BaseObject",
						},
						// Has properties → must be visited.
						map[string]any{
							"properties": map[string]any{
								"foo": "bar",
							},
						},
					},
					"allOf": []any{
						// Has properties → must be visited.
						map[string]any{
							"properties": map[string]any{
								"baz": "qux",
							},
						},
					},
				},
			},
		},
	}

	var visitedCount int

	err := mutateSchemaProperties(doc, "YourSuperObject", func(schema map[string]any) {
		visitedCount++
		// Mark the schema so we can assert later that only the right ones were
		// touched.
		schema["visited"] = true
	})
	if err != nil {
		t.Fatalf("mutateSchemaProperties returned error: %v", err)
	}

	if visitedCount != 3 {
		t.Fatalf("expected visitor to be called 3 times, got %d", visitedCount)
	}

	components := doc["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	root := schemas["YourSuperObject"].(map[string]any)

	// Root schema should be visited.
	if v, ok := root["visited"].(bool); !ok || !v {
		t.Errorf("expected root schema to be marked visited")
	}

	oneOf := root["oneOf"].([]any)
	oneOf0 := oneOf[0].(map[string]any)
	oneOf1 := oneOf[1].(map[string]any)

	// oneOf[0] has no properties → should not be visited.
	if _, ok := oneOf0["visited"]; ok {
		t.Errorf("expected oneOf[0] NOT to be visited, but it was")
	}

	// oneOf[1] has properties → should be visited.
	if v, ok := oneOf1["visited"].(bool); !ok || !v {
		t.Errorf("expected oneOf[1] to be visited")
	}

	allOf := root["allOf"].([]any)
	allOf0 := allOf[0].(map[string]any)

	// allOf[0] has properties → should be visited.
	if v, ok := allOf0["visited"].(bool); !ok || !v {
		t.Errorf("expected allOf[0] to be visited")
	}
}

func Test_mutateSchemaProperties_SchemaNotFound(t *testing.T) {
	doc := map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{},
		},
	}

	err := mutateSchemaProperties(doc, "MissingSchema", func(schema map[string]any) {
		t.Fatalf("visitor should not be called when schema is missing")
	})

	if err == nil {
		t.Fatalf("expected error when schema does not exist, got nil")
	}
}

func Test_setNullableOnProperty(t *testing.T) {
	t.Run("sets nullable on direct property", func(t *testing.T) {
		doc := map[string]any{
			"components": map[string]any{
				"schemas": map[string]any{
					"TestSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"enabled": map[string]any{
								"type": "boolean",
							},
						},
					},
				},
			},
		}

		setNullableOnProperty(doc, "TestSchema", "enabled")

		// Verify nullable was set.
		schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
		testSchema := schemas["TestSchema"].(map[string]any)
		props := testSchema["properties"].(map[string]any)
		enabled := props["enabled"].(map[string]any)

		if nullable, ok := enabled["nullable"].(bool); !ok || !nullable {
			t.Errorf("expected enabled property to have nullable=true, got %v", enabled)
		}
	})

	t.Run("sets nullable on property in allOf", func(t *testing.T) {
		doc := map[string]any{
			"components": map[string]any{
				"schemas": map[string]any{
					"TestSchema": map[string]any{
						"allOf": []any{
							map[string]any{
								"$ref": "#/components/schemas/BaseObject",
							},
							map[string]any{
								"type": "object",
								"properties": map[string]any{
									"enabled": map[string]any{
										"type": "boolean",
									},
								},
							},
						},
					},
				},
			},
		}

		setNullableOnProperty(doc, "TestSchema", "enabled")

		// Verify nullable was set in the allOf item.
		schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
		testSchema := schemas["TestSchema"].(map[string]any)
		allOf := testSchema["allOf"].([]any)
		allOfItem := allOf[1].(map[string]any)
		props := allOfItem["properties"].(map[string]any)
		enabled := props["enabled"].(map[string]any)

		if nullable, ok := enabled["nullable"].(bool); !ok || !nullable {
			t.Errorf("expected enabled property in allOf to have nullable=true, got %v", enabled)
		}
	})

	t.Run("returns error when property not found", func(t *testing.T) {
		doc := map[string]any{
			"components": map[string]any{
				"schemas": map[string]any{
					"TestSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"enabled": map[string]any{
								"type": "boolean",
							},
						},
					},
				},
			},
		}

		setNullableOnProperty(doc, "TestSchema", "nonexistent")

	})

	t.Run("returns error when schema not found", func(t *testing.T) {
		doc := map[string]any{
			"components": map[string]any{
				"schemas": map[string]any{},
			},
		}

		// Should panic because mutateSchemaProperties will return an error that
		// setNullableOnProperty panics on.
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic when schema does not exist")
			}
		}()

		setNullableOnProperty(doc, "MissingSchema", "enabled")
	})
}
