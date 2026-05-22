package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/spf13/cobra"
)

func ctxCmd(groupID string) *cobra.Command {
	var contextName string
	var outputFormat string

	cmd := &cobra.Command{
		Use:           "ctx [field]",
		Short:         "Display current context information",
		Long:          "Display the current context or a specific field from the context.",
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		Example: `  # Show current context in YAML
  vcpctl ctx

  # Show current context in JSON
  vcpctl ctx -ojson

  # Show only the clientID field
  vcpctl ctx clientid

  # Show a specific context
  vcpctl ctx --context prod`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration
			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			// Resolve context
			var ctx ToolContext
			var ok bool
			if contextName != "" {
				ctx, ok = resolveContext(conf, contextName)
				if !ok {
					// List available contexts
					var names []string
					for _, c := range conf.ToolContexts {
						names = append(names, c.Name)
					}
					return fmt.Errorf("context '%s' not found. Available contexts:\n    %s", contextName, strings.Join(names, "\n    "))
				}
			} else {
				ctx, ok = currentFrom(conf)
				if !ok {
					return fmt.Errorf("not logged in. Log in with:\n    vcpctl login\n")
				}
			}

			// If field argument is provided, display only that field
			if len(args) > 0 {
				fieldName := strings.ToLower(args[0])

				// Map lowercase field names to actual struct field names
				fieldMap := map[string]string{
					"name":               "Name",
					"tenantid":           "TenantID",
					"apiurl":             "APIURL",
					"tenanturl":          "TenantURL",
					"username":           "Username",
					"authenticationtype": "AuthenticationType",
					"apikey":             "APIKey",
					"email":              "Email",
					"userid":             "UserID",
					"accesstoken":        "AccessToken",
					"privatekey":         "PrivateKey",
					"issuerurl":          "IssuerURL",
					"subject":            "Subject",
					"audience":           "Audience",
					"clientid":           "ClientID",
					"clientsecret":       "ClientSecret",
					"authurl":            "AuthURL",
				}

				actualFieldName, exists := fieldMap[fieldName]
				if !exists {
					// List available fields (non-empty) for this context
					var availableFields []string
					v := reflect.ValueOf(ctx)
					for lowercaseName, structFieldName := range fieldMap {
						field := v.FieldByName(structFieldName)
						if field.IsValid() && field.String() != "" {
							availableFields = append(availableFields, lowercaseName)
						}
					}
					sort.Strings(availableFields)
					return fmt.Errorf("field '%s' not found. Available fields for this context:\n    %s", args[0], strings.Join(availableFields, "\n    "))
				}

				// Use reflection to get field value
				v := reflect.ValueOf(ctx)
				field := v.FieldByName(actualFieldName)
				if !field.IsValid() {
					return fmt.Errorf("field '%s' not found in context", actualFieldName)
				}

				// Check if field is empty
				if field.String() == "" {
					// List available fields (non-empty) for this context
					var availableFields []string
					for lowercaseName, structFieldName := range fieldMap {
						f := v.FieldByName(structFieldName)
						if f.IsValid() && f.String() != "" {
							availableFields = append(availableFields, lowercaseName)
						}
					}
					sort.Strings(availableFields)
					return fmt.Errorf("field '%s' is empty. Available fields for this context:\n    %s", args[0], strings.Join(availableFields, "\n    "))
				}

				fmt.Println(field.String())
				return nil
			}

			// Validate output format
			outputFormat = strings.ToLower(outputFormat)
			if outputFormat != "yaml" && outputFormat != "json" {
				return fmt.Errorf("invalid output format '%s'. Valid formats: yaml, json", outputFormat)
			}

			// Display full context
			if outputFormat == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(ctx); err != nil {
					return fmt.Errorf("encoding context as JSON: %w", err)
				}
			} else {
				out, err := yaml.Marshal(ctx)
				if err != nil {
					return fmt.Errorf("encoding context as YAML: %w", err)
				}
				fmt.Print(string(out))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Context name to display")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "yaml", "Output format (yaml or json)")

	return cmd
}
