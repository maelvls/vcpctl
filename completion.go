package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// contextCompletionFunc provides dynamic shell completion for --context and
// --from-context flags by listing all available context names from the config
// file (~/.config/vcpctl.yaml).
//
// This function is registered via RegisterFlagCompletionFunc in the commands
// that accept --context or --from-context flags.
//
// If the config file cannot be loaded (e.g., doesn't exist or is malformed),
// the function returns an empty list of completions instead of erroring out,
// allowing the shell completion to continue gracefully.
func contextCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Load the configuration file
	conf, err := loadFileConf(context.Background())
	if err != nil {
		// If we can't load the config, return no completions
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	// Extract context names
	var contextNames []string
	for _, ctx := range conf.ToolContexts {
		contextNames = append(contextNames, ctx.Name)
	}

	return contextNames, cobra.ShellCompDirectiveNoFileComp
}

// apiPathCompletionFunc provides dynamic shell completion for the path argument
// of the "vcpctl api" command by listing all available API endpoints from the
// embedded OpenAPI schema.
//
// This function is registered via ValidArgsFunction in the api command.
//
// If the OpenAPI schema cannot be parsed, the function returns an empty list
// of completions instead of erroring out.
func apiPathCompletionFunc(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Only complete the first positional argument (the path)
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var schema struct {
		Paths map[string]map[string]any `json:"paths"`
	}

	if err := json.Unmarshal(openapiSchema, &schema); err != nil {
		// If we can't parse the schema, return no completions
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	// Collect all endpoint paths
	var paths []string
	for path := range schema.Paths {
		paths = append(paths, path)
	}

	// Sort paths for consistent ordering
	sort.Strings(paths)

	// Add descriptions for each path showing supported methods
	var completions []string
	for _, path := range paths {
		methods := schema.Paths[path]
		var methodList []string
		for method := range methods {
			// Filter out non-HTTP methods
			switch strings.ToUpper(method) {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
				methodList = append(methodList, strings.ToUpper(method))
			}
		}
		sort.Strings(methodList)

		// Format: "/v1/path\tGET,POST,DELETE"
		completion := path + "\t" + strings.Join(methodList, ",")
		completions = append(completions, completion)
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}
