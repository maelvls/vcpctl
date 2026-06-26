package main

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	api "github.com/maelvls/vcpctl/api"
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
//
// For NGTS/TSG authentication, the paths are prefixed with /ngts.
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

	// Check if we're using NGTS (TSG) authentication to prepend /ngts
	var pathPrefix string
	conf, err := getToolConfig(cmd)
	if err == nil && conf.AuthenticationType == "tsg" {
		pathPrefix = "/ngts"
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

		// Prepend /ngts for NGTS/TSG contexts
		completePath := pathPrefix + path

		// Format: "/v1/path\tGET,POST,DELETE" or "/ngts/v1/path\tGET,POST,DELETE"
		completion := completePath + "\t" + strings.Join(methodList, ",")
		completions = append(completions, completion)
	}

	return completions, cobra.ShellCompDirectiveNoFileComp
}

// completeSubCAName provides dynamic shell completion for SubCA provider names.
// Used by subca get, rm, and edit commands.
// Shows names with UUIDs as descriptions.
func completeSubCAName(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Only complete the first positional argument
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	conf, err := getToolConfig(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	apiClient, err := newAPIClient(conf)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	providers, err := api.GetSubCAProviders(cmd.Context(), apiClient)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	// First, collect matching providers and detect duplicates
	type providerMatch struct {
		provider api.SubCaProviderInformation
		byName   bool
		byUUID   bool
	}
	var matches []providerMatch
	nameCount := make(map[string]int)

	// Check if input looks like a UUID
	looksLikeUUID := len(toComplete) > 0 && (strings.Contains(toComplete, "-") || len(toComplete) >= 8)

	for _, provider := range providers {
		match := providerMatch{provider: provider}
		if strings.HasPrefix(provider.Name, toComplete) {
			match.byName = true
			nameCount[provider.Name]++
		}
		if looksLikeUUID && strings.HasPrefix(provider.Id.String(), toComplete) {
			match.byUUID = true
		}

		if match.byName || match.byUUID {
			matches = append(matches, match)
		}
	}

	// Build completions based on matches and duplicates
	var suggestions []string
	for _, m := range matches {
		if m.byUUID {
			// User is typing a UUID, show UUID with name as description
			suggestions = append(suggestions, m.provider.Id.String()+"\t"+m.provider.Name)
		} else if m.byName {
			if nameCount[m.provider.Name] > 1 {
				// Duplicate name: show UUID with name as description
				suggestions = append(suggestions, m.provider.Id.String()+"\t"+m.provider.Name)
			} else {
				// Unique name: show name with UUID as description
				suggestions = append(suggestions, m.provider.Name+"\t"+m.provider.Id.String())
			}
		}
	}

	return suggestions, cobra.ShellCompDirectiveNoFileComp
}

// completePolicyName provides dynamic shell completion for policy names.
// Used by policy get, rm, and edit commands.
// Shows names with UUIDs as descriptions.
func completePolicyName(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Only complete the first positional argument
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	conf, err := getToolConfig(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	apiClient, err := newAPIClient(conf)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	policies, err := api.GetPolicies(cmd.Context(), apiClient)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	// First, collect matching policies and detect duplicates
	type policyMatch struct {
		policy api.ExtendedPolicyInformation
		byName bool
		byUUID bool
	}
	var matches []policyMatch
	nameCount := make(map[string]int)

	// Check if input looks like a UUID
	looksLikeUUID := len(toComplete) > 0 && (strings.Contains(toComplete, "-") || len(toComplete) >= 8)

	for _, policy := range policies {
		match := policyMatch{policy: policy}
		if strings.HasPrefix(policy.Name, toComplete) {
			match.byName = true
			nameCount[policy.Name]++
		}
		if looksLikeUUID && strings.HasPrefix(policy.Id.String(), toComplete) {
			match.byUUID = true
		}

		if match.byName || match.byUUID {
			matches = append(matches, match)
		}
	}

	// Build completions based on matches and duplicates
	var suggestions []string
	for _, m := range matches {
		if m.byUUID {
			// User is typing a UUID, show UUID with name as description
			suggestions = append(suggestions, m.policy.Id.String()+"\t"+m.policy.Name)
		} else if m.byName {
			if nameCount[m.policy.Name] > 1 {
				// Duplicate name: show UUID with name as description
				suggestions = append(suggestions, m.policy.Id.String()+"\t"+m.policy.Name)
			} else {
				// Unique name: show name with UUID as description
				suggestions = append(suggestions, m.policy.Name+"\t"+m.policy.Id.String())
			}
		}
	}

	return suggestions, cobra.ShellCompDirectiveNoFileComp
}

// completeSANameForFlag provides dynamic shell completion for service account names
// used as flag values (e.g., --sa flag).
// Shows names with UUIDs as descriptions.
func completeSANameForFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	conf, err := getToolConfig(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	apiClient, err := newAPIClient(conf)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	svcaccts, err := api.GetServiceAccounts(cmd.Context(), apiClient)
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}

	// First, collect matching service accounts and detect duplicates
	type saMatch struct {
		sa     api.ServiceAccountDetails
		byName bool
		byUUID bool
	}
	var matches []saMatch
	nameCount := make(map[string]int)

	// Check if input looks like a UUID
	looksLikeUUID := len(toComplete) > 0 && (strings.Contains(toComplete, "-") || len(toComplete) >= 8)

	for _, sa := range svcaccts {
		match := saMatch{sa: sa}
		if strings.HasPrefix(sa.Name, toComplete) {
			match.byName = true
			nameCount[sa.Name]++
		}
		if looksLikeUUID && strings.HasPrefix(sa.Id.String(), toComplete) {
			match.byUUID = true
		}

		if match.byName || match.byUUID {
			matches = append(matches, match)
		}
	}

	// Build completions based on matches and duplicates
	var suggestions []string
	for _, m := range matches {
		if m.byUUID {
			// User is typing a UUID, show UUID with name as description
			suggestions = append(suggestions, m.sa.Id.String()+"\t"+m.sa.Name)
		} else if m.byName {
			if nameCount[m.sa.Name] > 1 {
				// Duplicate name: show UUID with name as description
				suggestions = append(suggestions, m.sa.Id.String()+"\t"+m.sa.Name)
			} else {
				// Unique name: show name with UUID as description
				suggestions = append(suggestions, m.sa.Name+"\t"+m.sa.Id.String())
			}
		}
	}

	return suggestions, cobra.ShellCompDirectiveNoFileComp
}
