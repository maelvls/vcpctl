package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

// Parent command for conf operations
func confCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conf",
		Short: "Manage WIM (Workload Identity Manager) configurations",
		Long: undent.Undent(`
			Manage WIM (Workload Identity Manager, formerly Firefly) configurations in
			CyberArk Certificate Manager, SaaS.
		`),
	}
	cmd.AddCommand(confLsCmd())
	cmd.AddCommand(confGetCmd())
	cmd.AddCommand(confRmCmd())
	return cmd
}

// List Workload Identity Manager configurations.
func confLsCmd() *cobra.Command {
	var showSaIDs bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List WIM (Workload Identity Manager, formerly Firefly) configurations",
		Long: undent.Undent(`
			List WIM (Workload Identity Manager, formerly Firefly) configurations in
			CyberArk Certificate Manager, SaaS.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			confs, err := api.GetConfigs(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("while listing configurations: %w", err)
			}

			knownSvcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("fetching service accounts: %w", err)
			}

			saByID := make(map[string]api.ServiceAccountDetails)
			for _, sa := range knownSvcaccts {
				saByID[sa.Id.String()] = sa
			}

			// Build a map to store formatted service account names for each config
			configSANames := make(map[string][]string)

			for _, m := range confs {
				type resolvedEntry struct {
					name  string
					id    string
					found bool
				}
				var (
					entries    []resolvedEntry
					namesInCfg = make(map[string]int)
				)
				for _, saID := range m.ServiceAccountIds {
					sa, found := saByID[saID.String()]
					if found {
						entries = append(entries, resolvedEntry{name: sa.Name, id: sa.Id.String(), found: true})
						namesInCfg[sa.Name]++
						continue
					}
					entries = append(entries, resolvedEntry{id: saID.String(), found: false})
				}

				var saNames []string
				for _, entry := range entries {
					if !entry.found {
						saNames = append(saNames, entry.id+redBold(" (deleted)"))
						continue
					}

					needsID := showSaIDs || namesInCfg[entry.name] > 1
					if needsID {
						saNames = append(saNames, fmt.Sprintf("%s (%s)", entry.name, lightGray(entry.id)))
						continue
					}

					saNames = append(saNames, entry.name)
				}
				configSANames[m.Id.String()] = saNames
			}

			var rows [][]string
			for _, m := range confs {
				rows = append(rows, []string{
					m.Name,
					strings.Join(configSANames[m.Id.String()], ", "),
				})
			}

			printTable([]string{"WIM CONFIGURATION", "Attached Service Accounts"}, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showSaIDs, "show-sa-ids", false, "Show service account IDs even when names are unique")
	return cmd
}

func confGetCmd() *cobra.Command {
	var showDeps bool
	var raw bool
	cmd := &cobra.Command{
		Use:   "get <config-name>",
		Short: "Export a WIM configuration",
		Long: undent.Undent(`
			Get a WIM (Workload Identity Manager, formerly Firefly) configuration
			from CyberArk Certificate Manager, SaaS. By default, displays the
			configuration as a manifest.WIMConfiguration. Use --raw to display
			the raw API response. The configuration is written to stdout in YAML
			format.
		`),
		Example: undent.Undent(`
			vcpctl conf get <config-name>
			vcpctl conf get <config-name> --deps
			vcpctl conf get <config-name> --raw
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the WIM configuration name), got %s", args)
			}
			idOrName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			knownSvcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("while fetching service accounts: %w", err)
			}

			config, err := api.GetConfig(context.Background(), apiClient, idOrName)
			if err != nil {
				return fmt.Errorf("while getting original Workload Identity Manager configuration: %w", err)
			}

			issuingTemplates, err := api.GetIssuingTemplates(context.Background(), apiClient)

			var yamlData []byte
			if raw {
				// Display raw API response
				var buf bytes.Buffer
				enc := yaml.NewEncoder(&buf)
				err = enc.Encode(config)
				if err != nil {
					return fmt.Errorf("while encoding raw config to YAML: %w", err)
				}
				yamlData = buf.Bytes()
			} else if showDeps {
				// Show all dependencies (old behavior)
				yamlData, err = renderToYAML(saResolver(knownSvcaccts), issuingtemplateResolver(issuingTemplates), config)
				if err != nil {
					return err
				}
			} else {
				// Only show WIMConfiguration
				wimConfig, _, _, _, err := renderToManifests(saResolver(knownSvcaccts), issuingtemplateResolver(issuingTemplates), config)
				if err != nil {
					return fmt.Errorf("while rendering to manifests: %w", err)
				}

				configManifest := configurationManifest{
					Kind:             kindConfiguration,
					WIMConfiguration: wimConfig,
				}

				var buf bytes.Buffer
				enc := yaml.NewEncoder(&buf)
				err = enc.Encode(configManifest)
				if err != nil {
					return fmt.Errorf("while encoding WIMConfiguration to YAML: %w", err)
				}
				yamlData = buf.Bytes()
			}

			schemaFile, err := api.SaveSchemaToWellKnownPath()
			if err != nil {
				return fmt.Errorf("while saving schema.json to disk so that YAML can reference it: %w", err)
			}

			yamlData = appendSchemaComment(yamlData, schemaFile)

			coloredYAMLPrint(string(yamlData))

			return nil
		},
	}
	cmd.Flags().BoolVar(&showDeps, "deps", false, "Include dependencies (service accounts, policies, and Sub CA)")
	cmd.Flags().BoolVar(&raw, "raw", false, "Display raw API response instead of manifest format")
	return cmd
}

func confRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <config-name>",
		Short: "Remove a WIM configuration",
		Long: undent.Undent(`
			Remove a WIM (Workload Identity Manager, formerly Firefly)
			configuration. This deletes the configuration from CyberArk Certificate
			Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl conf rm my-config
			vcpctl conf rm 03931ba6-3fc5-11f0-85b8-9ee29ab248f0
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the WIM configuration name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			// Get the configuration by name or ID.
			c, err := api.GetConfig(context.Background(), apiClient, nameOrID)
			if err != nil {
				if errors.As(err, &errutil.NotFound{}) {
					return fmt.Errorf("Workload Identity Manager configuration '%s' not found", nameOrID)
				}
				return fmt.Errorf("while getting Workload Identity Manager configuration by name or ID '%s': %w", nameOrID, err)
			}
			// Remove the configuration.
			err = api.RemoveConfig(context.Background(), apiClient, c.Id.String())
			if err != nil {
				return fmt.Errorf("while removing Workload Identity Manager configuration '%s': %w", nameOrID, err)
			}
			logutil.Debugf("Workload Identity Manager configuration '%s' removed successfully.", nameOrID)
			return nil
		},
	}
	return cmd
}

// Deprecated commands for backward compatibility

func deprecatedLsCmd() *cobra.Command {
	var showSaIDs bool
	cmd := &cobra.Command{
		Use:           "ls",
		Short:         "List WIM configurations (deprecated: use 'vcpctl conf ls')",
		Hidden:        false,
		Deprecated:    "use 'vcpctl conf ls' instead",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return confLsCmd().RunE(cmd, args)
		},
	}
	cmd.Flags().BoolVar(&showSaIDs, "show-sa-ids", false, "Show service account IDs even when names are unique")
	return cmd
}

func deprecatedGetCmd() *cobra.Command {
	var showDeps bool
	cmd := &cobra.Command{
		Use:           "get <config-name>",
		Short:         "Export a WIM configuration (deprecated: use 'vcpctl conf get')",
		Hidden:        false,
		Deprecated:    "use 'vcpctl conf get' instead",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return confGetCmd().RunE(cmd, args)
		},
	}
	cmd.Flags().BoolVar(&showDeps, "deps", false, "Include dependencies (service accounts, policies, and Sub CA)")
	return cmd
}

func deprecatedRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rm <config-name>",
		Short:         "Remove a WIM configuration (deprecated: use 'vcpctl conf rm')",
		Hidden:        false,
		Deprecated:    "use 'vcpctl conf rm' instead",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return confRmCmd().RunE(cmd, args)
		},
	}
	return cmd
}
