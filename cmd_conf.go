package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

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
				return fmt.Errorf("ls: %w", err)
			}

			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			confs, err := api.GetConfigs(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("ls: while listing configurations: %w", err)
			}

			knownSvcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("ls: fetching service accounts: %w", err)
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
	return &cobra.Command{
		Use:   "get",
		Short: "Export a WIM configuration",
		Long: undent.Undent(`
			Get a WIM (Workload Identity Manager, formerly Firefly) configuration
			from CyberArk Certificate Manager, SaaS. The configuration is written
			to stdout in YAML format.
		`),
		Example: undent.Undent(`
			vcpctl get <config-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("get: expected a single argument (the WIM configuration name), got %s", args)
			}
			idOrName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("get: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("get: while creating API client: %w", err)
			}

			knownSvcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("get: while fetching service accounts: %w", err)
			}

			config, err := api.GetConfig(context.Background(), apiClient, idOrName)
			if err != nil {
				return fmt.Errorf("get: while getting original Workload Identity Manager configuration: %w", err)
			}

			issuingTemplates, err := api.GetIssuingTemplates(context.Background(), apiClient)

			yamlData, err := renderToYAML(saResolver(knownSvcaccts), issuingtemplateResolver(issuingTemplates), config)
			if err != nil {
				return err
			}

			schemaFile, err := api.SaveSchemaToWellKnownPath()
			if err != nil {
				return fmt.Errorf("get: while saving schema.json to disk so that YAML can reference it: %w", err)
			}

			yamlData = appendSchemaComment(yamlData, schemaFile)

			coloredYAMLPrint(string(yamlData))

			return nil
		},
	}
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
			vcpctl rm my-config
			vcpctl rm 03931ba6-3fc5-11f0-85b8-9ee29ab248f0
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the WIM configuration name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("rm: while creating API client: %w", err)
			}
			// Get the configuration by name or ID.
			c, err := api.GetConfig(context.Background(), apiClient, nameOrID)
			if err != nil {
				if errors.As(err, &errutil.NotFound{}) {
					return fmt.Errorf("rm: Workload Identity Manager configuration '%s' not found", nameOrID)
				}
				return fmt.Errorf("rm: while getting Workload Identity Manager configuration by name or ID '%s': %w", nameOrID, err)
			}
			// Remove the configuration.
			err = api.RemoveConfig(context.Background(), apiClient, c.Id.String())
			if err != nil {
				return fmt.Errorf("rm: while removing Workload Identity Manager configuration '%s': %w", nameOrID, err)
			}
			logutil.Debugf("Workload Identity Manager configuration '%s' removed successfully.", nameOrID)
			return nil
		},
	}
	return cmd
}
