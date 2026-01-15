package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/spf13/cobra"
)

// List Workload Identity Manager configurations.
func lsCmd() *cobra.Command {
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
