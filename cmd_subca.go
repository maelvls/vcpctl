package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	"github.com/spf13/cobra"
)

func subcaSubcmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subca",
		Short: "Manage SubCA Providers",
		Long: undent.Undent(`
			Manage SubCA Providers. SubCA Providers issue certificates from a SubCA.
			You can list, create, delete, and set a SubCA Provider for a WIM
			(Workload Identity Manager, formerly Firefly) configuration.

			Example:
			  vcpctl subca ls
			  vcpctl subca get <subca-name>
			  vcpctl subca rm <subca-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
	}
	cmd.AddCommand(
		subcaLsCmd(),
		subcaGetCmd(),
		subcaEditCmd(),
		subcaRmCmd(),
	)
	return cmd
}

func subcaLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List SubCA Providers",
		Long: undent.Undent(`
			List SubCA Providers. SubCA Providers are used to issue certificates
			from a SubCA.
		`),
		Example: undent.Undent(`
			vcpctl subca ls
			vcpctl subca get <subca-name>
			vcpctl subca rm <subca-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			providers, err := api.GetSubCAProviders(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("while listing subCA providers: %w", err)
			}

			var rows [][]string
			for _, provider := range providers {
				rows = append(rows, []string{
					provider.Id.String(),
					uniqueColor(string(provider.CaType)),
					provider.Name,
				})
			}
			printTable([]string{"ID", "Type", "Sub CA Name"}, rows)
			return nil
		},
	}
	return cmd
}

func subcaGetCmd() *cobra.Command {
	var format string
	var raw bool
	cmd := &cobra.Command{
		Use:   "get <subca-name-or-id>",
		Short: "Get a SubCA Provider",
		Long: undent.Undent(`
			Get a SubCA Provider's details. By default, displays the SubCA Provider
			as a manifest.WIMSubCAProvider. Use --raw to display the raw API response.
		`),
		Example: undent.Undent(`
			vcpctl subca get <subca-name>
			vcpctl subca get <subca-name> --raw
			vcpctl subca get <subca-name> -o json
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the SubCA Provider name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			subca, err := api.GetSubCAProvider(cmd.Context(), apiClient, nameOrID)
			if err != nil {
				return fmt.Errorf("while getting SubCA Provider: %w", err)
			}

			var outputData interface{}
			if raw {
				outputData = subca
			} else {
				// Need to resolve issuing templates like in conf get
				issuingTemplates, err := api.GetIssuingTemplates(cmd.Context(), apiClient)
				if err != nil {
					return fmt.Errorf("while getting issuing templates: %w", err)
				}

				manifestSubCa, err := apiToManifestSubCa(cmd.Context(), issuingtemplateResolver(issuingTemplates), subca)
				if err != nil {
					return fmt.Errorf("while converting to manifest: %w", err)
				}

				outputData = subCaProviderManifest{
					Kind:  kindWIMSubCaProvider,
					SubCa: manifestSubCa,
				}
			}

			switch format {
			case "yaml":
				var buf bytes.Buffer
				enc := yaml.NewEncoder(&buf)
				err = enc.Encode(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling SubCA Provider to YAML: %w", err)
				}
				coloredYAMLPrint(buf.String())
				return nil
			case "json":
				data, err := json.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling SubCA Provider to JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "yaml", "Output format (json, yaml)")
	cmd.Flags().BoolVar(&raw, "raw", false, "Display raw API response instead of manifest format")
	return cmd
}

func subcaRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <subca-name-or-id>",
		Short: "Remove a SubCA Provider",
		Long: undent.Undent(`
			Remove a SubCA Provider. This deletes the SubCA Provider from CyberArk
			Certificate Manager, SaaS. You cannot remove a SubCA Provider that is
			attached to a WIM (Workload Identity Manager, formerly Firefly)
			configuration.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the Sub CA name), got %s", args)
			}
			providerNameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.DeleteSubCaProvider(cmd.Context(), apiClient, providerNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}

			return nil
		},
	}
	return cmd
}

func subcaEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <subca-name-or-id>",
		Short: "Edit a SubCA Provider",
		Long: undent.Undent(`
			Edit a SubCA Provider using a single YAML manifest. The temporary file
			opened in your editor contains a single WIMSubCAProvider manifest.
		`),
		Example: undent.Undent(`
			vcpctl subca edit <subca-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the SubCA Provider name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("subca edit: %w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("subca edit: while creating API client: %w", err)
			}

			subca, err := api.GetSubCAProvider(cmd.Context(), apiClient, nameOrID)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return errutil.Fixable(fmt.Errorf("SubCA Provider '%s' not found. Please create it first using 'vcpctl apply -f <manifest.yaml>'", nameOrID))
			case err != nil:
				return fmt.Errorf("subca edit: while getting SubCA Provider: %w", err)
			}

			issuingTemplates, err := api.GetIssuingTemplates(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("subca edit: while getting issuing templates: %w", err)
			}

			manifestSubCa, err := apiToManifestSubCa(cmd.Context(), issuingtemplateResolver(issuingTemplates), subca)
			if err != nil {
				return fmt.Errorf("subca edit: while converting to manifest: %w", err)
			}

			subCaManifest := subCaProviderManifest{
				Kind:  kindWIMSubCaProvider,
				SubCa: manifestSubCa,
			}

			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			if err := enc.Encode(subCaManifest); err != nil {
				return fmt.Errorf("subca edit: while encoding WIMSubCAProvider to YAML: %w", err)
			}

			return editManifestsInEditor(
				cmd.Context(),
				buf.Bytes(),
				func(raw []byte) ([]manifest.Manifest, error) {
					return parseSingleManifestOfKind(raw, kindWIMSubCaProvider)
				},
				func(items []manifest.Manifest) error {
					if err := applyManifests(cmd.Context(), apiClient, items, false); err != nil {
						return fmt.Errorf("subca edit: while patching WIMSubCAProvider: %w", err)
					}
					return nil
				},
			)
		},
	}
	return cmd
}
