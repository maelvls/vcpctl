package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	"github.com/spf13/cobra"
)

func saSubcmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sa",
		Short: "Manage Service Accounts",
		Long: undent.Undent(`
			Manage Service Accounts.
		`),
		Example: undent.Undent(`
			vcpctl sa ls
			vcpctl sa rm <sa-name>
			vcpctl sa get <sa-name>
			vcpctl sa get <sa-name> -oclientid
			vcpctl sa edit <sa-name>
			vcpctl sa put wif <sa-name>
			vcpctl sa put keypair <sa-name>
			vcpctl sa gen wif <sa-name>
			vcpctl sa gen keypair <sa-name>
			vcpctl sa scopes
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
	}
	cmd.AddCommand(
		saLsCmd(),
		saRmCmd(),
		saPutCmd(),
		saGenCmd(),
		saGetCmd(),
		saEditCmd(),
		saScopesCmd(),
		&cobra.Command{Use: "gen-rsa", Deprecated: "the 'gen-rsa' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE, Hidden: true},
		&cobra.Command{Use: "keygen", Deprecated: "the 'keygen' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE, Hidden: true},
		&cobra.Command{Use: "get-clientid", Deprecated: "the 'get-clientid' command is deprecated, please use 'vcpctl sa get -oclientid' instead.", RunE: saGenkeypairCmd().RunE, Hidden: true},
	)
	return cmd
}

func saLsCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "ls [-o json|id]",
		Short: "List Service Accounts",
		Long: undent.Undent(`
			List service accounts. Service accounts authenticate applications that
			use WIM (Workload Identity Manager) configurations.

			You can use -oid to only display the Service Account client IDs.
		`),
		Example: undent.Undent(`
			vcpctl sa ls
			vcpctl sa ls -ojson
			vcpctl sa ls -oid
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
			svcaccts, err := api.GetServiceAccounts(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("while listing service accounts: %w", err)
			}

			switch outputFormat {
			case "json":
				b, err := marshalIndent(svcaccts, "", "  ")
				if err != nil {
					return fmt.Errorf("while marshaling service accounts to JSON: %w", err)
				}
				fmt.Println(string(b))
				return nil
			case "table":
				var rows [][]string
				for _, sa := range svcaccts {
					rows = append(rows, []string{
						sa.Id.String(),
						uniqueColor(sa.AuthenticationType),
						sa.Name,
					})
				}
				printTable([]string{"Client ID", "Auth Type", "Service Account Name"}, rows)
				return nil
			case "id":
				for _, sa := range svcaccts {
					fmt.Println(sa.Id.String())
				}
				return nil
			default:
				return errutil.Fixable(fmt.Errorf("invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table, id)")
	return cmd
}

func saGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generates and sets a new key pair or Workload Identity Federation configuration for a Service Account",
		Long: undent.Undent(`
			Generates and sets a new key pair or Workload Identity Federation configuration
			for a Service Account in CyberArk Certificate Manager, SaaS.

			The command 'vcpctl sa gen wif' pushes the generated public key to
			https://0x0.st and sets the JWKS URL in the Service Account configuration
			to that URL. Security-wise, this is safe because the URL's path is a randomly
			generated hash: no way to squat the same URL to serve a different JWKS.

			The JWKS URL served by 0x0.st goes away after 30 days.
		`),
		Example: undent.Undent(`
			vcpctl sa gen keypair <sa-name>
			vcpctl sa gen keypair <sa-name> -ojson
			vcpctl sa gen wif <sa-name> -ojson
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(saGenkeypairCmd())
	cmd.AddCommand(saGenWifCmd())
	return cmd
}

func saPutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Creates or updates a Service Account",
		Long: undent.Undent(`
			Creates or updates a Service Account in CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa put keypair <sa-name>
			vcpctl sa put wif <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(saPutKeypairCmd())
	cmd.AddCommand(saPutWifCmd())
	return cmd
}

func saGetCmd() *cobra.Command {
	var format string
	var raw bool
	cmd := &cobra.Command{
		Use:   "get <sa-name-or-id>",
		Short: "Get the information about an existing Service Account using its name or ID",
		Long: undent.Undent(`
			Get the Service Account's details. By default, displays the service
			account as a manifest.ServiceAccount. Use --raw to display the raw
			API response. You can use -o clientid to only display the client ID
			of the Service Account.

			Note that the 'client ID' of a service account is the same as its ID,
			which means these two commands are equivalent:

			  vcpctl sa get <sa-name> -oid
			  vcpctl sa get <sa-name> -oclientid
		`),
		Example: undent.Undent(`
			vcpctl sa get <sa-name-or-id>
			vcpctl sa get <sa-name-or-id> --raw
			vcpctl sa get <sa-name-or-id> -o json
			vcpctl sa get <sa-name-or-id> -o id
			vcpctl sa get <sa-name-or-id> -o clientid
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the service account name), got: %s", args)
			}

			saName := args[0]

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			sa, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			if err != nil {
				if errutil.ErrIsNotFound(err) {
					return fmt.Errorf("service account '%s' not found", saName)
				}
				return fmt.Errorf("while getting service account by name: %w", err)
			}

			if sa.Id.String() == "" {
				return fmt.Errorf("service account '%s' has no client ID", saName)
			}

			// Convert to manifest unless --raw is specified.
			var outputData interface{}
			if raw {
				outputData = sa
			} else {
				outputData = serviceAccountManifest{
					Kind:           kindServiceAccount,
					ServiceAccount: apiToManifestServiceAccount(sa),
				}
			}

			switch format {
			case "yaml":
				bytes, err := yaml.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling service account to YAML: %w", err)
				}
				coloredYAMLPrint(string(bytes) + "\n") // Not sure why '\n' is needed, but it is.
				return nil
			case "id":
				fmt.Println(sa.Id.String())
				return nil
			case "clientid":
				fmt.Println(sa.Id.String())
				return nil
			case "json":
				data, err := json.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling service account to JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "yaml", "Output format (id, json, yaml). The 'id' is the service account's client ID.")
	cmd.Flags().BoolVar(&raw, "raw", false, "Display raw API response instead of manifest format")
	return cmd
}

func saEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <sa-name-or-id>",
		Short: "Edit a Service Account",
		Long: undent.Undent(`
			Edit a Service Account using a single YAML manifest. The temporary
			file opened in your editor contains a single ServiceAccount manifest.
		`),
		Example: undent.Undent(`
			vcpctl sa edit <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the service account name or ID), got: %s", args)
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

			sa, err := api.GetServiceAccount(cmd.Context(), apiClient, nameOrID)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return errutil.Fixable(fmt.Errorf("service account '%s' not found. Please create it first using 'vcpctl sa put keypair %s' or 'vcpctl sa put wif %s'", nameOrID, nameOrID, nameOrID))
			case err != nil:
				return fmt.Errorf("while getting service account: %w", err)
			}

			saManifest := serviceAccountManifest{
				Kind:           kindServiceAccount,
				ServiceAccount: apiToManifestServiceAccount(sa),
			}

			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			if err := enc.Encode(saManifest); err != nil {
				return fmt.Errorf("while encoding ServiceAccount to YAML: %w", err)
			}

			return editManifestsInEditor(
				cmd.Context(),
				buf.Bytes(),
				func(raw []byte) ([]manifest.Manifest, error) {
					return parseSingleManifestOfKind(raw, kindServiceAccount)
				},
				func(items []manifest.Manifest) error {
					if err := applyManifests(cmd.Context(), apiClient, items, false); err != nil {
						return fmt.Errorf("while patching ServiceAccount: %w", err)
					}
					return nil
				},
			)
		},
	}
	return cmd
}

func saScopesCmd() *cobra.Command {
	var outputFormat string // "json", "table"
	var typeFilter string   // "rsaKey", "rsaKeyFederated"
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "List all available Service Account scopes",
		Long: undent.Undent(`
			List all available Service Account scopes. Scopes define what
			permissions a service account has when authenticating with
			CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa scopes
			vcpctl sa scopes -o json
			vcpctl sa scopes --type rsaKey
			vcpctl sa scopes --type rsaKeyFederated -o table
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

			scopes, err := api.GetServiceAccountScopes(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("while listing scopes: %w", err)
			}

			if typeFilter != "" {
				var filtered []api.ScopeDetails
				for _, s := range scopes {
					if s.AuthenticationType == typeFilter || slices.Contains(s.AuthenticationTypes, typeFilter) {
						filtered = append(filtered, s)
					}
				}
				scopes = filtered
			}

			switch outputFormat {
			case "json":
				b, err := marshalIndent(scopes, "", "  ")
				if err != nil {
					return fmt.Errorf("while marshaling scopes to JSON: %w", err)
				}
				fmt.Println(string(b))
				return nil
			case "table":
				var rows [][]string
				for _, scope := range scopes {
					var authTypes []string
					if scope.AuthenticationType != "" {
						authTypes = append(authTypes, scope.AuthenticationType)
					}
					authTypes = append(authTypes, scope.AuthenticationTypes...)

					if len(authTypes) == 0 {
						authTypes = []string{"-"}
					}
					rows = append(rows, []string{
						scope.Id,
						strings.Join(authTypes, ", "),
						scope.ReadableName,
					})
				}
				printTable([]string{"Scope ID", "Auth Type", "Description"}, rows)
				return nil
			default:
				return errutil.Fixable(fmt.Errorf("invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table).")
	cmd.Flags().StringVarP(&typeFilter, "type", "a", "", "Filter scopes by authentication type. Supported values are 'rsaKey' and 'rsaKeyFederated'.")
	return cmd
}

func saRmCmd() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{
		Use:   "rm (<sa-name> | -i)",
		Short: "Remove a Service Account",
		Long: undent.Undent(`
			Remove a Service Account. This will delete the Service Account from
			CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa rm <sa-name>
			vcpctl sa rm -i
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if interactive {
				if len(args) > 0 {
					return fmt.Errorf("expected no arguments when using --interactive, got %s", args)
				}
				// In interactive mode, we will list the service accounts and let the user
				// select one to remove.
				conf, err := getToolConfig(cmd)
				if err != nil {
					return fmt.Errorf("%w", err)
				}
				apiClient, err := newAPIClient(conf)
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				svcaccts, err := api.GetServiceAccounts(cmd.Context(), apiClient)
				if err != nil {
					return fmt.Errorf("while listing service accounts: %w", err)
				}

				// Use a simple prompt to select the service account to remove.
				selected := rmInteractive(svcaccts)
				for _, saID := range selected {
					err = api.DeleteServiceAccount(cmd.Context(), apiClient, saID)
					if err != nil {
						return fmt.Errorf("while removing service account '%s': %w", saID, err)
					}
				}

				logutil.Debugf("Service Account(s) removed successfully:\n%s", strings.Join(selected, "\n"))
				return nil
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the service account name), got: %s", args)
			}
			saName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.DeleteServiceAccount(cmd.Context(), apiClient, saName)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactively select the service account to remove.")
	return cmd
}
