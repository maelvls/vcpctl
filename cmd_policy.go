package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	"github.com/spf13/cobra"
)

func policySubcmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Policies",
		Long: undent.Undent(`
			Manage policies. Policies define the rules for issuing certificates.
			You can list, create, delete, and set a policy for a WIM (Workload
			Identity Manager, formerly Firefly) configuration.
		`),
		Example: undent.Undent(`
			vcpctl policy ls
			vcpctl policy get <policy-name>
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
	}
	cmd.AddCommand(
		policyLsCmd(),
		policyGetCmd(),
		policyEditCmd(),
		policyRmCmd(),
	)
	return cmd
}

func policyLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List Policies",
		Long: undent.Undent(`
			List Policies. Policies are used to define the rules for issuing
			certificates.
		`),
		Example: undent.Undent(`
			vcpctl policy ls
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
			policies, err := api.GetPolicies(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("while listing policies: %w", err)
			}
			var rows [][]string
			for _, policy := range policies {
				rows = append(rows, []string{
					policy.Id.String(),
					policy.Name,
					policy.ValidityPeriod,
					strings.Join(policy.Subject.CommonName.DefaultValues, ", "),
					strings.Join(policy.Sans.DnsNames.DefaultValues, ", "),
				})
			}

			printTable([]string{"ID", "Policy Name", "Validity", "Common Name", "DNS Names"}, rows)
			return nil
		},
	}
	return cmd
}

func policyGetCmd() *cobra.Command {
	var format string
	var raw bool
	cmd := &cobra.Command{
		Use:   "get <policy-name-or-id>",
		Short: "Get a Policy",
		Long: undent.Undent(`
			Get a policy's details. By default, displays the policy as a
			manifest.WIMIssuerPolicy. Use --raw to display the raw API response.
		`),
		Example: undent.Undent(`
			vcpctl policy get <policy-name>
			vcpctl policy get <policy-name> --raw
			vcpctl policy get <policy-name> -o json
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the policy name or ID), got %s", args)
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

			policy, err := api.GetPolicy(cmd.Context(), apiClient, nameOrID)
			if err != nil {
				return fmt.Errorf("while getting policy: %w", err)
			}

			var outputData interface{}
			if raw {
				outputData = policy
			} else {
				outputData = policyManifest{
					Kind:   kindIssuerPolicy,
					Policy: apiToManifestExtendedPolicyInformation(policy),
				}
			}

			switch format {
			case "yaml":
				bytes, err := yaml.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling policy to YAML: %w", err)
				}
				coloredYAMLPrint(string(bytes) + "\n")
				return nil
			case "json":
				data, err := json.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling policy to JSON: %w", err)
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

func policyRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <policy-name-or-id>",
		Short: "Remove a Policy",
		Long: undent.Undent(`
			Remove a policy. This deletes the policy from CyberArk Certificate
			Manager, SaaS. You cannot remove a policy that is attached to a WIM
			(Workload Identity Manager, formerly Firefly) configuration. Remove the
			policy from the WIM configuration first.
		`),
		Example: undent.Undent(`
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the Policy name or ID), but got %s", args)
			}
			policyNameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.DeletePolicy(cmd.Context(), apiClient, policyNameOrID)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			logutil.Debugf("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}

func policyEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <policy-name-or-id>",
		Short: "Edit a Policy",
		Long: undent.Undent(`
			Edit a Policy using a single YAML manifest. The temporary file opened
			in your editor contains a single WIMIssuerPolicy manifest.
		`),
		Example: undent.Undent(`
			vcpctl policy edit <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the policy name or ID), got %s", args)
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

			policy, err := api.GetPolicy(cmd.Context(), apiClient, nameOrID)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return errutil.Fixable(fmt.Errorf("policy '%s' not found. Please create it first using 'vcpctl apply -f <manifest.yaml>'", nameOrID))
			case err != nil:
				return fmt.Errorf("while getting policy: %w", err)
			}

			policyManifest := policyManifest{
				Kind:   kindIssuerPolicy,
				Policy: apiToManifestExtendedPolicyInformation(policy),
			}

			var buf bytes.Buffer
			enc := yaml.NewEncoder(&buf)
			if err := enc.Encode(policyManifest); err != nil {
				return fmt.Errorf("while encoding WIMIssuerPolicy to YAML: %w", err)
			}

			return editManifestsInEditor(
				cmd.Context(),
				buf.Bytes(),
				func(raw []byte) ([]manifest.Manifest, error) {
					return parseSingleManifestOfKind(raw, kindIssuerPolicy)
				},
				func(items []manifest.Manifest) error {
					if err := applyManifests(cmd.Context(), apiClient, items, false); err != nil {
						return fmt.Errorf("while patching WIMIssuerPolicy: %w", err)
					}
					return nil
				},
			)
		},
	}
	return cmd
}
