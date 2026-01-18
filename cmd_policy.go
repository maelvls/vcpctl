package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

func policyCmd() *cobra.Command {
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
	}
	cmd.AddCommand(
		policyLsCmd(),
		policyGetCmd(),
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
				return fmt.Errorf("policy ls: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			policies, err := api.GetPolicies(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("policy ls: while listing policies: %w", err)
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
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			policy, err := api.GetPolicy(context.Background(), apiClient, nameOrID)
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
				return fmt.Errorf("rm: expected a single argument (the Policy name), got %s", args)
			}
			policyNameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.DeletePolicy(context.Background(), apiClient, policyNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			logutil.Debugf("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}
