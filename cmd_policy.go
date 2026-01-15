package main

import (
	"context"
	"fmt"
	"strings"

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
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		policyLsCmd(),
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
			err = api.RemovePolicy(context.Background(), apiClient, policyNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			logutil.Debugf("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}
