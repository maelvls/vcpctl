package main

import (
	"fmt"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/spf13/cobra"
)

func attachSaCmd(groupID string) *cobra.Command {
	var saName string
	cmd := &cobra.Command{
		Use:   "attach-sa <config-name> --sa <sa-name>",
		Short: "Attach a service account to a WIM configuration",
		Long: undent.Undent(`
			Attach the given service account to the WIM (Workload Identity Manager,
			formerly Firefly) configuration.
		`),
		Example: undent.Undent(`
			vcpctl attach-sa "config-name" --sa "sa-name"
			vcpctl attach-sa "config-name" --sa "03931ba6-3fc5-11f0-85b8-9ee29ab248f0"
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the WIM configuration name), got %s", args)
			}
			confName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.AttachSAToConf(cmd.Context(), apiClient, confName, saName)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&saName, "sa", "s", "", "Service account name or client ID to attach to the WIM configuration")
	_ = cmd.MarkFlagRequired("sa")
	return cmd
}
