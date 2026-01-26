package main

import (
	"fmt"
	"os"

	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/spf13/cobra"
)

func deleteCmd(groupID string) *cobra.Command {
	var filePath string
	var ignoreNotFound bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete resources from a YAML manifest",
		Long: undent.Undent(`
			Delete resources from a manifest file in CyberArk Certificate Manager,
			SaaS.

			The deletion order goes from the last object to the first in order
			to respect dependencies (e.g., ServiceAccount should be deleted
			after the WIMConfiguration that uses it).
		`),
		Example: undent.Undent(`
			vcpctl delete -f config.yaml
			vcpctl delete -f - < config.yaml
			vcpctl delete -f config.yaml --ignore-not-found
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			var file *os.File
			switch filePath {
			case "":
				return fmt.Errorf("no file specified, use --file or -f to specify a file path. You can use '-f -' to read from stdin.")
			case "-":
				filePath = "/dev/stdin"
				file = os.Stdin
			default:
				var err error
				file, err = os.Open(filePath)
				if err != nil {
					return fmt.Errorf("opening file '%s': %w", filePath, err)
				}
				defer file.Close()
			}

			if len(args) != 0 {
				return fmt.Errorf("expected no arguments. The resource name is read from the 'name' field in the provided YAML manifest.")
			}

			data, err := cancellablereader.ReadAllWithContext(cmd.Context(), file)
			if err != nil {
				return fmt.Errorf("while reading WIM configuration from '%s': %w", filePath, err)
			}

			manifests, err := parseManifests(data)
			if err != nil {
				return fmt.Errorf("while decoding WIM manifests from '%s': %w", filePath, err)
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			if err := deleteManifests(cmd.Context(), apiClient, manifests, ignoreNotFound); err != nil {
				return err
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the manifest file (YAML). Use '-' to read from stdin.")
	cmd.Flags().BoolVar(&ignoreNotFound, "ignore-not-found", false, "Ignore errors if the resource is not found")
	return cmd
}
