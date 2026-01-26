package main

import (
	"fmt"
	"os"

	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/spf13/cobra"
)

func applyCmd(groupID string) *cobra.Command {
	var filePath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Applies resources from a YAML manifest",
		Long: undent.Undent(`
			Applies resources from a manifest file to CyberArk Certificate Manager,
			SaaS.
		`),
		Example: undent.Undent(`
			vcpctl apply -f config.yaml
			vcpctl apply -f - < config.yaml
			vcpctl apply -f config.yaml --dry-run
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
				return fmt.Errorf("expected no arguments. The configuration name is read from the 'name' field in the provided YAML manifest.")
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
			err = applyManifests(cmd.Context(), apiClient, manifests, dryRun)
			if err != nil {
				return fmt.Errorf("while applying manifests: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the WIM configuration file (YAML). Use '-' to read from stdin.")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be created/updated without making API calls")
	return cmd
}

func deprecatedPutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "put",
		Short:      "DEPRECATED: use 'vcpctl apply' instead",
		Hidden:     true,
		Deprecated: "use \"vcpctl apply\" instead; 'put' no longer does anything, and its input format has widely diverged from 'apply'",
	}

	return cmd
}
