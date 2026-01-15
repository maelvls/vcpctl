package main

import (
	"fmt"
	"io"
	"os"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/spf13/cobra"
)

func deleteCmd() *cobra.Command {
	var filePath string
	var ignoreNotFound bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete WIM resources from a manifest",
		Long: undent.Undent(`
			Delete WIM (Workload Identity Manager, formerly Firefly) resources
			from a manifest file in CyberArk Certificate Manager, SaaS.
			The resource name is read from the manifest's 'name' field.

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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDelete(cmd, filePath, args, ignoreNotFound)
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the WIM configuration file (YAML). Use '-' to read from stdin.")
	cmd.Flags().BoolVar(&ignoreNotFound, "ignore-not-found", false, "Ignore errors if the resource is not found")
	return cmd
}

func runDelete(cmd *cobra.Command, filePath string, args []string, ignoreNotFound bool) error {
	cmdName := cmd.Name()
	var file *os.File
	switch filePath {
	case "":
		return fmt.Errorf("%s: no file specified, use --file or -f to specify a file path. You can use '-f -' to read from stdin.", cmdName)
	case "-":
		filePath = "/dev/stdin"
		file = os.Stdin
	default:
		var err error
		file, err = os.Open(filePath)
		if err != nil {
			return fmt.Errorf("%s: opening file '%s': %w", cmdName, filePath, err)
		}
		defer file.Close()
	}

	if len(args) != 0 {
		return fmt.Errorf("%s: expected no arguments. The resource name is read from the 'name' field in the provided YAML manifest.", cmdName)
	}

	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdName, err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("%s: while reading WIM configuration from '%s': %w", cmdName, filePath, err)
	}

	manifests, err := parseManifests(data)
	if err != nil {
		return fmt.Errorf("%s: while decoding WIM manifests from '%s': %w", cmdName, filePath, err)
	}

	apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
	if err != nil {
		return fmt.Errorf("%s: while creating API client: %w", cmdName, err)
	}
	if err := deleteManifests(apiClient, manifests, ignoreNotFound); err != nil {
		return err
	}

	return nil
}
