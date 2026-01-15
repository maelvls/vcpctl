package main

import (
	"fmt"
	"io"
	"os"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/spf13/cobra"
)

func applyCmd() *cobra.Command {
	var filePath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Create or update a WIM configuration",
		Long: undent.Undent(`
			Create or update a WIM (Workload Identity Manager, formerly Firefly)
			configuration in CyberArk Certificate Manager, SaaS. The configuration
			name is read from the manifest's 'name' field.
			Provide a kubectl-style multi-document manifest: declare ServiceAccount
			manifests first, followed by WIMIssuerPolicy manifests, and finish with
			a WIMConfiguration manifest.
		`),
		Example: undent.Undent(`
			vcpctl apply -f config.yaml
			vcpctl apply -f - < config.yaml
			vcpctl apply -f config.yaml --dry-run
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd, filePath, args, dryRun)
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

func runApply(cmd *cobra.Command, filePath string, args []string, dryRun bool) error {
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
		return fmt.Errorf("%s: expected no arguments. The configuration name is read from the 'name' field in the provided YAML manifest.", cmdName)
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
	err = applyManifests(apiClient, manifests, dryRun)
	if err != nil {
		return fmt.Errorf("%s: while applying manifests: %w", cmdName, err)
	}

	return nil
}
