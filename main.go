package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/njayp/ophis"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

// Replace the old flag-based main() with cobra execution.
func main() {
	var apiURLFlag, apiKeyFlag, tenantFlag string
	rootCmd := &cobra.Command{
		Use:   "vcpctl",
		Short: "CLI tool for managing WIM (formerly Firefly) configs in CyberArk Certificate Manager, SaaS",
		Long: undent.Undent(`
			vcpctl is a CLI tool for managing WIM (Workload Identity Manager,
			formerly Firefly) configurations in CyberArk Certificate Manager, SaaS
			(formerly known as Venafi Control Plane and Venafi Cloud).
            To configure it, set the VEN_API_KEY environment variable to your
            CyberArk Certificate Manager, SaaS API key. You can also set the
            VEN_API_URL environment variable to override the default API URL.
        `),
		Example: undent.Undent(`
			vcpctl ls
			vcpctl apply -f config.yaml
			vcpctl edit <config-name>
			vcpctl get <config-name> > config.yaml
			vcpctl attach-sa <config-name> --sa <sa-name>
			vcpctl sa ls
			vcpctl sa rm <sa-name>
			vcpctl sa put keypair <sa-name>
			vcpctl sa gen keypair <sa-name>
			vcpctl sa scopes
			vcpctl subca ls
			vcpctl subca rm <subca-name>
			vcpctl policy ls
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  false,
	}

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "api-url", "", "Use the given CyberArk Certificate Manager, SaaS API URL. You can also set VEN_API_URL. Flag takes precedence. When using this flag, the configuration file is not used.")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "Use the given CyberArk Certificate Manager, SaaS API key. You can also set VEN_API_KEY. Flag takes precedence. When using this flag, the configuration file is not used.")
	rootCmd.PersistentFlags().StringVar(&tenantFlag, "tenant", "", "Switch to the given tenant for this command. Accepts tenant ID (UUID), UI URL (domain or full URL). Overrides the current tenant in the config file.")

	rootCmd.PersistentFlags().BoolVar(&logutil.EnableDebug, "debug", false, "Enable debug logging (set to 'true' to enable)")
	rootCmd.AddCommand(
		loginCmd(),
		switchCmd(),
		tenantidCmd(),
		apikeyCmd(),
		apiurlCmd(),
		authCmd(),
		apiCmd(),
		lsCmd(),
		editCmd(),
		attachSaCmd(),
		applyCmd(),
		deprecatedPutCmd(),
		rmCmd(),
		getCmd(),
		saCmd(),
		subcaCmd(),
		policyCmd(),
	)

	rootCmd.AddCommand(ophis.Command(nil))

	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	switch {
	case errors.Is(err, api.APIKeyInvalid):
		logutil.Errorf("API key is invalid, try logging in again with:\n  vcpctl auth login\n")
		os.Exit(1)
	case err != nil:
		logutil.Errorf("%v", err)
		os.Exit(1)
	}
}

// For now we aren't yet using ~/.config/vcpctl.yml.
type ToolConf struct {
	APIURL string `json:"apiURL"`
	APIKey string `json:"apiKey"`
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
				return fmt.Errorf("sa ls: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			svcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("sa ls: while listing service accounts: %w", err)
			}

			switch outputFormat {
			case "json":
				b, err := marshalIndent(svcaccts, "", "  ")
				if err != nil {
					return fmt.Errorf("sa ls: while marshaling service accounts to JSON: %w", err)
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
				return errutil.Fixable(fmt.Errorf("sa ls: invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table, id)")
	return cmd
}

func attachSaCmd() *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("attach-sa: expected a single argument (the WIM configuration name), got %s", args)
			}
			confName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.AttachSAToConf(context.Background(), apiClient, confName, saName)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&saName, "sa", "s", "", "Service account name or client ID to attach to the WIM configuration")
	_ = cmd.MarkFlagRequired("sa")
	return cmd
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit a WIM configuration",
		Long: undent.Undent(`
			Edit a WIM (Workload Identity Manager, formerly Firefly) configuration.
			The temporary file opened in your editor is a multi-document manifest
			containing the ServiceAccount, WIMIssuerPolicy, and WIMConfiguration
			objects in dependency order.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("edit: expected a single argument (the WIM configuration name), got %s", args)
			}

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			client, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			err = editCmdLogic(context.Background(), client, args[0])
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			return nil
		},
	}
}

func applyCmd() *cobra.Command {
	return newApplyLikeCmd("apply")
}

func deprecatedPutCmd() *cobra.Command {
	cmd := newApplyLikeCmd("put")
	cmd.Deprecated = "use \"vcpctl apply\" instead; this alias will be removed in a future release"
	return cmd
}

func newApplyLikeCmd(name string) *cobra.Command {
	var filePath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   name,
		Short: "Create or update a WIM configuration",
		Long: undent.Undent(`
			Create or update a WIM (Workload Identity Manager, formerly Firefly)
			configuration in CyberArk Certificate Manager, SaaS. The configuration
			name is read from the manifest's 'name' field.
			Provide a kubectl-style multi-document manifest: declare ServiceAccount
			manifests first, followed by WIMIssuerPolicy manifests, and finish with
			a WIMConfiguration manifest.
		`),
		Example: undent.Undent(fmt.Sprintf(`
			vcpctl %s -f config.yaml
			vcpctl %s -f - < config.yaml
			vcpctl %s -f config.yaml --dry-run
		`, name, name, name)),
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

func rmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <config-name>",
		Short: "Remove a WIM configuration",
		Long: undent.Undent(`
			Remove a WIM (Workload Identity Manager, formerly Firefly)
			configuration. This deletes the configuration from CyberArk Certificate
			Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl rm my-config
			vcpctl rm 03931ba6-3fc5-11f0-85b8-9ee29ab248f0
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the WIM configuration name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("rm: while creating API client: %w", err)
			}
			// Get the configuration by name or ID.
			c, err := api.GetConfig(context.Background(), apiClient, nameOrID)
			if err != nil {
				if errors.As(err, &errutil.NotFound{}) {
					return fmt.Errorf("rm: Workload Identity Manager configuration '%s' not found", nameOrID)
				}
				return fmt.Errorf("rm: while getting Workload Identity Manager configuration by name or ID '%s': %w", nameOrID, err)
			}
			// Remove the configuration.
			err = api.RemoveConfig(context.Background(), apiClient, c.Id.String())
			if err != nil {
				return fmt.Errorf("rm: while removing Workload Identity Manager configuration '%s': %w", nameOrID, err)
			}
			logutil.Debugf("Workload Identity Manager configuration '%s' removed successfully.", nameOrID)
			return nil
		},
	}
	return cmd
}

func getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Export a WIM configuration",
		Long: undent.Undent(`
			Get a WIM (Workload Identity Manager, formerly Firefly) configuration
			from CyberArk Certificate Manager, SaaS. The configuration is written
			to stdout in YAML format.
		`),
		Example: undent.Undent(`
			vcpctl get <config-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("get: expected a single argument (the WIM configuration name), got %s", args)
			}
			idOrName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("get: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("get: while creating API client: %w", err)
			}

			knownSvcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("get: while fetching service accounts: %w", err)
			}

			config, err := api.GetConfig(context.Background(), apiClient, idOrName)
			if err != nil {
				return fmt.Errorf("get: while getting original Workload Identity Manager configuration: %w", err)
			}

			issuingTemplates, err := api.GetIssuingTemplates(context.Background(), apiClient)

			yamlData, err := renderToYAML(saResolver(knownSvcaccts), issuingtemplateResolver(issuingTemplates), config)
			if err != nil {
				return err
			}

			schemaFile, err := api.SaveSchemaToWellKnownPath()
			if err != nil {
				return fmt.Errorf("get: while saving schema.json to disk so that YAML can reference it: %w", err)
			}

			yamlData = appendSchemaComment(yamlData, schemaFile)

			coloredYAMLPrint(string(yamlData))

			return nil
		},
	}
}

func saResolver(svcAccts []api.ServiceAccountDetails) func(id openapi_types.UUID) (api.ServiceAccountDetails, error) {
	return func(id openapi_types.UUID) (api.ServiceAccountDetails, error) {
		found := api.ServiceAccountDetails{}
		for _, sa := range svcAccts {
			if sa.Id == openapi_types.UUID(id) {
				found = sa
				break
			}
		}
		if found.Id.String() == "" {
			return api.ServiceAccountDetails{}, fmt.Errorf("service account with ID %s not found", id.String())
		}
		return found, nil
	}
}

func issuingtemplateResolver(templates []api.CertificateIssuingTemplateInformation1) func(caAccountId, caProductOptionId openapi_types.UUID) (api.CertificateIssuingTemplateInformation1, error) {
	return func(caAccountId, caProductOptionId openapi_types.UUID) (api.CertificateIssuingTemplateInformation1, error) {
		for _, t := range templates {
			if t.CertificateAuthorityAccountId == caAccountId && t.CertificateAuthorityProductOptionId == caProductOptionId {
				return t, nil
			}
		}
		return api.CertificateIssuingTemplateInformation1{}, fmt.Errorf("issuing template with CaAccountId %s and CaProductOptionId %s not found", caAccountId.String(), caProductOptionId.String())
	}
}

func editCmdLogic(ctx context.Context, cl *api.Client, name string) error {
	knownSvcaccts, err := api.GetServiceAccounts(ctx, cl)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	config, err := api.GetConfig(ctx, cl, name)
	switch {
	case errors.Is(err, errutil.NotFound{}):
		return errutil.Fixable(fmt.Errorf("configuration '%s' not found. Please create it first using 'vcpctl apply config.yaml'", name))
	case err != nil:
		return fmt.Errorf("while getting configuration ID: %w", err)
	}

	templates, err := api.GetIssuingTemplates(ctx, cl)
	if err != nil {
		return fmt.Errorf("while fetching issuing templates: %w", err)
	}

	yamlData, err := renderToYAML(saResolver(knownSvcaccts), issuingtemplateResolver(templates), config)
	if err != nil {
		return err
	}

	schemaFile, err := api.SaveSchemaToWellKnownPath()
	if err != nil {
		return fmt.Errorf("while saving schema.json to disk so that YAML can reference it: %w", err)
	}
	defer os.Remove(schemaFile)

	yamlData = appendSchemaComment(yamlData, schemaFile)

	tmpfile, err := os.CreateTemp("", "vcp-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(yamlData); err != nil {
		return err
	}
	defer tmpfile.Close()

	info, _ := os.Stat(tmpfile.Name())
	lastSaved := info.ModTime()
	justSaved := func() {
		info, _ := os.Stat(tmpfile.Name())
		lastSaved = info.ModTime()
	}
edit:
	// Open editor to let you edit YAML.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf(`%s "%s"`, editor, tmpfile.Name()))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// Read and parse the modified YAML.
	modifiedRaw, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		return err
	}

	// Abort if the file is empty or if the file hasn't been written to.
	if len(modifiedRaw) == 0 {
		logutil.Debugf("the configuration file is empty, aborting")
		return nil
	}
	info, _ = os.Stat(tmpfile.Name())
	if info.ModTime().Equal(lastSaved) {
		logutil.Infof("No edits, aborting.")
		return nil
	}

	modified, err := parseManifests(modifiedRaw)
	switch {
	case errutil.ErrIsFixable(err):
		err = addErrorNoticeToFile(tmpfile.Name(), err)
		if err != nil {
			return fmt.Errorf("while showing notice for fixable error: %w", err)
		}
		justSaved()
		goto edit
	case err != nil:
		return fmt.Errorf("while parsing modified Workload Identity Manager manifests: %w", err)
	}

	if err != nil {
		return fmt.Errorf("edit: while creating API client: %w", err)
	}
	err = applyManifests(cl, modified, false)
	switch {
	// In case we were returned a 400 Bad Request or if it's a fixable error,
	// let's give a chance to the user to fix the problem.
	case errutil.ErrIsFixable(err), api.ErrIsHTTPBadRequest(err):
		err = addErrorNoticeToFile(tmpfile.Name(), err)
		if err != nil {
			return fmt.Errorf("while showing notice for fixable error: %w", err)
		}
		justSaved()
		goto edit
	case err != nil:
		return fmt.Errorf("while merging and patching Workload Identity Manager configuration: %w", err)
	}

	return nil
}

func addErrorNoticeToFile(tmpfile string, err error) error {
	if err == nil {
		logutil.Errorf("addErrorNoticeToFile: err is nil")
		return nil
	}

	// Read and parse the modified YAML.
	modifiedRaw, rerr := os.ReadFile(tmpfile)
	if rerr != nil {
		logutil.Errorf("while reading temporary file to show notice: %s", rerr)
		return fmt.Errorf("while reading temporary file to show notice: %w", rerr)
	}

	logutil.Debugf("the configuration you have modified has an issue:\n%s", err)

	modifiedRaw = removeNoticeFromYAML(modifiedRaw)
	notice := "# NOTICE: Errors were found, please edit the configuration.\n" +
		"# NOTICE: You can abort editing by emptying this file.\n" +
		"# NOTICE:\n" +
		"# NOTICE: " + strings.ReplaceAll(err.Error(), "\n", "\n# NOTICE: ") + "\n\n"
	err = os.WriteFile(tmpfile, append([]byte(notice), modifiedRaw...), 0644)
	if err != nil {
		return fmt.Errorf("while writing notice to temporary file: %w", err)
	}

	return nil
}

var re = regexp.MustCompile(`(?m)^# NOTICE:.*\n`)

// Remove the NOTICE lines from the YAML data.
func removeNoticeFromYAML(yamlData []byte) []byte {
	return re.ReplaceAll(yamlData, []byte{})
}

// Doesn't work anymore since `serviceAccountIds` is hidden in the 'get', 'put,
// and 'edit' commands.
var ErrPINRequired = errutil.Fixable(fmt.Errorf("subCaProvider.pkcs11.pin is required when patching the subCA provider"))

// Returns the PEM-encoded private and public keys.
func genECKeyPair() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while generating EC key pair: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while marshalling private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while marshalling public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return string(privPEM), string(pubPEM), nil
}

// For anyone who uses the Red Hat YAML LSP server.
func appendSchemaComment(b []byte, schemaAbsPath string) []byte {
	return appendLines(b,
		"# yaml-language-server: $schema=file://"+schemaAbsPath,
	)
}

func appendLines(b []byte, line ...string) []byte {
	if len(line) == 0 {
		return b
	}
	for _, l := range line {
		b = append(b, []byte("\n"+l+"\n")...)
	}
	return b
}

func coloredYAMLPrint(yamlBytes string) {
	// If not a TTY, let's not color the output.
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Print(yamlBytes)
		return
	}

	const escape = "\x1b"
	format := func(attr color.Attribute) string {
		return fmt.Sprintf("%s[%dm", escape, attr)
	}

	tokens := lexer.Tokenize(yamlBytes)

	var p printer.Printer
	p.LineNumber = false
	p.LineNumberFormat = func(num int) string {
		fn := color.New(color.Bold, color.FgHiWhite).SprintFunc()
		return fn(fmt.Sprintf("%2d | ", num))
	}
	p.Bool = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.Number = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.MapKey = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiCyan),
			Suffix: format(color.Reset),
		}
	}
	p.Anchor = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiYellow),
			Suffix: format(color.Reset),
		}
	}
	p.Alias = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiYellow),
			Suffix: format(color.Reset),
		}
	}
	p.String = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiGreen),
			Suffix: format(color.Reset),
		}
	}
	p.Comment = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiBlack),
			Suffix: format(color.Reset),
		}
	}
	writer := colorable.NewColorableStdout()
	_, _ = writer.Write([]byte(p.PrintTokens(tokens)))
}

// Returns a list of IDs.
func rmInteractive(in []api.ServiceAccountDetails) []string {
	type item struct {
		Name, ID string
	}

	var opts []huh.Option[item]
	for _, sa := range in {
		opts = append(opts, huh.NewOption(fmt.Sprintf("client ID: %s, name: %s", sa.Id, sa.Name), item{
			Name: sa.Name,
			ID:   sa.Id.String(),
		}).Selected(false))
	}

	var selected []item
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[item]().Options(opts...).Value(&selected),
		).Title("Select Service Accounts to remove"),
	)

	if err := form.Run(); err != nil {
		logutil.Errorf("rmInteractive: while running form: %s", err)
		return nil
	}

	var ids []string
	for _, sel := range selected {
		ids = append(ids, sel.ID)
	}
	return ids
}

// I don't like Lipgloss's tables because they make it hard to select text in
// the table without also selecting other elements. So I've implemented a
// simple table printer that uses ANSI escape codes to color the output.
//
// All columns are tab-separated, and the headers are printed in bold cyan.
func printTable(headers []string, rows [][]string) {
	// Color the headers in bold cyan, and make them ALL CAPS.
	for i := range headers {
		headers[i] = strings.ToUpper(headers[i])
		headers[i] = boldCyan(headers[i])
	}

	maxWidths := make([]int, len(headers))
	for i, header := range headers {
		maxWidths[i] = len(withoutANSI(header))
	}
	for _, row := range rows {
		for i, col := range row {
			len := len(withoutANSI(col))
			if len > maxWidths[i] {
				maxWidths[i] = len
			}
		}
	}

	for i, header := range headers {
		fmt.Printf("%-*s\t", maxWidths[i]+countANSIChars(header), header)
	}
	fmt.Println()

	for _, row := range rows {
		for i, col := range row {
			fmt.Printf("%-*s\t", maxWidths[i]+countANSIChars(col), col)
		}
		fmt.Println()
	}
}

// Returns an ANSI color escape code that is unique to the given text.
func uniqueColor(text string) string {
	// Don't color if the terminal is not a TTY.
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}

	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", hash(text)%256, text)
}

func hash(s string) int {
	// A simple hash function that returns a number between 0 and 255. This is
	// not cryptographically secure, but it's good enough for our purposes of
	// generating unique colors.
	var h int
	for _, c := range s {
		h = (h*31 + int(c)) % 256
	}
	return h
}

func redBold(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[1;31m%s\x1b[0m", text)
}

func lightGray(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[90m%s\x1b[0m", text)
}

func boldCyan(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[1;34m%s\x1b[0m", text)
}

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// Remove ANSI escape codes from the text. Useful for calculating how many chars
// a string has for alignment purposes.
func withoutANSI(s string) string {
	return ansiRegexp.ReplaceAllString(s, "")
}

func countANSIChars(s string) int {
	return len(s) - len(withoutANSI(s))
}
