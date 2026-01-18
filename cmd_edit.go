package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

func confEditCmd() *cobra.Command {
	var showDeps bool
	cmd := &cobra.Command{
		Use:   "edit <config-name>",
		Short: "Edit a WIM configuration",
		Long: undent.Undent(`
			Edit a WIM (Workload Identity Manager, formerly Firefly) configuration.
			By default, the temporary file opened in your editor contains a
			single WIMConfiguration manifest. Use --deps to include all
			dependencies in the same order as 'vcpctl conf get --deps':
			WIMConfiguration, ServiceAccount, WIMIssuerPolicy, WIMSubCAProvider.
		`),
		Example: undent.Undent(`
			vcpctl conf edit <config-name>
			vcpctl conf edit <config-name> --deps
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

			client, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			err = confEditCmdLogic(context.Background(), client, args[0], showDeps)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&showDeps, "deps", false, "Include dependencies (service accounts, policies, and Sub CA)")
	return cmd
}

func confEditCmdLogic(ctx context.Context, cl *api.Client, name string, includeDeps bool) error {
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

	var yamlData []byte
	if includeDeps {
		yamlData, err = renderToYAML(saResolver(knownSvcaccts), issuingtemplateResolver(templates), config)
		if err != nil {
			return err
		}
	} else {
		wimConfig, _, _, _, err := renderToManifests(saResolver(knownSvcaccts), issuingtemplateResolver(templates), config)
		if err != nil {
			return fmt.Errorf("while rendering to manifests: %w", err)
		}
		configManifest := configurationManifest{
			Kind:             kindConfiguration,
			WIMConfiguration: wimConfig,
		}

		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		if err := enc.Encode(configManifest); err != nil {
			return fmt.Errorf("while encoding WIMConfiguration to YAML: %w", err)
		}
		yamlData = buf.Bytes()
	}

	parseFn := parseManifests
	if !includeDeps {
		parseFn = func(raw []byte) ([]manifest.Manifest, error) {
			return parseSingleManifestOfKind(raw, kindConfiguration)
		}
	}

	return editManifestsInEditor(
		yamlData,
		parseFn,
		func(items []manifest.Manifest) error {
			err := applyManifests(cl, items, false)
			if err != nil {
				return fmt.Errorf("while merging and patching Workload Identity Manager configuration: %w", err)
			}
			return nil
		},
	)
}

func editManifestsInEditor(
	initial []byte,
	parse func([]byte) ([]manifest.Manifest, error),
	apply func([]manifest.Manifest) error,
) error {
	tmpfile, err := os.CreateTemp("", "vcp-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(initial); err != nil {
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
		logutil.Debugf("the manifest file is empty, aborting")
		return nil
	}
	info, _ = os.Stat(tmpfile.Name())
	if info.ModTime().Equal(lastSaved) {
		logutil.Infof("No edits, aborting.")
		return nil
	}

	modified, err := parse(modifiedRaw)
	switch {
	case errutil.ErrIsFixable(err):
		err = addErrorNoticeToFile(tmpfile.Name(), err)
		if err != nil {
			return fmt.Errorf("while showing notice for fixable error: %w", err)
		}
		justSaved()
		goto edit
	case err != nil:
		return fmt.Errorf("while parsing modified manifests: %w", err)
	}

	err = apply(modified)
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
		return err
	}

	return nil
}

func parseSingleManifestOfKind(raw []byte, expectedKind string) ([]manifest.Manifest, error) {
	manifests, err := parseManifests(raw)
	if err != nil {
		return nil, err
	}
	if len(manifests) != 1 {
		return nil, errutil.Fixable(fmt.Errorf("expected a single %s manifest, got %d document(s)", expectedKind, len(manifests)))
	}

	gotKind := getManifestKind(manifests[0])
	if gotKind != expectedKind {
		return nil, errutil.Fixable(fmt.Errorf("expected manifest kind %q, got %q", expectedKind, gotKind))
	}

	return manifests, nil
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
		return "", "", fmt.Errorf("while generating EC key pair: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("while marshalling private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("while marshalling public key: %w", err)
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
