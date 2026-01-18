package main

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/x/term"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/logutil"
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

			To get started, run:

				vcpctl login
        `),
		Example: undent.Undent(`
			vcpctl conf ls
			vcpctl apply -f config.yaml
			vcpctl delete -f config.yaml
			vcpctl edit <config-name>
			vcpctl conf get <config-name> > config.yaml
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
		SilenceUsage:  true,
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
		confCmd(),
		editCmd(),
		attachSaCmd(),
		applyCmd(),
		deleteCmd(),
		deprecatedPutCmd(),
		deprecatedLsCmd(),
		deprecatedGetCmd(),
		deprecatedRmCmd(),
		saCmd(),
		subcaCmd(),
		policyCmd(),
	)

	rootCmd.AddCommand(ophis.Command(&ophis.Config{}))

	ctx := context.Background()
	err := fang.Execute(
		ctx,
		rootCmd,
		fang.WithErrorHandler(errHandler),
		fang.WithNotifySignal(os.Interrupt, os.Kill),
	)
	switch {
	case err != nil:
		os.Exit(1)
	}
}

func errHandler(w io.Writer, styles fang.Styles, err error) {
	// If stderr is not a tty, simply print the error without any styling. That
	// way, it is still possible to parse error messages in scripts.
	if w, ok := w.(term.File); ok {
		if !term.IsTerminal(w.Fd()) {
			_, _ = fmt.Fprintln(w, err.Error())
			return
		}
	}

	// Handle multiline error messages by processing each line separately to
	// preserve the transform while maintaining line breaks.
	errStr := err.Error()
	noTransform := styles.ErrorText.UnsetTransform()
	var errMsgLines []string
	for i, line := range strings.Split(errStr, "\n") {
		if line == "" {
			errMsgLines = append(errMsgLines, "")
			continue
		}
		if i > 0 {
			errMsgLines = append(errMsgLines, noTransform.Render(line))
			continue
		}
		errMsgLines = append(errMsgLines, styles.ErrorText.Render(line))
	}
	errMsgRendered := strings.Join(errMsgLines, "\n")

	styles.ErrorText.Inline(true).PaddingLeft(0)
	_, _ = fmt.Fprintln(w, styles.ErrorHeader.String())
	_, _ = fmt.Fprintln(w, errMsgRendered)
	_, _ = fmt.Fprintln(w)
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
