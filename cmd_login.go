package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

// This CLI stores its authentication information in ~/.config/vcpctl.yaml.
const configPath = ".config/vcpctl.yaml"

// FileConf is inspired by kubectl's ~/.kube/config structure
type FileConf struct {
	CurrentContext string        `yaml:"current-context"`
	ToolContexts   []ToolContext `yaml:"contexts"`
}

type ToolContext struct {
	Name string `yaml:"name"` // Derived from tenant URL domain with numeric suffix

	TenantID  string `json:"tenantID,omitzero"` // The tenant ID (company ID).
	TenantURL string `yaml:"url,omitzero"`      // The UI URL of the tenant, e.g., https://ven-cert-manager-uk.venafi.cloud
	APIURL    string `json:"apiURL,omitzero"`   // The API URL of the tenant, e.g., https://api.uk.venafi.cloud
	Username  string `json:"username,omitzero"` // Not really used. Just there to help the user identify the context.

	AuthenticationType string `json:"authenticationType,omitzero"` // e.g., "apiKey", "rsaKeyFederated", "rsaKey"

	// For the type "apiKey".
	APIKey string `json:"apiKey,omitzero"`
	Email  string `json:"email,omitzero"`  // Not really used. Just there to help the user identify the context.
	UserID string `json:"userID,omitzero"` // Only used to identify when two contexts are the "same".

	// For the types "rsaKeyFederated" and "rsaKey".
	AccessToken string `json:"accessToken,omitzero"`
	PrivateKey  string `json:"privateKey,omitzero"`

	// For the type "rsaKeyFederated".
	IssuerURL string `json:"issuerURL,omitzero"`
	Subject   string `json:"subject,omitzero"`
	Audience  string `json:"audience,omitzero"`

	// For the type "rsaKey" and "rsaKeyFederated". Not really needed for
	// "rsaKeyFederated", but useful to know when two contexts are the "same".
	ClientID string `json:"clientID,omitzero"`
}

func deprecatedAuthCmd(_ string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "auth",
		SilenceErrors: true,
		SilenceUsage:  true,
		Hidden:        true,
		Deprecated:    "all auth subcommands are now available at root level. Use 'vcpctl login', 'vcpctl switch', 'vcpctl apikey', and 'vcpctl apiurl'",
	}
	cmd.AddCommand(authLoginCmd(""), authSwitchCmd(""), authAPIKeyCmd(""), authAPIURLCmd(""))
	return cmd
}

func loginCmd(groupID string) *cobra.Command {
	var apiURL, apiKey, contextName string
	cmd := &cobra.Command{
		Use:           "login [url]",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		Short:         "Authenticate to a CyberArk Certificate Manager, SaaS tenant with an API key.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant using an API key.

			You can provide the tenant UI URL (the URL you use to access the web interface in
			your browser) as a positional argument. If no URL is provided, you will be prompted
			to enter it.

			Note: The positional [url] argument is the tenant UI URL (e.g.,
			https://ui-stack-dev130.qa.venafi.io), not the API URL. The API URL will be
			automatically determined from the tenant URL.

			If you prefer avoiding prompts entirely, you can provide --api-key along with the
			tenant URL, or use --api-url and --api-key together to bypass the automatic API URL
			discovery.

			Alternatively, you can use the environment variables VEN_API_URL and VEN_API_KEY to
			provide the API URL and API key.

			For WIF authentication, use 'vcpctl login-wif'.
			For service account keypair authentication, use 'vcpctl login-keypair'.
		`),
		Example: undent.Undent(`
			# Interactive login with prompts:
			vcpctl login

			# Provide tenant URL, will prompt for API key:
			vcpctl login https://ui-stack-dev130.qa.venafi.io

			# Fully non-interactive with tenant URL and API key:
			vcpctl login https://ui-stack-dev130.qa.venafi.io --api-key <key>

			# Bypass tenant URL to API URL conversion (for advanced use):
			vcpctl login --api-url https://api-stack-dev130.qa.venafi.io --api-key <key>
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			anonymousClient, err := api.NewAnonymousClient()
			if err != nil {
				return err
			}
			warnIgnoredLoginEnvVars()

			tenantURLArgProvided := len(args) > 0
			if tenantURLArgProvided {
				if apiURL != "" {
					logutil.Infof("⚠️  Warning: --api-url will be ignored because the tenant URL positional argument is provided. The API URL will be determined automatically from the tenant URL.")
				}
				return loginWithTenantURL(cmd.Context(), anonymousClient.Client, args[0], apiKey, contextName)
			}

			if apiURL != "" {
				return loginWithAPIURL(cmd.Context(), apiURL, apiKey, contextName)
			}

			return loginInteractive(cmd.Context(), apiKey, contextName)
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "The API URL of the CyberArk Certificate Manager, SaaS tenant. If not provided, you will be prompted to enter it")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "The API key for the CyberArk Certificate Manager, SaaS tenant. If not provided, you will be prompted to enter it")
	cmd.Flags().StringVar(&contextName, "context", "", "Context name to create or update")

	return cmd
}

// The 'cl' must be an unauthenticated client.
func loginWithTenantURL(ctx context.Context, anonymousClient api.HttpRequestDoer, tenantURL, apiKey, contextName string) error {
	tenantURL = normalizeURL(tenantURL)
	if tenantURL == "" {
		return fmt.Errorf("tenant URL cannot be empty")
	}

	info, err := api.GetTenantInfo(anonymousClient, tenantURL)
	if err != nil {
		return err
	}

	current := Auth{
		AuthenticationType: "apiKey",
		TenantURL:          tenantURL,
		TenantID:           info.TenantID,
		APIURL:             info.APIURL,
	}

	if apiKey != "" {
		if err := populateFromAPIKey(ctx, &current, apiKey); err != nil {
			return err
		}
	} else {
		if err := promptForAPIKey(ctx, &current); err != nil {
			return err
		}
	}

	return saveLoginAndReport(ctx, current, contextName)
}

func loginWithAPIURL(ctx context.Context, apiURL, apiKey, contextName string) error {
	apiURL = normalizeURL(apiURL)
	if apiURL == "" {
		return fmt.Errorf("API URL cannot be empty")
	}

	current := Auth{
		AuthenticationType: "apiKey",
		APIURL:             apiURL,
	}

	if apiKey != "" {
		if err := populateFromAPIKey(ctx, &current, apiKey); err != nil {
			return err
		}
	} else {
		if err := promptForAPIKey(ctx, &current); err != nil {
			return err
		}
	}

	return saveLoginAndReport(ctx, current, contextName)
}

func loginInteractive(ctx context.Context, apiKey, contextName string) error {
	conf, err := loadFileConf(ctx)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	current, _ := currentFrom(conf)

	anonClient, err := api.NewAnonymousClient()
	if err != nil {
		return fmt.Errorf("while creating unauthenticated API client: %w", err)
	}

	if len(conf.ToolContexts) > 1 && contextName == "" {
		if current.Name != "" {
			fmt.Printf("\n📝  Re-logging in using current context '%s'.\n", displayContextForSelection(current))

			if len(conf.ToolContexts) > 1 {
				fmt.Println("\nOther available contexts:")
				for _, toolctx := range conf.ToolContexts {
					if toolctx.Name != current.Name {
						displayContextForSelection(toolctx)
					}
				}
				fmt.Printf("\n💡  To log in to a different context, use: vcpctl login --context <name>\n\n")
			}
		}
	}

	skipTenantPrompt := false
	if current.TenantURL != "" && current.APIURL != "" && current.APIKey != "" {
		cl, err := api.NewAPIKeyClient(current.APIURL, current.APIKey)
		if err != nil {
			return fmt.Errorf("while creating API client: %w", err)
		}
		_, tenantURL, err := api.SelfCheckAPIKey(ctx, cl)
		if err == nil {
			fmt.Printf("\n%s\n\n", successStyle.Render("✅  You are already logged in with the context "+displayContextForSelection(current)))

			type loginChoice string
			const (
				loginChoiceRelogin loginChoice = "relogin"
				loginChoiceNew     loginChoice = "new"
			)
			choice := loginChoiceRelogin
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[loginChoice]().
						Options(
							huh.NewOption("Edit the current context's API key", loginChoiceRelogin),
							huh.NewOption("Log in using a new context", loginChoiceNew),
						).
						Value(&choice),
				).Title("How would you like to log in?"),
			)
			if err := form.RunWithContext(ctx); err != nil {
				return fmt.Errorf("prompt cancelled: %w", err)
			}

			if choice == loginChoiceRelogin {
				skipTenantPrompt = true
				current.TenantURL = tenantURL
			} else {
				current = Auth{}
			}
			fmt.Println()
		}
	}

	current.AuthenticationType = "apiKey"

	if !skipTenantPrompt {
		if err := promptForTenantURL(ctx, anonClient.Client, &current); err != nil {
			return err
		}
		fmt.Println()
	} else if current.APIURL == "" {
		return fmt.Errorf("current context is missing an API URL; please specify --api-url or a tenant URL")
	}

	if apiKey != "" {
		if err := populateFromAPIKey(ctx, &current, apiKey); err != nil {
			return err
		}
	} else {
		if err := promptForAPIKey(ctx, &current); err != nil {
			return err
		}
	}

	return saveLoginAndReport(ctx, current, contextName)
}

func loginWifCmd(groupID string) *cobra.Command {
	var contextName string
	cmd := &cobra.Command{
		Use:           "login-wif <json-file>",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		Short:         "Authenticate to a CyberArk Certificate Manager, SaaS tenant using WIF.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant using Workload Identity Federation (WIF).

			This command expects a JSON file containing the WIF credentials from 'vcpctl sa gen wif'.
			Use '-' to read the JSON from stdin.
		`),
		Example: undent.Undent(`
			# WIF login from file:
			vcpctl login-wif wif-credentials.json

			# WIF login from stdin:
			vcpctl sa gen wif my-sa -ojson | vcpctl login-wif -
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			return loginWithWIFJSON(cmd.Context(), args[0], contextName)
		},
	}
	cmd.Flags().StringVar(&contextName, "context", "", "Context name to create or update")
	return cmd
}

// authLoginCmd is a deprecated alias for loginCmd
func authLoginCmd(groupID string) *cobra.Command {
	cmd := loginCmd(groupID)
	cmd.Deprecated = "use 'vcpctl login' instead; 'vcpctl auth login' will be removed in a future release"
	return cmd
}

func apikeyCmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "apikey",
		Short:         "Prints the API key for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIKey := os.Getenv("VEN_API_KEY")
			flagAPIKey, _ := cmd.Flags().GetString("api-key")
			if envAPIKey != "" || flagAPIKey != "" {
				logutil.Debugf("$VEN_API_KEY or --api-key has been passed but will be ignored. This command only prints the API key from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			auth, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl login\n")
			}
			fmt.Println(auth.APIKey)
			return nil
		},
	}
	return cmd
}

// authAPIKeyCmd is a deprecated alias for apikeyCmd
func authAPIKeyCmd(groupID string) *cobra.Command {
	cmd := apikeyCmd(groupID)
	cmd.Use = "api-key"
	cmd.Deprecated = "use 'vcpctl apikey' instead; 'vcpctl auth api-key' will be removed in a future release"
	return cmd
}

func apiurlCmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "apiurl",
		Short:         "Prints the API URL for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIURL := os.Getenv("VEN_API_URL")
			flagAPIURL, _ := cmd.Flags().GetString("api-url")
			if envAPIURL != "" || flagAPIURL != "" {
				logutil.Debugf("$VEN_API_URL or --api-url has been passed but will be ignored. This command only prints the API URL from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			auth, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl login\n")
			}
			fmt.Println(auth.APIURL)
			return nil
		},
	}
	return cmd
}

// authAPIURLCmd is a deprecated alias for apiurlCmd
func authAPIURLCmd(groupID string) *cobra.Command {
	cmd := apiurlCmd(groupID)
	cmd.Use = "api-url"
	cmd.Deprecated = "use 'vcpctl apiurl' instead; 'vcpctl auth api-url' will be removed in a future release"
	return cmd
}

func tenantidCmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "tenantid",
		Short:         "Prints the tenant ID for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIURL := os.Getenv("VEN_API_URL")
			envAPIKey := os.Getenv("VEN_API_KEY")
			flagAPIURL, _ := cmd.Flags().GetString("api-url")
			flagAPIKey, _ := cmd.Flags().GetString("api-key")
			flagContext, _ := cmd.Flags().GetString("context")

			if envAPIKey != "" || flagAPIKey != "" || envAPIURL != "" || flagAPIURL != "" || flagContext != "" {
				logutil.Debugf("$VEN_API_URL, $VEN_API_KEY, --api-url, --api-key, or --context has been passed but will be ignored. This command only prints the tenant ID from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			ctx, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl login\n")
			}

			if ctx.TenantID == "" {
				logutil.Debugf("Tenant ID not found in config. This might be an older config file. Please re-login with 'vcpctl login'.")
				return fmt.Errorf("tenant ID not available")
			}

			fmt.Println(ctx.TenantID)
			return nil
		},
	}
	return cmd
}

func switchCmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch [context-name]",
		Short: "Switch to a context",
		Long: undent.Undent(`
			Switch to a different context. A context holds the authentication
			information: server URL, API key, etc. It allows you to easily switch
			between different CyberArk Certificate Manager SaaS tenants, as well
			as different users within the same tenant.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			if len(conf.ToolContexts) == 0 {
				return fmt.Errorf("no contexts found in configuration. Please run:\n    vcpctl login")
			}

			if len(args) > 0 {
				// If a context name/URL is provided, we try to find it in the
				// configuration.
				contextInput := args[0]
				ctx, ok := resolveContext(conf, contextInput)
				if !ok {
					return errutil.Fixable(fmt.Errorf("context '%s' not found in configuration. Please run `vcpctl login` to add it.", contextInput))
				}
				conf.CurrentContext = ctx.Name
				return saveFileConf(conf)
			}

			// If no context is provided, we prompt the user to select one.
			current, _ := currentFrom(conf)

			var opts []huh.Option[ToolContext]
			for _, toolctx := range conf.ToolContexts {
				opts = append(opts, huh.Option[ToolContext]{
					Value: toolctx,
					Key:   displayContextForSelection(toolctx),
				})
			}

			var fields []huh.Field
			if os.Getenv("VEN_API_URL") != "" || os.Getenv("VEN_API_KEY") != "" {
				fields = append(fields, huh.NewNote().
					Description("⚠️  WARNING: the env var VEN_API_URL or VEN_API_KEY is set.\n⚠️  WARNING: This means that all of the other commands will ignore what's set by 'vcpctl login'."),
				)
			}
			fields = append(fields, huh.NewSelect[ToolContext]().
				Options(opts...).
				Description("Select the context you want to switch to.").
				Value(&current),
			)
			err = huh.NewForm(huh.NewGroup(fields...)).RunWithContext(cmd.Context())
			if err != nil {
				return fmt.Errorf("selecting context: %w", err)
			}
			conf.CurrentContext = current.Name
			return saveFileConf(conf)
		},
	}

	return cmd
}

// The fields in the context may be sparse. We need to display something like:
//
//	  foo (type: apiKey, url: https://glow-in-the-dark.venafi.cloud, email: mael.valais@venafi.com)
//	  bar (type: rsaKey, username: firefly)
//	> baz (type: rsaKeyFederated, service account: 12345678-90ab-cdef-1234-567890abcdef)
//
// Sometimes, Username or Email may be empty. Let's skip the missing fields.
func displayContextForSelection(toolctx ToolContext) string {
	var parts []string
	if toolctx.AuthenticationType != "" {
		parts = append(parts, fmt.Sprintf("type: %s", toolctx.AuthenticationType))
	}
	if toolctx.TenantURL != "" {
		parts = append(parts, fmt.Sprintf("url: %s", toolctx.TenantURL))
	}
	if toolctx.Email != "" {
		parts = append(parts, fmt.Sprintf("email: %s", toolctx.Email))
	} else if toolctx.Username != "" && toolctx.AuthenticationType == "apiKey" {
		parts = append(parts, fmt.Sprintf("username: %s", toolctx.Username))
	} else if toolctx.Username != "" && toolctx.AuthenticationType != "apiKey" {
		parts = append(parts, fmt.Sprintf("service account: %s", toolctx.Username))
	} else if toolctx.ClientID != "" {
		parts = append(parts, fmt.Sprintf("service account: %s", toolctx.ClientID))
	}
	return fmt.Sprintf("%s (%s)", toolctx.Name, strings.Join(parts, ", "))
}

// authSwitchCmd is a deprecated alias for switchCmd
func authSwitchCmd(groupID string) *cobra.Command {
	cmd := switchCmd(groupID)
	cmd.Deprecated = "use 'vcpctl switch' instead; 'vcpctl auth switch' will be removed in a future release"
	return cmd
}

func sameContext(a, b ToolContext) bool {
	switch {
	case a.TenantURL != b.TenantURL:
		return false
	case a.AuthenticationType != b.AuthenticationType:
		return false
	case a.AuthenticationType == "apiKey":
		return a.Email == b.Email && a.UserID == b.UserID
	case a.AuthenticationType == "rsaKeyFederated":
		return a.ClientID == b.ClientID
	case a.AuthenticationType == "rsaKey":
		return a.ClientID == b.ClientID
	}
	return false
}

// Meant for the `vcpctl login*` commands. The provided toolctx's name can be
// left empty, in which case a name will be derived. The contextFlag can also be
// left empty. Returns the name of the saved context.
func saveCurrentContext(ctx context.Context, target ToolContext, contextFlag string) (ToolContext, error) {
	conf, err := loadFileConf(ctx)
	if err != nil {
		return ToolContext{}, fmt.Errorf("loading configuration: %w", err)
	}

	// If --context flag was provided, use that name directly.
	var name string
	if contextFlag != "" {
		name = contextFlag
	} else {
		// No --context was passed, let's figure out if there is an existing
		// context that is similar to the current one.
		for _, existingCtx := range conf.ToolContexts {
			if sameContext(existingCtx, target) {
				name = existingCtx.Name
			}
		}
	}
	if name == "" {
		name = generateContextName(target, conf.ToolContexts)
	}
	target.Name = name

	if target.Name == "" {
		return ToolContext{}, errors.New("internal error: context name derivation failed")
	}

	// Find the context.
	var existing int = -1
	for i, existingCtx := range conf.ToolContexts {
		if existingCtx.Name == target.Name {
			existing = i
			break
		}
	}
	if existing == -1 {
		// Doesn't exist in the config yet, let's add it.
		conf.ToolContexts = append(conf.ToolContexts, target)
		conf.CurrentContext = target.Name
		return target, saveFileConf(conf)
	}

	existingCtx := conf.ToolContexts[existing]

	// Let's make sure the user know if this context didn't have the same
	// authentication type before.
	if existingCtx.AuthenticationType != "" &&
		existingCtx.AuthenticationType != target.AuthenticationType {
		fmt.Printf("⚠️  Warning: Changing authentication type from '%s' to '%s' for context '%s'\n",
			existingCtx.AuthenticationType, target.AuthenticationType, target.Name)
		fmt.Printf("To keep existing context unchanged, use: vcpctl login --context <new-name>\n")

		proceed, err := promptYesNo(ctx, "Continue?")
		if err != nil {
			return ToolContext{}, fmt.Errorf("prompting for confirmation: %w", err)
		}
		if !proceed {
			return ToolContext{}, fmt.Errorf("login cancelled")
		}
	}

	conf.CurrentContext = target.Name
	conf.ToolContexts[existing] = target
	return target, saveFileConf(conf)
}

// Backwards compatibility alias.
func saveCurrentTenant(ctx context.Context, toolctx ToolContext) error {
	_, err := saveCurrentContext(ctx, toolctx, "")
	return err
}

// generateContextName derives a Docker-style context name (e.g., "clever-alpaca") from
// the tenant URL domain and user/service account ID.
//
// For API key type: Uses domain + user ID
// For service account (rsaKeyFederated or rsaKey): Uses domain + service account ID
//
// The name generation is deterministic based on the seed, so the same tenant/user
// combination will always produce the same name.
func generateContextName(toolctx ToolContext, existing []ToolContext) string {
	alreadyUsed := func(name string) bool {
		for _, ctx := range existing {
			if ctx.Name == name {
				return true
			}
		}
		return false
	}

	if toolctx.TenantURL != "" {
		// Attempt 1: just the domain name. Example:
		//  glow-in-the-dark.venafi.cloud
		contextName := extractDomainFromURL(toolctx.TenantURL)
		if !alreadyUsed(contextName) {
			return contextName
		}

		// Attempt 2: add a number. Example:
		//  glow-in-the-dark.venafi.cloud.2
		for i := 2; i < 1000; i++ {
			candidate := fmt.Sprintf("%s.%d", contextName, i)
			if !alreadyUsed(candidate) {
				return candidate
			}
		}
	} else if toolctx.ClientID != "" {
		// If no tenant URL, fall back to "sa-<id>".
		return "sa" + toolctx.ClientID
	} else if toolctx.UserID != "" {
		// If no tenant URL or client ID, fall back to "user-<id>".
		return "user-" + toolctx.UserID
	}

	panic("why do you have so many contexts? I give up")
}

// extractDomainFromURL extracts the domain name from a given URL.
func extractDomainFromURL(tenantURL string) string {
	url := tenantURL
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.SplitN(url, "/", 2)
	return parts[0]
}

// ensureUniqueName ensures the name is unique by appending hash suffix if collision exists
func ensureUniqueName(baseName, seed string, existingContexts []ToolContext) string {
	nameExists := func(name string) bool {
		for _, ctx := range existingContexts {
			if ctx.Name == name {
				return true
			}
		}
		return false
	}

	if !nameExists(baseName) {
		return baseName
	}

	// If collision, append first 4 chars of hash
	h := sha256.Sum256([]byte(seed))
	suffix := fmt.Sprintf("%x", h[:2]) // first 4 hex chars
	return baseName + "-" + suffix
}

// resolveContext find a context by name.
func resolveContext(conf FileConf, contextInput string) (ToolContext, bool) {
	normalized := strings.TrimSpace(contextInput)

	for _, ctx := range conf.ToolContexts {
		if ctx.Name == normalized {
			return ctx, true
		}
	}

	return ToolContext{}, false
}

// For now we aren't yet using ~/.config/vcpctl.yml.
type ToolConf struct {
	APIURL      string `json:"apiURL"`
	APIKey      string `json:"apiKey"`
	AccessToken string `json:"accessToken"`

	AuthenticationType string `json:"authenticationType"`
	ClientID           string `json:"clientID"`
	PrivateKey         string `json:"privateKey"`
	TenantID           string `json:"tenantID"`
	IssuerURL          string `json:"issuerURL"`
	Subject            string `json:"subject"`
	Audience           string `json:"audience"`
	ContextName        string `json:"contextName"`
}

func newAPIClient(conf ToolConf) (*api.Client, error) {
	if conf.AccessToken != "" {
		return newAccessTokenAPIClient(conf)
	}
	if conf.APIKey != "" {
		return api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
	}

	return nil, fmt.Errorf("programmer mistake: no authentication method available, AccessToken and APIKey are both empty in ToolConf")
}

// This must be used by all other commands to get the API key and API URL.
func getToolConfig(cmd *cobra.Command) (ToolConf, error) {
	// This CLI used to support the APIKEY and APIURL env vars, but it no longer
	// does since VEN_API_KEY and VEN_API_URL are the standard in other tools
	// such as venctl. Let's give a warning if the old ones are used.
	if os.Getenv("APIKEY") != "" {
		logutil.Infof("⚠️  Warning: the env var APIKEY is set but it is no longer read by this tool. Please use VEN_API_KEY instead.")
	}
	if os.Getenv("APIURL") != "" {
		logutil.Infof("⚠️  Warning: the env var APIURL is set but it is no longer read by this tool. Please use VEN_API_URL instead.")
	}

	envAPIURL := os.Getenv("VEN_API_URL")
	envAPIKey := os.Getenv("VEN_API_KEY")
	flagAPIURL, _ := cmd.Flags().GetString("api-url")
	flagAPIKey, _ := cmd.Flags().GetString("api-key")
	flagContext, _ := cmd.Flags().GetString("context")

	// If any of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set, we
	// don't use the configuration file.
	if flagAPIKey != "" || envAPIKey != "" || flagAPIURL != "" || envAPIURL != "" {
		logutil.Debugf("one of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set. The configuration file at ~/%s won't be loaded", configPath)

		// --context flag is ignored when --api-key or --api-url is used
		if flagContext != "" {
			logutil.Debugf("--context flag is ignored when --api-key or --api-url is provided")
		}

		// Priority: $APIURL > --api-url.
		apiURL := envAPIURL
		if apiURL == "" {
			apiURL = flagAPIURL
		}

		apiKey := envAPIKey
		if apiKey == "" {
			apiKey = flagAPIKey
		}

		if apiURL == "" && apiKey != "" {
			return ToolConf{}, fmt.Errorf("you have set the API key using $VEN_API_KEY or --api-key, but you haven't set the API URL. Please use --api-url or $VEN_API_URL. If you aren't sure, unset VEN_API_KEY and remove --api-key, then use `vcpctl login` which will figure it out for you.")
		}
		if apiKey == "" && apiURL != "" {
			return ToolConf{}, fmt.Errorf("you have set the API URL using $VEN_API_URL or --api-url, but you haven't set the API key. Please use --api-key or $VEN_API_KEY. If you aren't sure, unset VEN_API_URL and remove --api-url, then use `vcpctl login` which will figure it out for you.")
		}

		return ToolConf{
			APIURL: apiURL,
			APIKey: apiKey,

			AccessToken:        "",
			AuthenticationType: "apiKey",
		}, nil
	}

	logutil.Debugf("none of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set, using the configuration file at ~/%s", configPath)

	conf, err := loadFileConf(cmd.Context())
	if err != nil {
		return ToolConf{}, fmt.Errorf("loading configuration: %w", err)
	}

	var current ToolContext
	var ok bool

	// If --context flag is provided, use it to override the current context.
	if flagContext != "" {
		current, ok = resolveContext(conf, flagContext)
		if !ok {
			return ToolConf{}, fmt.Errorf("context '%s' not found in configuration. Available contexts can be listed with 'vcpctl switch'. Log in to a new tenant with 'vcpctl login'.", flagContext)
		}
		logutil.Debugf("Using context '%s' (tenant URL: %s, ID: %s) from --context flag", current.Name, current.TenantURL, current.TenantID)
	} else {
		// Find the current context from config.
		current, ok = currentFrom(conf)
		if !ok {
			if len(conf.ToolContexts) > 0 {
				return ToolConf{}, fmt.Errorf("no context set, but %d contexts exist. Run this to select one of them:\n	vcpctl switch", len(conf.ToolContexts))
			}

			return ToolConf{}, fmt.Errorf("not logged in. To authenticate, run:\n    vcpctl login")
		}
	}

	// Let's make sure the URL never contains a trailing slash.
	current.APIURL = strings.TrimRight(current.APIURL, "/")
	if current.APIKey == "" && current.AccessToken == "" {
		return ToolConf{}, fmt.Errorf("not logged in. To authenticate, run:\n    vcpctl login")
	}

	return ToolConf{
		APIURL:             current.APIURL,
		APIKey:             current.APIKey,
		AccessToken:        current.AccessToken,
		AuthenticationType: current.AuthenticationType,
		ClientID:           current.ClientID,
		PrivateKey:         current.PrivateKey,
		TenantID:           current.TenantID,
		IssuerURL:          current.IssuerURL,
		Subject:            current.Subject,
		Audience:           current.Audience,
		ContextName:        current.Name,
	}, nil
}

// Only meant to be used by the `auth` commands.
func loadFileConf(ctx context.Context) (FileConf, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FileConf{}, fmt.Errorf("while getting user's home directory: %w", err)
	}

	f, err := os.Open(path.Join(home, configPath))
	switch {
	case os.IsNotExist(err):
		return FileConf{}, nil
	case err != nil:
		return FileConf{}, fmt.Errorf("while opening ~/%s: %w", configPath, err)
	default:
		// All good, continue below.
	}

	bytes, err := cancellablereader.ReadAllWithContext(ctx, f)
	if err != nil {
		return FileConf{}, fmt.Errorf("while reading ~/%s: %w", configPath, err)
	}

	// If the file is empty, return an empty config.
	if len(bytes) == 0 {
		return FileConf{}, nil
	}

	var conf FileConf

	err = yaml.Unmarshal(bytes, &conf)
	if err != nil {
		return FileConf{}, fmt.Errorf("while decoding ~/%s: %w", configPath, err)
	}

	// Check if this is an old format config that needs conversion Old format
	// has "auths" field, new format has "contexts" field.
	if len(conf.ToolContexts) == 0 {
		// Try to unmarshal as old format
		var oldConf OldFileConf
		err = yaml.Unmarshal(bytes, &oldConf)
		if err == nil && len(oldConf.Auths) > 0 {
			logutil.Debugf("Detected old config format, converting to new format")
			conf = convertOldToNewConfig(oldConf)

			// Automatically save the converted config
			if err := saveFileConf(conf); err != nil {
				logutil.Debugf("Warning: failed to save converted config: %v", err)
			} else {
				logutil.Infof("✅  Configuration automatically converted to new format")
			}
		}
	}

	return conf, nil
}

// Only meant to be used by the `auth` commands.
func saveFileConf(conf FileConf) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("while getting user's home directory: %w", err)
	}

	f, err := os.Create(path.Join(home, configPath))
	if err != nil {
		return fmt.Errorf("while creating ~/%s: %w", configPath, err)
	}
	defer f.Close()

	if err := yaml.NewEncoder(f).Encode(conf); err != nil {
		return fmt.Errorf("while encoding ~/%s: %w", configPath, err)
	}

	return nil
}

// Only meant to be used by the `auth login` command.
func currentFrom(conf FileConf) (ToolContext, bool) {
	if conf.CurrentContext != "" {
		for _, ctx := range conf.ToolContexts {
			if ctx.Name == conf.CurrentContext {
				return ctx, true
			}
		}
	}

	return ToolContext{}, false
}

// Legacy type for backward compatibility during migration (not used in new
// code).
type Auth = ToolContext

// OldFileConf represents the deprecated config structure used before the
// current-context/contexts redesign. This is kept for automatic migration.
type OldFileConf struct {
	CurrentURL string    `yaml:"currentURL"` // Corresponds to the UI URL of the current tenant.
	Auths      []OldAuth `yaml:"auths"`
}

// OldAuth represents the deprecated auth structure.
type OldAuth struct {
	URL      string `yaml:"url"`      // The UI URL of the tenant, e.g., https://ven-cert-manager-uk.venafi.cloud
	APIURL   string `yaml:"apiURL"`   // The API URL of the tenant, e.g., https://api.uk.venafi.cloud
	APIKey   string `yaml:"apiKey"`   // The API key for authentication
	TenantID string `yaml:"tenantID"` // The tenant ID (company ID)
}

// convertOldToNewConfig converts the old config format to the new one.
func convertOldToNewConfig(old OldFileConf) FileConf {
	var newConf FileConf

	// Convert current URL to current context name
	// The current URL becomes the name of the current context
	if old.CurrentURL != "" {
		newConf.CurrentContext = old.CurrentURL
	}

	// Convert each old auth to a new context
	for _, oldAuth := range old.Auths {
		newCtx := ToolContext{
			Name:               oldAuth.URL, // Use the URL as the context name
			TenantURL:          oldAuth.URL,
			APIURL:             oldAuth.APIURL,
			AuthenticationType: "apiKey",
			APIKey:             oldAuth.APIKey,
			TenantID:           oldAuth.TenantID,
			// Email and UserID are not in the old format, so they remain empty
		}
		newConf.ToolContexts = append(newConf.ToolContexts, newCtx)
	}

	return newConf
}

// Styles for prompts.
var (
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("red"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("green"))
	subtleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func promptYesNo(ctx context.Context, question string) (bool, error) {
	fmt.Printf("%s %s: ", question, subtleStyle.Render("(y/n)"))

	// Try to set raw mode for immediate single-character input.
	oldState, err := term.MakeRaw(os.Stdin.Fd())
	if err != nil {
		// Fallback to line-based input if raw mode not available.
		stdin := bufio.NewReader(cancellablereader.New(ctx, os.Stdin))
		input, err := stdin.ReadString('\n')
		if err != nil {
			return false, err
		}
		input = strings.TrimSpace(strings.ToLower(input))
		switch input {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Println(errorStyle.Render("❌  Please enter 'y' or 'n'"))
		return promptYesNo(ctx, question)
	}
	defer term.Restore(os.Stdin.Fd(), oldState)

	// Read single character without waiting for Enter.
	stdin := cancellablereader.New(ctx, os.Stdin)
	for {
		var buf [1]byte
		_, err = stdin.Read(buf[:])
		if err != nil {
			term.Restore(os.Stdin.Fd(), oldState)
			return false, err
		}

		char := strings.ToLower(string(buf[0]))

		switch char {
		case "y":
			fmt.Println("y")
			return true, nil
		case "n":
			fmt.Println("n")
			return false, nil
		}
		// Invalid input; let's continue reading without showing an error
		// message for better UX.
	}
}

type validationDoneMsg struct {
	err error
}

type promptInputModel struct {
	prompt     string
	input      textinput.Model
	spinner    spinner.Model
	validating bool
	err        error
	validate   func(string) error
	canceled   bool
}

func (m promptInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m promptInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.canceled = true
			return m, tea.Quit
		case "enter":
			if m.validating {
				return m, nil
			}
			if m.validate == nil {
				return m, tea.Quit
			}
			value := strings.TrimSpace(m.input.Value())
			m.validating = true
			m.err = nil
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
				return validationDoneMsg{err: m.validate(value)}
			})
		}
	case spinner.TickMsg:
		if m.validating {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	case validationDoneMsg:
		m.validating = false
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		return m, tea.Quit
	}

	if m.validating {
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m promptInputModel) View() tea.View {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(m.prompt))
	b.WriteString("\n")
	b.WriteString(m.input.View())
	if m.validating {
		b.WriteString("\n")
		b.WriteString(subtleStyle.Render(m.spinner.View()))
		b.WriteString(subtleStyle.Render(" validating..."))
	}
	if m.err != nil {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render("❌  " + m.err.Error()))
	}
	return tea.NewView(b.String())
}

func promptString(ctx context.Context, prompt, defaultVal string, validate func(ctx context.Context, input string) error) (string, error) {
	input := textinput.New()
	input.SetValue(strings.TrimSpace(defaultVal))
	input.CharLimit = 0
	input.Prompt = "› "
	// input.PromptStyle = subtleStyle
	styles := input.Styles()
	styles.Cursor.Shape = tea.CursorBlock
	styles.Cursor.Blink = true
	styles.Cursor.Color = lipgloss.Color("7")
	input.SetStyles(styles)
	input.Focus()

	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = subtleStyle

	var validator func(string) error
	if validate != nil {
		validator = func(value string) error {
			return validate(ctx, strings.TrimSpace(value))
		}
	}

	model := promptInputModel{
		prompt:   prompt,
		input:    input,
		spinner:  sp,
		validate: validator,
	}

	result, err := tea.NewProgram(model).Run()
	if err != nil {
		return "", err
	}
	finalModel := result.(promptInputModel)
	if finalModel.canceled {
		return "", context.Canceled
	}

	return strings.TrimSpace(finalModel.input.Value()), nil
}

func warnIgnoredLoginEnvVars() {
	var set []string
	for _, name := range []string{"VEN_API_URL", "VEN_API_KEY", "APIURL", "APIKEY"} {
		if os.Getenv(name) != "" {
			set = append(set, name)
		}
	}
	if len(set) == 0 {
		return
	}
	logutil.Infof("⚠️  Warning: %s set. vcpctl login ignores these environment variables.", strings.Join(set, ", "))
}

func normalizeURL(raw string) string {
	url := strings.TrimRight(strings.TrimSpace(raw), "/")
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		url = "https://" + url
	}
	return url
}

func populateFromAPIKey(ctx context.Context, current *Auth, apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}
	if current.APIURL == "" {
		return fmt.Errorf("API URL is required to validate the API key")
	}
	cl, err := api.NewAPIKeyClient(current.APIURL, apiKey)
	if err != nil {
		return fmt.Errorf("while creating API client: %w", err)
	}
	resp, tenantURL, err := api.SelfCheckAPIKey(ctx, cl)
	if err != nil {
		return err
	}
	current.APIKey = apiKey
	current.TenantID = resp.Company.Id.String()
	current.TenantURL = tenantURL
	current.Email = resp.User.EmailAddress
	current.UserID = resp.User.Id.String()
	current.Username = resp.User.Username
	return nil
}

// Unauthenticated client is fine here.
func promptForTenantURL(ctx context.Context, anonClient api.HttpRequestDoer, current *Auth) error {
	fmt.Println(subtleStyle.Render("Enter the URL you use to log into CyberArk Certificate Manager, SaaS"))
	fmt.Println(subtleStyle.Render("Example: https://ven-cert-manager-uk.venafi.cloud"))
	fmt.Println()

	tenantURL, err := promptString(ctx, "Tenant URL: ", current.TenantURL, func(ctx context.Context, input string) error {
		input = normalizeURL(input)
		if input == "" {
			return fmt.Errorf("tenant URL cannot be empty")
		}

		tenant, err := api.GetTenantInfo(anonClient, input)
		if err != nil {
			return err
		}
		current.TenantURL = input
		current.TenantID = tenant.TenantID
		current.APIURL = tenant.APIURL
		return nil
	})
	if err != nil {
		return err
	}
	current.TenantURL = normalizeURL(tenantURL)
	return nil
}

func promptForAPIKey(ctx context.Context, current *Auth) error {
	if current.TenantURL != "" {
		fmt.Println(subtleStyle.Render("To get the API key, open: " + current.TenantURL + "/platform-settings/user-preferences?key=api-keys"))
		fmt.Println()
	}

	apiKeyInput, err := promptString(ctx, "API Key: ", current.APIKey, func(ctx context.Context, input string) error {
		return populateFromAPIKey(ctx, current, input)
	})
	if err != nil {
		return err
	}
	current.APIKey = strings.TrimSpace(apiKeyInput)
	return nil
}

func saveLoginAndReport(ctx context.Context, current Auth, contextName string) error {
	current, err := saveCurrentContext(ctx, current, contextName)
	if err != nil {
		return fmt.Errorf("saving configuration for %s: %w", current.TenantURL, err)
	}
	conf, err := loadFileConf(ctx)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	if currentCtx, ok := currentFrom(conf); ok {
		logutil.Infof("✅  You are now authenticated. Context name is %v", displayContextForSelection(currentCtx))
		return nil
	}
	logutil.Infof("✅  You are now authenticated.")
	return nil
}
