package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// This CLI stores its authentication information in ~/.config/vcpctl.yaml.
const configPath = ".config/vcpctl.yaml"

type FileConf struct {
	CurrentURL string `json:"currentURL"` // Corresponds to the UI URL of the current tenant.
	Auths      []Auth `json:"auths"`
}

type Auth struct {
	URL      string `json:"url"`    // The UI URL of the tenant, e.g., https://ven-cert-manager-uk.venafi.cloud
	APIURL   string `json:"apiURL"` // The API URL of the tenant, e.g., https://api.uk.venafi.cloud
	APIKey   string `json:"apiKey"`
	TenantID string `json:"tenantID"` // The tenant ID (company ID)
}

// Styles for prompts.
var (
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("red"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("green"))
	subtleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func promptYesNo(question string) (bool, error) {
	fmt.Printf("%s %s: ", question, subtleStyle.Render("(y/n)"))

	// Try to set raw mode for immediate single-character input.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Fallback to line-based input if raw mode not available.
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "yes" {
			return true, nil
		} else if input == "n" || input == "no" {
			return false, nil
		}
		fmt.Println(errorStyle.Render("✗ Please enter 'y' or 'n'"))
		return promptYesNo(question)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Read single character without waiting for Enter.
	for {
		var buf [1]byte
		_, err = os.Stdin.Read(buf[:])
		if err != nil {
			term.Restore(int(os.Stdin.Fd()), oldState)
			return false, err
		}

		char := strings.ToLower(string(buf[0]))

		if char == "y" {
			fmt.Println("y")
			return true, nil
		} else if char == "n" {
			fmt.Println("n")
			return false, nil
		}
		// Invalid input; let's continue reading without showing an error
		// message for better UX.
	}
}

func promptString(prompt string, validate func(string) error) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s", prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if validate != nil {
			if err := validate(input); err != nil {
				fmt.Println(errorStyle.Render("✗ " + err.Error()))
				continue
			}
		}
		return input, nil
	}
}

func promptSelect(title string, items []string) (int, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(title)
	for i, item := range items {
		fmt.Printf("  %d) %s\n", i+1, item)
	}
	for {
		fmt.Printf("\nSelect (1-%d): ", len(items))
		input, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		input = strings.TrimSpace(input)
		var choice int
		_, err = fmt.Sscanf(input, "%d", &choice)
		if err != nil || choice < 1 || choice > len(items) {
			fmt.Println(errorStyle.Render(fmt.Sprintf("✗ Please enter a number between 1 and %d", len(items))))
			continue
		}
		return choice - 1, nil
	}
}

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "auth",
		Short:         "Commands for authenticating and switching tenants.",
		Long:          "Manage authentication for CyberArk Certificate Manager, SaaS (formerly known as Venafi Control Plane and also known as Venafi Cloud), including login and switch.",
		SilenceErrors: true,
		SilenceUsage:  true,
		Hidden:        true,
		Deprecated:    "all auth subcommands are now available at root level. Use 'vcpctl login', 'vcpctl switch', 'vcpctl apikey', and 'vcpctl apiurl'",
	}
	cmd.AddCommand(authLoginCmd(), authSwitchCmd(), authAPIKeyCmd(), authAPIURLCmd())
	return cmd
}

// https://docs.venafi.cloud/vsatellite/r-VSatellite-deployNew-network-connections
var venafiRegions = []string{
	"https://api.venafi.cloud",
	"https://api.eu.venafi.cloud",
	"https://api.uk.venafi.cloud",
	"https://api.au.venafi.cloud",
	"https://api.ca.venafi.cloud",
	"https://api.sg.venafi.cloud",
}

func loginCmd() *cobra.Command {
	var apiURL, apiKey string
	cmd := &cobra.Command{
		Use:           "login [url]",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		Short:         "Authenticate to a CyberArk Certificate Manager, SaaS tenant.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant.

			You can provide the tenant UI URL (the URL you use to access the web interface in
			your browser) as a positional argument. If no URL is provided, you will be prompted
			to enter it.

			Note: The positional [url] argument is the tenant UI URL (e.g.,
			https://ui-stack-dev130.qa.venafi.io), not the API URL. The API URL will be
			automatically determined from the tenant URL.

			If you prefer avoiding prompts entirely, you can provide --api-key along with the
			tenant URL, or use --api-url and --api-key together to bypass the automatic API URL
			discovery.

			You can also use environment variables:
			    VEN_API_URL and VEN_API_KEY
		`),
		Example: undent.Undent(`
			# Provide tenant URL, will prompt for API key:
			vcpctl login https://ui-stack-dev130.qa.venafi.io

			# Fully non-interactive with tenant URL and API key:
			vcpctl login https://ui-stack-dev130.qa.venafi.io --api-key <key>

			# Bypass tenant URL to API URL conversion (for advanced use):
			vcpctl login --api-url https://api.venafi.cloud --api-key <key>
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for conflicts between positional URL argument and --api-url flag or env vars
			if len(args) > 0 {
				if apiURL != "" {
					logutil.Infof("⚠️  Warning: --api-url will be ignored because the tenant URL positional argument is provided. The API URL will be determined automatically from the tenant URL.")
					apiURL = "" // Clear it to use the tenant URL flow
				} else if os.Getenv("VEN_API_URL") != "" {
					logutil.Infof("⚠️  Warning: VEN_API_URL will be ignored because the tenant URL positional argument is provided. The API URL will be determined automatically from the tenant URL.")
				} else if os.Getenv("APIURL") != "" {
					logutil.Infof("⚠️  Warning: APIURL will be ignored because the tenant URL positional argument is provided. The API URL will be determined automatically from the tenant URL.")
				}
			}

			// If the user provided the --api-url and --api-key flags, we use
			// them. (But not if there are positional args - those take precedence)
			if len(args) == 0 && (apiURL != "" || apiKey != "") {
				if apiURL == "" {
					return fmt.Errorf("the --api-url flag is required when using the --api-key flag")
				}
				if apiKey == "" {
					return errutil.Fixable(fmt.Errorf("the --api-key flag is required when using the --api-url flag"))
				}

				// Normalize the API URL.
				apiURL = strings.TrimRight(apiURL, "/")
				if !strings.HasPrefix(apiURL, "https://") && !strings.HasPrefix(apiURL, "http://") {
					apiURL = "https://" + apiURL
				}

				cl, err := api.NewAPIKeyClient(apiURL, apiKey)
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				resp, err := api.SelfCheck(context.Background(), cl)
				if err != nil {
					return fmt.Errorf("while checking the API key's validity: %w", err)
				}

				// Workaround the fact that all devstacks are created with the
				// URL prefix "stack" instead of "ui-stack-devXXX". For now,
				// let's just use the API URL, which looks like this:
				//   https://api-dev210.qa.venafi.io
				// and turn it into the tenant URL, like this:
				//   https://ui-stack-dev210.qa.venafi.io
				//
				// See:
				// https://gitlab.com/venafi/vaas/test-enablement/vaas-auto/-/merge_requests/738/diffs#note_2579353788
				tenantURL := fmt.Sprintf("%s.venafi.cloud", resp.Company.UrlPrefix)
				if tenantURL == "stack" {
					tenantURL = apiURL
					tenantURL = strings.Replace(tenantURL, "api-", "ui-stack-", 1)
				}

				current := Auth{
					APIURL:   apiURL,
					APIKey:   apiKey,
					URL:      tenantURL,
					TenantID: resp.Company.Id.String(),
				}

				err = saveCurrentTenant(current)
				if err != nil {
					return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
				}

				logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.URL)
				return nil
			}

			// If the user provided a positional URL argument, use it instead of
			// prompting.
			if len(args) > 0 {
				tenantURL := args[0]

				// Normalize tenant URL.
				tenantURL = strings.TrimRight(tenantURL, "/")
				if !strings.HasPrefix(tenantURL, "https://") && !strings.HasPrefix(tenantURL, "http://") {
					tenantURL = "https://" + tenantURL
				}

				// Convert tenant URL to API URL.
				httpCl := http.Client{Transport: api.LogTransport}
				apiURLFromTenant, err := api.GetAPIURLFromTenantURL(httpCl, tenantURL)
				switch {
				case err == nil:
					// Success, continue below.
				case errors.As(err, &errutil.NotFound{}):
					return fmt.Errorf("URL '%s' doesn't seem to be a valid tenant. Please check the URL and try again.", tenantURL)
				default:
					return fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
				}

				current := Auth{
					URL:    tenantURL,
					APIURL: apiURLFromTenant,
				}

				// If --api-key was provided, use it; otherwise prompt for it.
				if apiKey != "" {
					current.APIKey = apiKey

					// Validate the API key.
					cl, err := api.NewAPIKeyClient(current.APIURL, current.APIKey)
					if err != nil {
						return fmt.Errorf("while creating API client: %w", err)
					}
					_, err = api.SelfCheck(context.Background(), cl)
					if err != nil {
						return fmt.Errorf("while checking the API key's validity: %w", err)
					}
				} else {
					// Prompt for API key.
					fmt.Println(subtleStyle.Render("To get the API key, open: " + current.URL + "/platform-settings/user-preferences?key=api-keys"))
					fmt.Println()

					apiKeyInput, err := promptString("API Key: ", func(input string) error {
						if input == "" {
							return fmt.Errorf("API key cannot be empty")
						}

						// Remove extraneous spaces before and after the user's
						// input for convenience.
						input = strings.TrimSpace(input)

						if len(input) != 36 {
							return fmt.Errorf("API key must be 36 characters long")
						}

						cl, err := api.NewAPIKeyClient(current.APIURL, input)
						if err != nil {
							return fmt.Errorf("while creating API client: %w", err)
						}

						resp, err := api.SelfCheck(context.Background(), cl)
						if err != nil {
							return err
						}
						current.TenantID = resp.Company.Id.String()
						return nil
					})
					if err != nil {
						return err
					}
					current.APIKey = apiKeyInput
				}

				err = saveCurrentTenant(current)
				if err != nil {
					return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
				}

				logutil.Infof("\n%s\n", successStyle.Render("✓ You are now authenticated to tenant '"+current.URL+"'."))
				return nil
			}

			// Load the current configuration.
			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			current, _ := currentFrom(conf)

			// Let the user know if they are already authenticated.
			skipTenantPrompt := false
			if current.URL != "" {
				cl, err := api.NewAPIKeyClient(current.APIURL, current.APIKey)
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				_, err = api.SelfCheck(context.Background(), cl)
				if err == nil {
					fmt.Printf("\n%s\n\n", successStyle.Render("✓ You are already logged in to "+current.URL))

					// Ask if they want to add a new tenant or re-login to existing one
					addNew, err := promptYesNo("Do you want to add a new tenant?")
					if err != nil {
						return fmt.Errorf("prompt cancelled: %w", err)
					}

					if !addNew {
						relogin, err := promptYesNo("Do you want to re-login to " + current.URL + "?")
						if err != nil {
							return fmt.Errorf("prompt cancelled: %w", err)
						}
						if !relogin {
							fmt.Println("\nLogin cancelled.")
							return nil
						}
						// If re-login, skip the tenant URL prompt
						skipTenantPrompt = true
					} else {
						// If adding new tenant, clear the current URL so they enter a new one
						current = Auth{}
					}
					fmt.Println() // Add spacing
				}
			}

			if os.Getenv("APIURL") != "" || os.Getenv("APIKEY") != "" {
				fmt.Println(errorStyle.Render("⚠  WARNING: the env var APIURL or APIKEY is set."))
				fmt.Println(errorStyle.Render("⚠  WARNING: This means that all of the other commands will ignore what's set by 'vcpctl login'."))
				fmt.Println()
			}

			// Prompt for Tenant URL (skip if re-logging in)
			if !skipTenantPrompt {
				fmt.Println(subtleStyle.Render("Enter the URL you use to log into CyberArk Certificate Manager, SaaS"))
				fmt.Println(subtleStyle.Render("Example: https://ven-cert-manager-uk.venafi.cloud"))
				fmt.Println()

				tenantURL, err := promptString("Tenant URL: ", func(input string) error {
					// Normalize tenant URL
					input = strings.TrimRight(input, "/")
					if !strings.HasPrefix(input, "https://") && !strings.HasPrefix(input, "http://") {
						input = "https://" + input
					}

					httpCl := http.Client{Transport: api.LogTransport}
					apiURL, err := api.GetAPIURLFromTenantURL(httpCl, input)
					switch {
					case err == nil:
						current.URL = input
						current.APIURL = apiURL
						return nil
					case errors.As(err, &errutil.NotFound{}):
						return fmt.Errorf("URL '%s' doesn't seem to be a valid tenant. Please check the URL and try again.", input)
					default:
						return fmt.Errorf("while getting API URL for tenant '%s': %w", input, err)
					}
				})
				if err != nil {
					return err
				}
				current.URL = tenantURL
				fmt.Println()
			}

			// Prompt for API Key.
			fmt.Println(subtleStyle.Render("To get the API key, open: " + current.URL + "/platform-settings/user-preferences?key=api-keys"))
			fmt.Println()

			apiKeyInput, err := promptString("API Key: ", func(input string) error {
				if input == "" {
					return fmt.Errorf("API key cannot be empty")
				}

				// Remove extraneous spaces before and after the user's
				// input for convenience.
				input = strings.TrimSpace(input)

				if len(input) != 36 {
					return fmt.Errorf("API key must be 36 characters long")
				}

				cl, err := api.NewAPIKeyClient(current.APIURL, input)
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}

				resp, err := api.SelfCheck(context.Background(), cl)
				if err != nil {
					return err
				}
				current.TenantID = resp.Company.Id.String()

				return nil
			})
			if err != nil {
				return err
			}
			current.APIKey = apiKeyInput

			logutil.Infof("\n%s\n", successStyle.Render("✓ You are now authenticated to tenant '"+current.URL+"'."))

			// Save the configuration to ~/.config/vcpctl.yaml
			err = saveCurrentTenant(current)
			if err != nil {
				return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "The API URL of the CyberArk Certificate Manager, SaaS tenant. If not provided, you will be prompted to enter it.")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "The API key for the CyberArk Certificate Manager, SaaS tenant. If not provided, you will be prompted to enter it.")

	return cmd
}

// authLoginCmd is a deprecated alias for loginCmd
func authLoginCmd() *cobra.Command {
	cmd := loginCmd()
	cmd.Deprecated = "use 'vcpctl login' instead; 'vcpctl auth login' will be removed in a future release"
	return cmd
}

func apikeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "apikey",
		Short:         "Prints the API key for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIKey := os.Getenv("VEN_API_KEY")
			flagAPIKey, _ := cmd.Flags().GetString("api-key")
			if envAPIKey != "" || flagAPIKey != "" {
				logutil.Debugf("$VEN_API_KEY or --api-key has been passed but will be ignored. This command only prints the API key from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf()
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
func authAPIKeyCmd() *cobra.Command {
	cmd := apikeyCmd()
	cmd.Use = "api-key"
	cmd.Deprecated = "use 'vcpctl apikey' instead; 'vcpctl auth api-key' will be removed in a future release"
	return cmd
}

func apiurlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "apiurl",
		Short:         "Prints the API URL for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIURL := os.Getenv("VEN_API_URL")
			flagAPIURL, _ := cmd.Flags().GetString("api-url")
			if envAPIURL != "" || flagAPIURL != "" {
				logutil.Debugf("$VEN_API_URL or --api-url has been passed but will be ignored. This command only prints the API URL from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf()
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
func authAPIURLCmd() *cobra.Command {
	cmd := apiurlCmd()
	cmd.Use = "api-url"
	cmd.Deprecated = "use 'vcpctl apiurl' instead; 'vcpctl auth api-url' will be removed in a future release"
	return cmd
}

func tenantidCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "tenantid",
		Short:         "Prints the tenant ID for the current CyberArk Certificate Manager, SaaS tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIURL := os.Getenv("VEN_API_URL")
			envAPIKey := os.Getenv("VEN_API_KEY")
			flagAPIURL, _ := cmd.Flags().GetString("api-url")
			flagAPIKey, _ := cmd.Flags().GetString("api-key")
			flagTenant, _ := cmd.Flags().GetString("tenant")

			if envAPIKey != "" || flagAPIKey != "" || envAPIURL != "" || flagAPIURL != "" || flagTenant != "" {
				logutil.Debugf("$VEN_API_URL, $VEN_API_KEY, --api-url, --api-key, or --tenant has been passed but will be ignored. This command only prints the tenant ID from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			auth, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl login\n")
			}

			if auth.TenantID == "" {
				logutil.Debugf("Tenant ID not found in config. This might be an older config file. Please re-login with 'vcpctl login'.")
				return fmt.Errorf("tenant ID not available")
			}

			fmt.Println(auth.TenantID)
			return nil
		},
	}
	return cmd
}

func switchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch [tenant-url]",
		Short: "Switch to a different CyberArk Certificate Manager, SaaS tenant.",
		Long: undent.Undent(`
			Switch to a different CyberArk Certificate Manager, SaaS tenant. If the tenant is not specified,
			you will be prompted to select one.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			if len(conf.Auths) == 0 {
				return fmt.Errorf("no tenants found in configuration. Please run:\n    vcpctl login")
			}

			if len(args) > 0 {
				// If a tenant URL is provided, we try to find it in the configuration.
				tenantURL := args[0]
				for _, auth := range conf.Auths {
					if auth.URL == tenantURL {
						return saveCurrentTenant(auth)
					}
				}
				return errutil.Fixable(fmt.Errorf("tenant '%s' not found in configuration. Please run `vcpctl login` to add it.", tenantURL))
			}

			// If no tenant URL is provided, we prompt the user to select one.
			current, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("no current tenant found in configuration. Please run `vcpctl login` to add one.")
			}

			if os.Getenv("VEN_API_URL") != "" || os.Getenv("VEN_API_KEY") != "" {
				fmt.Println(errorStyle.Render("⚠  WARNING: the env var VEN_API_URL or VEN_API_KEY is set."))
				fmt.Println(errorStyle.Render("⚠  WARNING: This means that all of the other commands will ignore what's set by 'vcpctl login'."))
				fmt.Println()
			}

			// Build list of tenant URLs with current one marked
			items := make([]string, len(conf.Auths))
			for i, auth := range conf.Auths {
				marker := " "
				if auth.URL == current.URL {
					marker = successStyle.Render("*")
				}
				items[i] = fmt.Sprintf("%s %s", marker, auth.URL)
			}

			selectedIdx, err := promptSelect("Select the tenant you want to switch to:", items)
			if err != nil {
				return fmt.Errorf("selecting tenant: %w", err)
			}

			selectedAuth := conf.Auths[selectedIdx]
			conf.CurrentURL = selectedAuth.URL
			return saveFileConf(conf)
		},
	}

	return cmd
}

// authSwitchCmd is a deprecated alias for switchCmd
func authSwitchCmd() *cobra.Command {
	cmd := switchCmd()
	cmd.Deprecated = "use 'vcpctl switch' instead; 'vcpctl auth switch' will be removed in a future release"
	return cmd
}

// Meant for the `auth login` command.
func saveCurrentTenant(auth Auth) error {
	conf, err := loadFileConf()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Check if the tenant already exists in the configuration.
	for i := range conf.Auths {
		if conf.Auths[i].URL == auth.URL {
			conf.CurrentURL = auth.URL
			conf.Auths[i] = auth
			return saveFileConf(conf)
		}
	}

	// If it doesn't exist, add it.
	conf.CurrentURL = auth.URL
	newAuth := Auth{
		URL:    auth.URL,
		APIURL: auth.APIURL,
		APIKey: auth.APIKey,
	}
	conf.Auths = append(conf.Auths, newAuth)

	return saveFileConf(conf)
}

// Tenant name is the first segment of the URL used when a customer opens the
// UI. E.g., with the UI at URL:
//
//	https://ven-cert-manager-uk.venafi.cloud
//	        <-- tenantName --->
func toTenantID(cl http.Client, tenantName string) (apiURL, tenantID string, _ error) {
	for _, apiURL := range venafiRegions {
		url := fmt.Sprintf("%s/v1/companies/%s/loginconfig", apiURL, tenantName)
		resp, err := cl.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var respJSON struct {
			CompanyID string `json:"companyId"`
		}
		if err := decodeJSON(resp.Body, &resp); err != nil {
			continue
		}

		return apiURL, respJSON.CompanyID, nil
	}

	return "", "", errutil.NotFound{NameOrID: tenantName}
}

// resolveTenant resolves a tenant identifier (ID, domain, or URL) to an Auth entry
// from the configuration. Returns the matching Auth and true if found.
func resolveTenant(conf FileConf, tenantInput string) (Auth, bool) {
	// Normalize the input
	normalized := strings.TrimSpace(tenantInput)
	normalized = strings.TrimSuffix(normalized, "/")

	// First, try exact match by tenant ID
	for _, auth := range conf.Auths {
		if auth.TenantID == normalized {
			return auth, true
		}
	}

	// Try exact URL match
	for _, auth := range conf.Auths {
		if auth.URL == normalized {
			return auth, true
		}
	}

	// Try URL match with https:// prefix
	if !strings.HasPrefix(normalized, "https://") {
		normalized = "https://" + normalized
	}
	for _, auth := range conf.Auths {
		if auth.URL == normalized {
			return auth, true
		}
	}

	// Try domain substring match (e.g., "ui-stack-dev210.qa.venafi.io" should match "https://ui-stack-dev210.qa.venafi.io")
	for _, auth := range conf.Auths {
		if strings.Contains(auth.URL, tenantInput) {
			return auth, true
		}
	}

	return Auth{}, false
}

// This must be used by all other commands to get the API key and API URL.
func getToolConfig(cmd *cobra.Command) (ToolConf, error) {
	envAPIURL := os.Getenv("VEN_API_URL")
	envAPIKey := os.Getenv("VEN_API_KEY")
	flagAPIURL, _ := cmd.Flags().GetString("api-url")
	flagAPIKey, _ := cmd.Flags().GetString("api-key")
	flagTenant, _ := cmd.Flags().GetString("tenant")

	// If any of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set, we don't use
	// the configuration file.
	if flagAPIKey != "" || envAPIKey != "" || flagAPIURL != "" || envAPIURL != "" {
		logutil.Debugf("one of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set. The configuration file at ~/%s won't be loaded", configPath)

		// --tenant flag is ignored when --api-key or --api-url is used
		if flagTenant != "" {
			logutil.Debugf("--tenant flag is ignored when --api-key or --api-url is provided")
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
		}, nil
	}

	logutil.Debugf("none of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set, using the configuration file at ~/%s", configPath)

	conf, err := loadFileConf()
	if err != nil {
		return ToolConf{}, fmt.Errorf("loading configuration: %w", err)
	}

	var current Auth
	var ok bool

	// If --tenant flag is provided, use it to override the current tenant
	if flagTenant != "" {
		current, ok = resolveTenant(conf, flagTenant)
		if !ok {
			return ToolConf{}, fmt.Errorf("tenant '%s' not found in configuration. Available tenants can be listed with 'vcpctl switch'. Log in to a new tenant with 'vcpctl login'.", flagTenant)
		}
		logutil.Debugf("Using tenant '%s' (ID: %s) from --tenant flag", current.URL, current.TenantID)
	} else {
		// Find the current tenant from config
		current, ok = currentFrom(conf)
		if !ok {
			return ToolConf{}, fmt.Errorf("not logged in. To authenticate, run:\n    vcpctl login")
		}
	}

	// Let's make sure the URL never contains a trailing slash.
	current.APIURL = strings.TrimRight(current.APIURL, "/")

	return ToolConf{
		APIURL: current.APIURL,
		APIKey: current.APIKey,
	}, nil
}

// Only meant to be used by the `auth` commands.
func loadFileConf() (FileConf, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FileConf{}, fmt.Errorf("while getting user's home directory: %w", err)
	}

	f, err := os.Open(path.Join(home, configPath))
	if os.IsNotExist(err) {
		return FileConf{}, nil
	}
	if err != nil {
		return FileConf{}, fmt.Errorf("while opening ~/%s: %w", configPath, err)
	}

	var conf FileConf
	if err := yaml.NewDecoder(f).Decode(&conf); err != nil {
		return FileConf{}, fmt.Errorf("while decoding ~/%s: %w", configPath, err)
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
func currentFrom(conf FileConf) (Auth, bool) {
	if conf.CurrentURL != "" {
		for _, auth := range conf.Auths {
			if auth.URL == conf.CurrentURL {
				return auth, true
			}
		}
	}

	return Auth{}, false
}
