package main

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/internal/api"
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
	URL    string `json:"url"`    // The UI URL of the tenant, e.g., https://ven-cert-manager-uk.venafi.cloud
	APIURL string `json:"apiURL"` // The API URL of the tenant, e.g., https://api.uk.venafi.cloud
	APIKey string `json:"apiKey"`
}

// Styles for prompts
var (
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("red"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("green"))
	subtleStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// promptYesNo prompts for a yes/no answer
func promptYesNo(question string) (bool, error) {
	fmt.Printf("%s %s: ", question, subtleStyle.Render("(y/n)"))

	// Try to set raw mode for immediate single-character input
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		// Fallback to line-based input if raw mode not available
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

	// Read single character without waiting for Enter
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
		// Invalid input - continue reading without error message for better UX
	}
}

// promptString prompts for a string with optional validation
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

// promptSelect displays a numbered list and prompts for selection
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
		Use:   "login [--api-url <url>] [--api-key <key>]",
		Short: "Authenticate to a CyberArk Certificate Manager, SaaS tenant.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant. If the tenant is not specified,
			you will be prompted to enter it.

			If you prefer avoiding prompts, you can either use --api-url and
			--api-key (in which case the prompts are disabled).

			If you prefer using environment variables, you can pass:
			    --api-url $VEN_API_URL --api-key $VEN_API_KEY
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}

			// If the user provided the --api-url and --api-key flags, we use
			// them.
			if apiURL != "" || apiKey != "" {
				if apiURL == "" {
					return fmt.Errorf("the --api-url flag is required when using the --api-key flag")
				}
				if apiKey == "" {
					return Fixable(fmt.Errorf("the --api-key flag is required when using the --api-url flag"))
				}

				if strings.HasSuffix(apiURL, "/") {
					return fmt.Errorf("Tenant URL should not have a trailing slash, got: '%s'", apiURL)
				}
				if !strings.HasPrefix(apiURL, "https://") {
					return Fixable(fmt.Errorf("API URL should start with 'https://', got: '%s'", apiURL))
				}

				apiClient, err := api.NewClient(apiURL, api.WithHTTPClient(&cl), api.WithBearerToken(apiKey), api.WithUserAgent())
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				resp, err := checkAPIKey(context.Background(), *apiClient, apiURL, apiKey)
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
				tenantURL := fmt.Sprintf("%s.venafi.cloud", resp.Company.URLPrefix)
				if tenantURL == "stack" {
					tenantURL = apiURL
					tenantURL = strings.Replace(tenantURL, "api-", "ui-stack-", 1)
				}

				current := Auth{
					APIURL: apiURL,
					APIKey: apiKey,
					URL:    tenantURL,
				}

				err = saveCurrentTenant(current)
				if err != nil {
					return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
				}

				logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.URL)
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
				apiClient, err := api.NewClient(current.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(current.APIKey), api.WithUserAgent())
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				_, err = checkAPIKey(context.Background(), *apiClient, current.APIURL, current.APIKey)
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
					if strings.HasSuffix(input, "/") {
						return fmt.Errorf("Tenant URL should not have a trailing slash")
					}
					if !strings.HasPrefix(input, "https://") {
						return fmt.Errorf("Tenant URL should start with 'https://'")
					}

					apiURL, err := toAPIURL(cl, input)
					switch {
					case err == nil:
						current.URL = input
						current.APIURL = apiURL
						return nil
					case errors.As(err, &NotFound{}):
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

			// Prompt for API Key
			fmt.Println(subtleStyle.Render("To get the API key, open: " + current.URL + "/platform-settings/user-preferences?key=api-keys"))
			fmt.Println()

			apiKeyInput, err := promptString("API Key: ", func(input string) error {
				if input == "" {
					return fmt.Errorf("API key cannot be empty")
				}
				if strings.TrimSpace(input) != input {
					return fmt.Errorf("API key cannot contain leading or trailing spaces")
				}
				if len(input) != 36 {
					return fmt.Errorf("API key must be 36 characters long")
				}
				apiClient, err := api.NewClient(current.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(input), api.WithUserAgent())
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				_, err = checkAPIKey(context.Background(), *apiClient, current.APIURL, input)
				if err != nil {
					return err
				}

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
				return Fixable(fmt.Errorf("tenant '%s' not found in configuration. Please run `vcpctl login` to add it.", tenantURL))
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

	return "", "", NotFound{NameOrID: tenantName}
}

// Get the API URL for the given tenant URL.
func toAPIURL(cl http.Client, tenantURL string) (string, error) {
	url := fmt.Sprintf("%s/single-spa-root-config/baseEnvironment.json", tenantURL)
	resp, err := cl.Get(url)
	if err != nil {
		return "", fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	case http.StatusNotFound:
		return "", NotFound{NameOrID: tenantURL}
	default:
		return "", fmt.Errorf("unexpected status code %d while getting API URL for tenant '%s': %w", resp.StatusCode, tenantURL, parseJSONErrorOrDumpBody(resp))
	}

	var respJSON struct {
		APIBaseURL string `json:"apiBaseUrl"`
		UIHost     string `json:"uiHost"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	if err := json.Unmarshal(body, &respJSON); err != nil {
		return "", fmt.Errorf("while unmarshalling response body: %w", err)
	}

	return respJSON.APIBaseURL, nil
}

// This must be used by all other commands to get the API key and API URL.
func getToolConfig(cmd *cobra.Command) (ToolConf, error) {
	envAPIURL := os.Getenv("VEN_API_URL")
	envAPIKey := os.Getenv("VEN_API_KEY")
	flagAPIURL, _ := cmd.Flags().GetString("api-url")
	flagAPIKey, _ := cmd.Flags().GetString("api-key")

	// If any of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set, we don't use
	// the configuration file.
	if flagAPIKey != "" || envAPIKey != "" || flagAPIURL != "" || envAPIURL != "" {
		logutil.Debugf("one of $VEN_API_KEY, $VEN_API_URL, --api-key, or --api-url is set. The configuration file at ~/%s won't be loaded", configPath)
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

	// Find the current tenant.
	current, ok := currentFrom(conf)
	if !ok {
		return ToolConf{}, fmt.Errorf("not logged in. To authenticate, run:\n    vcpctl login")
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
