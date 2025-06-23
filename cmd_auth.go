package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
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

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "auth",
		Short:         "Commands for authenticating and switching tenants.",
		Long:          "Manage authentication for Venafi Cloud, including login and switch.",
		SilenceErrors: true,
		SilenceUsage:  true,
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

func authLoginCmd() *cobra.Command {
	var apiURL, apiKey string
	cmd := &cobra.Command{
		Use:   "login [--api-url <url>] [--api-key <key>]",
		Short: "Authenticate to Venafi Cloud tenant.",
		Long: undent.Undent(`
			Authenticate to a Venafi Cloud tenant. If the tenant is not specified,
			you will be prompted to enter it.

			If you prefer avoiding prompts, you can either use --api-url and
			--api-key (in which case the prompts are disabled).

			If you prefer using environment variables, you can pass:
			    --api-url $APIURL --api-key $APIKEY
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
					return fmt.Errorf("the --api-key flag is required when using the --api-url flag")
				}

				resp, err := checkAPIKey(cl, apiURL, apiKey)
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
			current, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("no current tenant found in configuration. Please run:\n    vcpctl auth login")
			}

			// Let the user know if they are already authenticated.
			if current.URL != "" {
				_, err := checkAPIKey(cl, current.APIURL, current.APIKey)
				if err == nil {
					var continueAuth bool
					f := huh.NewForm(huh.NewGroup(huh.NewConfirm().
						Title("Already authenticated").
						Description(fmt.Sprintf("You're already authenticated to '%s'. Do you want to continue editing the authentication details?", current.URL)).
						Value(&continueAuth).
						Affirmative("Yes").
						Negative("No"),
					))
					if err := f.Run(); err != nil {
						return fmt.Errorf("while asking if the user wants to continue: %w", err)
					}
					if !continueAuth {
						return nil
					}
				}
			}

			var fields []huh.Field

			if os.Getenv("APIURL") != "" || os.Getenv("APIKEY") != "" {
				fields = append(fields, huh.NewNote().
					Description("⚠️  WARNING: the env var APIURL or APIKEY is set.\n⚠️  WARNING: This means that all of the other commands will ignore what's set by 'vcpctl auth login'."),
				)
			}

			fields = append(fields, huh.NewInput().
				Prompt("Tenant URL: ").
				Description("Enter the URL you use to log into the Venafi Cloud web UI. Example: https://ven-cert-manager-uk.venafi.cloud").
				Value(&current.URL).
				Validate(func(input string) error {
					if strings.HasSuffix(input, "/") {
						return fmt.Errorf("Tenant URL should not have a trailing slash")
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
				}),
			)
			fields = append(fields, huh.NewInput().
				Prompt("API Key: ").
				EchoMode(huh.EchoModePassword).
				DescriptionFunc(func() string {
					if current.URL == "" {
						return ""
					}
					return fmt.Sprintf("To get the API key, open: %s/platform-settings/user-preferences?key=api-keys", current.URL)
				}, &current.URL).
				Validate(func(input string) error {
					if input == "" {
						return fmt.Errorf("API key cannot be empty")
					}
					if strings.TrimSpace(input) != input {
						return fmt.Errorf("API key cannot contain leading or trailing spaces")
					}
					if len(input) != 36 {
						return fmt.Errorf("API key must be 36 characters long")
					}
					_, err = checkAPIKey(cl, current.APIURL, input)
					if err != nil {
						return err
					}

					return nil
				}).
				Value(&current.APIKey),
			)

			err = huh.NewForm(huh.NewGroup(fields...)).Run()
			if err != nil {
				return err
			}

			logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.URL)

			// Save the configuration to ~/.config/vcpctl.yaml
			err = saveCurrentTenant(current)
			if err != nil {
				return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
			}

			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "The API URL of the Venafi Cloud tenant. If not provided, you will be prompted to enter it.")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "The API key for the Venafi Cloud tenant. If not provided, you will be prompted to enter it.")

	return cmd
}

func authAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "api-key",
		Short:         "Prints the API key for the current Venafi Cloud tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIKey := os.Getenv("APIKEY")
			flagAPIKey, _ := cmd.Flags().GetString("api-key")
			if envAPIKey != "" || flagAPIKey != "" {
				logutil.Debugf("$APIKEY or --api-key has been passed but will be ignored. This command only prints the API key from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			auth, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl auth login\n")
			}
			fmt.Println(auth.APIKey)
			return nil
		},
	}
	return cmd
}

func authAPIURLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "api-url",
		Short:         "Prints the API URL for the current Venafi Cloud tenant in the configuration.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			envAPIURL := os.Getenv("APIURL")
			flagAPIURL, _ := cmd.Flags().GetString("api-url")
			if envAPIURL != "" || flagAPIURL != "" {
				logutil.Debugf("$APIURL or --api-url has been passed but will be ignored. This command only prints the API URL from the configuration file at %s", configPath)
			}

			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			auth, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl auth login\n")
			}
			fmt.Println(auth.APIURL)
			return nil
		},
	}
	return cmd
}

func authSwitchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch [tenant-url]",
		Short: "Switch to a different Venafi Cloud tenant.",
		Long: undent.Undent(`
				Switch to a different Venafi Cloud tenant. If the tenant is not specified,
				you will be prompted to select one.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			if len(conf.Auths) == 0 {
				return fmt.Errorf("no tenants found in configuration. Please run:\n    vcpctl auth login")
			}

			if len(args) > 0 {
				// If a tenant URL is provided, we try to find it in the configuration.
				tenantURL := args[0]
				for _, auth := range conf.Auths {
					if auth.URL == tenantURL {
						return saveCurrentTenant(auth)
					}
				}
				return fmt.Errorf("tenant '%s' not found in configuration. Please run `vcpctl auth login` to add it.", tenantURL)
			}

			// If no tenant URL is provided, we prompt the user to select one.
			current, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("no current tenant found in configuration. Please run `vcpctl auth login` to add one.")
			}

			var opts []huh.Option[Auth]
			for _, auth := range conf.Auths {
				opts = append(opts, huh.Option[Auth]{
					Value: auth,
					Key:   auth.URL,
				})
			}

			var fields []huh.Field
			if os.Getenv("APIURL") != "" || os.Getenv("APIKEY") != "" {
				fields = append(fields, huh.NewNote().
					Description("⚠️  WARNING: the env var APIURL or APIKEY is set.\n⚠️  WARNING: This means that all of the other commands will ignore what's set by 'vcpctl auth login'."),
				)
			}
			fields = append(fields, huh.NewSelect[Auth]().
				Options(opts...).
				Description("Select the tenant you want to switch to.").
				Value(&current),
			)
			err = huh.NewForm(huh.NewGroup(fields...)).Run()
			if err != nil {
				return fmt.Errorf("selecting tenant: %w", err)
			}
			conf.CurrentURL = current.URL
			return saveFileConf(conf)
		},
	}

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
		if err := json.NewDecoder(resp.Body).Decode(&resp); err != nil {
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
	envAPIURL := os.Getenv("APIURL")
	envAPIKey := os.Getenv("APIKEY")
	flagAPIURL, _ := cmd.Flags().GetString("api-url")
	flagAPIKey, _ := cmd.Flags().GetString("api-key")

	// If any of $APIKEY, $APIURL, --api-key, or --api-url is set, we don't use
	// the configuration file.
	if flagAPIKey != "" || envAPIKey != "" || flagAPIURL != "" || envAPIURL != "" {
		logutil.Debugf("one of $APIKEY, $APIURL, --api-key, or --api-url is set. The configuration file at ~/%s won't be loaded", configPath)
		// Priority: $APIURL > --api-url.
		apiURL := envAPIURL
		if apiURL == "" {
			apiURL = flagAPIURL
		}
		apiKey := envAPIKey
		if apiKey == "" {
			apiKey = flagAPIKey
		}

		return ToolConf{
			APIURL: apiURL,
			APIKey: apiKey,
		}, nil
	}

	logutil.Debugf("none of $APIKEY, $APIURL, --api-key, or --api-url is set, using the configuration file at ~/%s", configPath)

	conf, err := loadFileConf()
	if err != nil {
		return ToolConf{}, fmt.Errorf("loading configuration: %w", err)
	}

	// Find the current tenant.
	current, ok := currentFrom(conf)
	if !ok {
		return ToolConf{}, fmt.Errorf("not logged in. To authenticate, run:\n    vcpctl auth login")
	}

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
