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

func LoadFileConf() (FileConf, error) {
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

func SaveFileConf(conf FileConf) error {
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

type LoginCmdFlags struct {
	APIURL string
	APIKey string
}

// Only meant to be used by the `auth login` command.
func CurrentFrom(conf FileConf) (Auth, bool) {
	if conf.CurrentURL != "" {
		for _, auth := range conf.Auths {
			if auth.URL == conf.CurrentURL {
				return auth, true
			}
		}
	}

	return Auth{}, false
}

// Also requests a new token if the token is empty.
func GetCredsUsingFileConf() (Auth, error) {
	conf, err := LoadFileConf()
	if err != nil {
		return Auth{}, fmt.Errorf("loading configuration: %w", err)
	}

	if conf.CurrentURL == "" {
		return Auth{}, fmt.Errorf("no current URL set in configuration. Please run `vcpctl auth login` to set it.")
	}

	// Find the auth for the current URL.
	var auth Auth
	for _, a := range conf.Auths {
		if a.URL == conf.CurrentURL {
			auth = a
			break
		}
	}

	if auth.URL == "" || auth.APIURL == "" || auth.APIKey == "" {
		return Auth{}, fmt.Errorf("not authenticated. Please run `vcpctl auth login`.")
	}

	// Let's check if the API key is valid.
	_, err = checkAPIKey(auth.APIURL, auth.APIKey)
	if err == nil {
		return auth, nil
	}

	return Auth{}, nil
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
	var flags LoginCmdFlags
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
			// If the user provided the --api-url and --api-key flags, we use them.
			if flags.APIURL != "" || flags.APIKey != "" {
				if flags.APIURL == "" {
					return fmt.Errorf("the --api-url flag is required when using the --api-key flag")
				}
				if flags.APIKey == "" {
					return fmt.Errorf("the --api-key flag is required when using the --api-url flag")
				}

				resp, err := checkAPIKey(flags.APIURL, flags.APIKey)
				if err != nil {
					return fmt.Errorf("while checking the API key's validity: %w", err)
				}

				current := Auth{
					APIURL: flags.APIURL,
					APIKey: flags.APIKey,
					URL:    fmt.Sprintf("https://%s.venafi.cloud", resp.Company.URLPrefix),
				}

				err = saveCurrentTenant(current)
				if err != nil {
					return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
				}

				logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.URL)
				return nil
			}

			// Load the current configuration.
			conf, err := LoadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			current, ok := CurrentFrom(conf)
			if !ok {
				return fmt.Errorf("no current tenant found in configuration. Please run `vcpctl auth login` to add one.")
			}

			f := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().
						Prompt("Tenant URL: ").
						Description("Enter the URL you use to log into the Venafi Cloud web UI. Example: https://ven-cert-manager-uk.venafi.cloud").
						Value(&current.URL).
						Validate(func(input string) error {
							apiURL, err := toAPIURL(input)
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
					huh.NewInput().
						Prompt("API Key: ").
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
							_, err = checkAPIKey(current.APIURL, input)
							if err != nil {
								return err
							}

							return nil
						}).
						Value(&current.APIKey),
				),
			)
			if err := f.Run(); err != nil {
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
	cmd.Flags().StringVar(&flags.APIURL, "api-url", "", "The API URL of the Venafi Cloud tenant. If not provided, you will be prompted to enter it.")
	cmd.Flags().StringVar(&flags.APIKey, "api-key", "", "The API key for the Venafi Cloud tenant.")

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
			conf, err := LoadFileConf()
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}
			if len(conf.Auths) == 0 {
				return fmt.Errorf("no tenants found in configuration. Please run `vcpctl auth login` to add one.")
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
			current, ok := CurrentFrom(conf)
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
			f := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[Auth]().
						Options(opts...).
						Description("Select the tenant you want to switch to.").
						Value(&current),
				),
			)
			if err := f.Run(); err != nil {
				return fmt.Errorf("selecting tenant: %w", err)
			}
			conf.CurrentURL = current.URL
			return SaveFileConf(conf)
		},
	}

	return cmd
}

// Meant for the `auth login` command.
func saveCurrentTenant(auth Auth) error {
	conf, err := LoadFileConf()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Check if the tenant already exists in the configuration.
	for i := range conf.Auths {
		if conf.Auths[i].URL == auth.URL {
			conf.CurrentURL = auth.URL
			conf.Auths[i] = auth
			return SaveFileConf(conf)
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

	return SaveFileConf(conf)
}

// Tenant name is the first segment of the URL used when a customer opens the
// UI. E.g., with the UI at URL:
//
//	https://ven-cert-manager-uk.venafi.cloud
//	        <-- tenantName --->
func toTenantID(tenantName string) (apiURL, tenantID string, _ error) {
	for _, apiURL := range venafiRegions {
		url := fmt.Sprintf("%s/v1/companies/%s/loginconfig", apiURL, tenantName)
		resp, err := http.Get(url)
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
func toAPIURL(tenantURL string) (string, error) {
	url := fmt.Sprintf("%s/single-spa-root-config/baseEnvironment.json", tenantURL)
	resp, err := http.Get(url)
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
