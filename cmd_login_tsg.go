package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

type envURLs struct {
	authURL string
	apiURL  string
	scmURL  string
}

var envURLMap = map[string]envURLs{
	"prod": {
		authURL: "https://auth.apps.paloaltonetworks.com",
		apiURL:  "https://api.strata.paloaltonetworks.com",
		scmURL:  "https://stratacloudmanager.paloaltonetworks.com",
	},
	"qa": {
		authURL: "https://auth.qa.appsvc.paloaltonetworks.com",
		apiURL:  "https://qa.api.sase.paloaltonetworks.com",
		scmURL:  "https://stratacloudmanager.qa.appsvc.paloaltonetworks.com",
	},
	"dev": {
		authURL: "https://auth.dev.appsvc.paloaltonetworks.com",
		apiURL:  "https://dev.api.sase.paloaltonetworks.com",
		scmURL:  "https://stratacloudmanager.dev.appsvc.paloaltonetworks.com",
	},
}

func loginTSGCmd(groupID string) *cobra.Command {
	var contextFlag, authURL, apiURL, clientSecret, env string
	var autoSwitch bool
	cmd := &cobra.Command{
		Use:           "login-tsg [client-id]",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		Short:         "Authenticate using a Palo Alto Networks TSG service account.",
		Long: undent.Undent(`
			Authenticate using a Palo Alto Networks TSG (Tenant Service Group) service
			account. The client ID is the service account email, e.g.,
			mael@1526746475.iam.panserviceaccount.com.

			The TSG ID is extracted from the client ID automatically. Use 'vcpctl tsg switch'
			after login to select a different TSG if needed.

			Use --env to select the environment (prod, qa, dev). The --auth-url and
			--api-url flags override the environment defaults.

			When run without arguments in a terminal, an interactive mode guides you
			through selecting the context, environment, and credentials.
		`),
		Example: undent.Undent(`
			# Interactive mode (prompts for all details):
			vcpctl login-tsg

			# Non-interactive:
			vcpctl login-tsg mael@1526746475.iam.panserviceaccount.com \
			  --client-secret <secret>

			vcpctl login-tsg mael@1526746475.iam.panserviceaccount.com \
			  --env qa --client-secret <secret>

			# Automatically switch to the new context:
			vcpctl login-tsg mael@1526746475.iam.panserviceaccount.com \
			  --client-secret <secret> --switch
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && IsInteractiveTerminal(os.Stdout.Fd()) {
				envProvided := cmd.Flags().Changed("env")
				return loginTSGInteractive(cmd.Context(), contextFlag, env, envProvided, autoSwitch)
			}

			if len(args) == 0 {
				return errutil.Fixable(fmt.Errorf("client-id is required (or run without arguments for interactive mode)"))
			}
			clientID := args[0]
			if clientSecret == "" {
				return errutil.Fixable(fmt.Errorf("--client-secret is required"))
			}

			urls, ok := envURLMap[env]
			if !ok {
				return errutil.Fixable(fmt.Errorf("unknown --env %q; valid values: prod, qa, dev", env))
			}
			if authURL == "" {
				authURL = urls.authURL
			}
			if apiURL == "" {
				apiURL = urls.apiURL
			}
			apiURL = normalizeAPIURL(apiURL)
			return loginWithTSG(cmd.Context(), clientID, clientSecret, authURL, apiURL, contextFlag, autoSwitch)
		},
	}
	cmd.Flags().StringVar(&env, "env", "prod", "Environment to use: prod, qa, or dev")
	cmd.Flags().StringVar(&authURL, "auth-url", "", "Override the OAuth2 authorization server URL")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Override the API URL ('/ngts' is appended if not already present)")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "The client secret for the service account")
	cmd.Flags().StringVar(&contextFlag, "context", "", "Context name to create or update")
	cmd.Flags().BoolVar(&autoSwitch, "switch", false, "Automatically switch to the context after logging in without prompting")
	_ = cmd.Flags().MarkDeprecated("auth-url", "use --env instead")
	_ = cmd.Flags().MarkDeprecated("api-url", "use --env instead")
	return cmd
}

func loginTSGInteractive(ctx context.Context, contextFlag, envFlag string, envProvided bool, autoSwitch bool) error {
	// Step 1: context picker (before any other prompt).
	resolvedContext := contextFlag
	var existingTSGContext *ToolContext
	if resolvedContext == "" {
		conf, err := loadFileConf(ctx)
		if err != nil {
			return fmt.Errorf("loading configuration: %w", err)
		}
		if conf.CurrentContext != "" {
			// Filter contexts by environment if --env was provided
			envFilter := ""
			if envProvided {
				envFilter = envFlag
			}
			resolvedContext, err = promptContextSelectionWithEnv(ctx, conf, []string{"tsg"}, envFilter)
			if err != nil {
				return err
			}
			if existing, ok := resolveContext(conf, resolvedContext); ok && existing.AuthenticationType == "tsg" {
				existingTSGContext = &existing
			}
		}
	}

	// Step 2: environment selector — skip if --env was provided, otherwise pre-select based on existing context if available.
	var env string
	if envProvided {
		env = envFlag
	} else {
		env = envFromAuthURL(existingTSGContext)
		envForm := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Which environment?").
					Description("You can pass --env to skip this prompt").
					Options(
						huh.NewOption("Production (prod)", "prod"),
						huh.NewOption("QA (qa)", "qa"),
						huh.NewOption("Dev (dev)", "dev"),
					).
					Value(&env),
			),
		)
		if err := envForm.RunWithContext(ctx); err != nil {
			return fmt.Errorf("prompt cancelled: %w", err)
		}
	}

	urls := envURLMap[env]

	// Step 3: instructions.
	settingsURL := fmt.Sprintf("%s/settings/iam/access", urls.scmURL)
	fmt.Printf("\nPlease go to \033[96m%s\033[0m\n", settingsURL)
	fmt.Printf("and create an SCM service account, then paste its email and client secret below.\n\n")

	// Step 4: client ID and secret prompts — pre-fill from existing context if available.
	var clientID, clientSecret string
	if existingTSGContext != nil {
		clientID = existingTSGContext.ClientID
		clientSecret = existingTSGContext.ClientSecret
	}
	credForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Service account email (client ID):").
				Description("You can pass the client ID as a positional argument to skip this prompt").
				Value(&clientID).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("client ID cannot be empty")
					}
					return nil
				}),
			huh.NewInput().
				Title("Client secret:").
				Description("You can pass --client-secret to skip this prompt").
				EchoMode(huh.EchoModePassword).
				Value(&clientSecret).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("client secret cannot be empty")
					}
					return nil
				}),
		),
	)
	if err := credForm.RunWithContext(ctx); err != nil {
		return fmt.Errorf("prompt cancelled: %w", err)
	}

	// Clear the instructions after credentials are entered
	fmt.Print("\033[3A\033[J")

	return loginWithTSG(ctx, strings.TrimSpace(clientID), strings.TrimSpace(clientSecret), urls.authURL, normalizeAPIURL(urls.apiURL), resolvedContext, autoSwitch)
}

// envFromAuthURL returns the env key ("prod", "qa", "dev") matching the
// existing context's AuthURL, falling back to "prod" if not found.
func envFromAuthURL(existing *ToolContext) string {
	if existing != nil {
		for key, urls := range envURLMap {
			if strings.EqualFold(existing.AuthURL, urls.authURL) {
				return key
			}
		}
	}
	return "prod"
}

// ngtsDataplaneURL returns the NGTS-only dataplane URL for the given TSG ID
// and environment.
func ngtsDataplaneURL(tsgID, env string) (string, error) {
	switch env {
	case "prod":
		return fmt.Sprintf("https://%s.ngts.paloaltonetworks.com", tsgID), nil
	case "qa":
		return fmt.Sprintf("https://%s.ngts.qa.venafi.io", tsgID), nil
	case "dev":
		return fmt.Sprintf("https://%s.ngts.dev.venafi.io", tsgID), nil
	default:
		return "", fmt.Errorf("NGTS dataplane URL not yet known for environment %q", env)
	}
}

func normalizeAPIURL(apiURL string) string {
	apiURL = strings.TrimRight(apiURL, "/")
	if !strings.HasSuffix(apiURL, "/ngts") {
		apiURL = apiURL + "/ngts"
	}
	return apiURL
}

var tsgIDRegexp = regexp.MustCompile(`@(\d+)\.iam\.panserviceaccount\.com$`)

func extractTSGID(clientID string) (string, error) {
	matches := tsgIDRegexp.FindStringSubmatch(clientID)
	if len(matches) < 2 {
		return "", errutil.Fixable(fmt.Errorf("could not extract TSG ID from client ID %q; expected format: <user>@<tsg-id>.iam.panserviceaccount.com", clientID))
	}
	return matches[1], nil
}

func loginWithTSG(ctx context.Context, clientID, clientSecret, authURL, apiURL, contextFlag string, autoSwitch bool) error {
	// Extract TSG ID from client ID
	tsgID, err := extractTSGID(clientID)
	if err != nil {
		return err
	}

	accessToken, err := fetchTSGAccessToken(ctx, authURL, clientID, clientSecret, tsgID)
	if err != nil {
		return fmt.Errorf("while obtaining access token: %w", err)
	}

	current := Auth{
		APIURL:             apiURL,
		AuthenticationType: "tsg",
		AccessToken:        accessToken,
		Username:           clientID,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		AuthURL:            authURL,
		TSGID:              tsgID,
	}

	current, err = saveCurrentContext(ctx, current, contextFlag, autoSwitch)
	if err != nil {
		return fmt.Errorf("saving configuration for context %v: %w", displayContextForSelection(current), err)
	}

	logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(current))
	return nil
}

func fetchTSGAccessToken(ctx context.Context, authURL, clientID, clientSecret, tsgID string) (string, error) {
	authURL = strings.TrimRight(authURL, "/")
	endpoint := fmt.Sprintf("%s/oauth2/access_token", authURL)

	form := url.Values{
		"grant_type": []string{"client_credentials"},
		"scope":      []string{fmt.Sprintf("tsg_id:%s", tsgID)},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("while creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", api.UserAgent)
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while sending token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("while reading token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", newTokenExchangeError(resp.StatusCode, resp.Status, body)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("while parsing token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	return parsed.AccessToken, nil
}
