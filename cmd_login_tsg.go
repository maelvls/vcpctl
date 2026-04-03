package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

type envURLs struct {
	authURL string
	apiURL  string
}

var envURLMap = map[string]envURLs{
	"prod": {
		authURL: "https://auth.apps.paloaltonetworks.com",
		apiURL:  "https://api.strata.paloaltonetworks.com",
	},
	"qa": {
		authURL: "https://auth.qa.appsvc.paloaltonetworks.com",
		apiURL:  "https://qa.api.sase.paloaltonetworks.com",
	},
	"dev": {
		authURL: "https://auth.dev.appsvc.paloaltonetworks.com",
		apiURL:  "https://dev.api.sase.paloaltonetworks.com",
	},
}

func loginTSGCmd(groupID string) *cobra.Command {
	var contextFlag, authURL, apiURL, clientSecret, env string
	cmd := &cobra.Command{
		Use:           "login-tsg <client-id>",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		Short:         "Authenticate using a Palo Alto Networks TSG service account.",
		Long: undent.Undent(`
			Authenticate using a Palo Alto Networks TSG (Tenant Service Group) service
			account. The client ID is the service account email, e.g.,
			mael@1526746475.iam.panserviceaccount.com.

			The TSG ID is extracted from the client ID automatically.

			Use --env to select the environment (prod, qa, dev). The --auth-url and
			--api-url flags override the environment defaults.
		`),
		Example: undent.Undent(`
			vcpctl login-tsg mael@1526746475.iam.panserviceaccount.com \
			  --client-secret <secret>

			vcpctl login-tsg mael@1526746475.iam.panserviceaccount.com \
			  --env qa --client-secret <secret>
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			apiURL = strings.TrimRight(apiURL, "/")
			if !strings.HasSuffix(apiURL, "/ngts") {
				apiURL = apiURL + "/ngts"
			}
			return loginWithTSG(cmd.Context(), clientID, clientSecret, authURL, apiURL, contextFlag)
		},
	}
	cmd.Flags().StringVar(&env, "env", "prod", "Environment to use: prod, qa, or dev")
	cmd.Flags().StringVar(&authURL, "auth-url", "", "Override the OAuth2 authorization server URL")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Override the API URL ('/ngts' is appended if not already present)")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "The client secret for the service account (required)")
	cmd.Flags().StringVar(&contextFlag, "context", "", "Context name to create or update")
	_ = cmd.MarkFlagRequired("client-secret")
	_ = cmd.Flags().MarkDeprecated("auth-url", "use --env instead")
	_ = cmd.Flags().MarkDeprecated("api-url", "use --env instead")
	return cmd
}

var tsgIDRegexp = regexp.MustCompile(`@(\d+)\.iam\.panserviceaccount\.com$`)

func extractTSGID(clientID string) (string, error) {
	matches := tsgIDRegexp.FindStringSubmatch(clientID)
	if len(matches) < 2 {
		return "", errutil.Fixable(fmt.Errorf("could not extract TSG ID from client ID %q; expected format: <user>@<tsg-id>.iam.panserviceaccount.com", clientID))
	}
	return matches[1], nil
}

func loginWithTSG(ctx context.Context, clientID, clientSecret, authURL, apiURL, contextFlag string) error {
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
	}

	current, err = saveCurrentContext(ctx, current, contextFlag)
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
