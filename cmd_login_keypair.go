package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

func loginKeypairCmd(groupID string) *cobra.Command {
	var contextFlag string
	var fromContextFlag string
	var saFlag string
	var scopeFlags []string
	var autoSwitch bool
	cmd := &cobra.Command{
		Use:           "login-keypair [json-file]",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		Short:         "Authenticate to a CyberArk Certificate Manager, SaaS tenant using a service account keypair.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant using a service account keypair.

			There are three modes:

			1. Interactive mode (no arguments): Prompts for service account, context, and scopes.
			   Generates a new keypair automatically.

			2. Non-interactive with flags (--sa, --context, --scope): Generates a new keypair
			   and configures the service account without prompts.

			3. Non-interactive with JSON file: Uses a pre-existing keypair from a JSON file
			   (from 'vcpctl sa gen keypair'). Use '-' to read from stdin.

			Notes:
			- Modes 1 and 2 require an API key context for API access (current context by default).
			- Use --from-context to specify a different API key context for API operations.
			- The --context flag specifies where to save the keypair authentication credentials.
		`),
		Example: undent.Undent(`
			# Interactive mode (prompts for everything):
			vcpctl login-keypair

			# Non-interactive with flags (no prompts, generates keypair):
			vcpctl login-keypair --sa mael --context dev210-keypair --scope distributed-issuance,kubernetes-discovery

			# Non-interactive with different source context for API access:
			vcpctl login-keypair --sa mael --context dev210-keypair --from-context prod-api-key

			# Non-interactive with JSON file:
			vcpctl login-keypair sa-keypair.json --context my-sa-context

			# Piped from stdin:
			vcpctl sa gen keypair my-sa -ojson | vcpctl login-keypair - --context my-sa-context

			# Automatically switch to the new context:
			vcpctl login-keypair --sa mael --context dev210-keypair --switch
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Mode 1: Interactive mode (no args, no --sa flag)
			if len(args) == 0 && saFlag == "" {
				if !IsInteractiveTerminal(os.Stdin.Fd()) {
					return errutil.Fixable(fmt.Errorf("when not running interactively, please either:\n  - pass a JSON authentication file or '-' (see --help),\n  - or pass the flags --sa and --context"))
				}

				return runLoginKeypairInteractive(cmd.Context(), contextFlag, fromContextFlag, scopeFlags, autoSwitch)
			}

			// Mode 2: Non-interactive with --sa flag (generates new keypair)
			if saFlag != "" {
				if len(args) > 0 {
					return errutil.Fixable(fmt.Errorf("cannot use both --sa flag and JSON file argument"))
				}

				// Require --context with --sa
				if contextFlag == "" {
					return errutil.Fixable(fmt.Errorf("--context is required when using --sa"))
				}

				return runLoginKeypairNonInteractive(cmd.Context(), saFlag, contextFlag, fromContextFlag, scopeFlags, autoSwitch)
			}

			// Non-interactive mode: read from JSON file
			saKeyPath := args[0]
			saKey, err := readJSONAuthKeypair(cmd.Context(), saKeyPath)
			if err != nil {
				return err
			}

			// Require --context in non-interactive mode
			if contextFlag == "" {
				return errutil.Fixable(fmt.Errorf("--context is required when using a JSON file"))
			}

			// Non-interactive: just authenticate with the provided keypair
			signedJWT, err := signServiceAccountJWT(saKey.ClientID, saKey.PrivateKey, saKey.APIURL, 30*time.Minute)
			if err != nil {
				return fmt.Errorf("while signing JWT: %w", err)
			}

			accessToken, err := exchangeServiceAccountJWT(cmd.Context(), saKey.APIURL, signedJWT)
			if err != nil {
				return fmt.Errorf("while exchanging JWT for access token: %w", err)
			}

			cl, err := api.NewAccessTokenClient(saKey.APIURL, accessToken)
			if err != nil {
				return fmt.Errorf("while creating access-token client: %w", err)
			}

			// We can't run SelfCheckAPIKeys() here because it only works with
			// API keys. But we can still know the service account name.
			saName, err := api.SelfCheckServiceAccount(cmd.Context(), cl)
			switch {
			case api.ErrIsHTTPForbidden(err):
				// This endpoint only works when the service account has the
				// scope 'platform-admin-role', otherwise it returns 403. Let's
				// just ignore the error and pretend the check passed and
				// continue below.
			case err != nil:
				return fmt.Errorf("while checking service account: %w", err)
			default:
				// Check passed, continue below.
			}

			current := Auth{
				APIURL:             saKey.APIURL,
				AuthenticationType: "rsaKey",
				ClientID:           saKey.ClientID,
				PrivateKey:         saKey.PrivateKey,
				AccessToken:        accessToken,
				Username:           saName,
			}

			current, err = saveCurrentContext(cmd.Context(), current, contextFlag, autoSwitch)
			if err != nil {
				return fmt.Errorf("saving configuration for context %v: %w", displayContextForSelection(current), err)
			}

			logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(current))
			return nil
		},
	}
	cmd.Flags().StringVar(&contextFlag, "context", "", "Context name to create or update for the keypair authentication")
	cmd.Flags().StringVar(&fromContextFlag, "from-context", "", "Context to use for API access (must be API key auth). Defaults to current context.")
	cmd.Flags().StringVar(&saFlag, "sa", "", "Service account name to use (enables non-interactive mode)")
	cmd.Flags().StringSliceVar(&scopeFlags, "scope", nil, "Scopes to assign to the service account (comma-separated or repeated flag)")
	cmd.Flags().BoolVar(&autoSwitch, "switch", false, "Automatically switch to the context after logging in without prompting")
	return cmd
}

type jsonAuthKeypair struct {
	Type       string `json:"type"`
	ClientID   string `json:"client_id"`
	PrivateKey string `json:"private_key"`
	APIURL     string `json:"api_url"`

	// Optional. Only useful when using Venafi Cloud, but not required even when
	// using Venafi Cloud. It is used to fill in the `tenantURL` field in
	// ~/.config/vcpctl.yaml, which allows us to display the UI URL when running
	// `vcpctl switch`.
	TenantURL string `json:"tenant_url,omitzero"`
}

type serviceAccountTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func readJSONAuthKeypair(ctx context.Context, path string) (jsonAuthKeypair, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		var err error
		reader, err = os.Open(path)
		if err != nil {
			return jsonAuthKeypair{}, fmt.Errorf("while opening %s: %w", path, err)
		}
	}

	raw, err := cancellablereader.ReadAllWithContext(ctx, reader)
	if err != nil {
		return jsonAuthKeypair{}, fmt.Errorf("while reading %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return jsonAuthKeypair{}, errutil.Fixable(fmt.Errorf("empty service account JSON"))
	}

	var input jsonAuthKeypair
	if err := json.Unmarshal(raw, &input); err != nil {
		return jsonAuthKeypair{}, fmt.Errorf("while parsing JSON: %w", err)
	}

	input.ClientID = strings.TrimSpace(input.ClientID)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	if input.ClientID == "" {
		return jsonAuthKeypair{}, errutil.Fixable(fmt.Errorf("missing 'client_id'"))
	}
	if input.PrivateKey == "" {
		return jsonAuthKeypair{}, errutil.Fixable(fmt.Errorf("missing 'private_key'"))
	}
	if input.APIURL == "" {
		return jsonAuthKeypair{}, errutil.Fixable(fmt.Errorf("missing 'api_url'"))
	}

	return input, nil
}

func signServiceAccountJWT(clientID, privateKeyPEM, apiURL string, validity time.Duration) (string, error) {
	key, method, err := parseServiceAccountPrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}

	// The audience must be the API URL without the https:// prefix. Example:
	//  api.venafi.cloud/v1/oauth/token/serviceaccount

	if apiURL == "" {
		return "", fmt.Errorf("API URL is required to sign the JWT")
	}
	logutil.Debugf("Signing JWT for API URL: %s", apiURL)

	claims := jwt.MapClaims{
		// This audience is hardcoded in the SaaS API and doesn't depend on what
		// the actual API URL is.
		"aud": "api.venafi.cloud/v1/oauth/token/serviceaccount",
		"iss": clientID,
		"sub": clientID,
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(time.Now().Add(validity)),

		// A uuid v4 is a good jti. A jti is required by the Venafi Cloud API.
		"jti": uuid.New().String(),
	}

	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(key)
}

func parseServiceAccountPrivateKey(privateKeyPEM string) (interface{}, jwt.SigningMethod, error) {
	rest := []byte(privateKeyPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("while parsing PKCS8 private key: %w", err)
			}
			return pickSigningMethod(key)
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("while parsing EC private key: %w", err)
			}
			return pickSigningMethod(key)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("while parsing RSA private key: %w", err)
			}
			return pickSigningMethod(key)
		}
	}
	return nil, nil, errutil.Fixable(fmt.Errorf("no private key found in PEM data"))
}

func pickSigningMethod(key interface{}) (interface{}, jwt.SigningMethod, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return k, jwt.SigningMethodES256, nil
		case elliptic.P384():
			return k, jwt.SigningMethodES384, nil
		case elliptic.P521():
			return k, jwt.SigningMethodES512, nil
		default:
			return nil, nil, fmt.Errorf("unsupported ECDSA curve %s", k.Curve.Params().Name)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

func exchangeServiceAccountJWT(ctx context.Context, apiURL, signedJWT string) (string, error) {
	apiURL = strings.TrimRight(apiURL, "/")
	endpoint := fmt.Sprintf("%s/v1/oauth/token/serviceaccount", apiURL)

	form := url.Values{
		"grant_type": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  []string{signedJWT},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("while creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", api.UserAgent)

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

	var parsed serviceAccountTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("while parsing token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	return parsed.AccessToken, nil
}

// runLoginKeypairInteractive handles the full interactive flow:
// 1. Prompt for service account name
// 2. Prompt for target rsaKey context
// 3. Prompt for scopes
// 4. Generate keypair and update SA
// 5. Authenticate and save to context
func runLoginKeypairInteractive(ctx context.Context, contextFlagOverride, fromContextOverride string, scopeFlagsOverride []string, autoSwitch bool) error {
	// Load config to get current context
	conf, err := loadFileConf(ctx)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Get source context for API access (fromContext or current)
	var current ToolContext
	if fromContextOverride != "" {
		var ok bool
		current, ok = resolveContext(conf, fromContextOverride)
		if !ok {
			return fmt.Errorf("--from-context '%s' not found. Run 'vcpctl switch' to see available contexts", fromContextOverride)
		}
	} else {
		var ok bool
		current, ok = currentFrom(conf)
		if !ok {
			if len(conf.ToolContexts) > 0 {
				return fmt.Errorf("no context set, but %d contexts exist. Run 'vcpctl switch' to select one", len(conf.ToolContexts))
			}
			return fmt.Errorf("not logged in. To authenticate, run 'vcpctl login'")
		}
	}

	currentAuth := ToolConf{
		APIURL:             strings.TrimRight(current.APIURL, "/"),
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
		ClientSecret:       current.ClientSecret,
		AuthURL:            current.AuthURL,
		TSGID:              current.TSGID,
	}

	if currentAuth.AuthenticationType != "apiKey" {
		return errutil.Fixable(fmt.Errorf("current context must use API key authentication. Please run 'vcpctl login' first or use 'vcpctl switch' to select an API key context"))
	}

	// Create API client
	apiClient, err := newAPIClient(currentAuth)
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	// Step 1: Prompt for target context (to know which SA was previously used)
	var contextName string
	if contextFlagOverride != "" {
		contextName = contextFlagOverride
	} else {
		contextName, err = promptContextSelection(ctx, conf, []string{"rsaKey"})
		if err != nil {
			return err
		}
	}

	// Check if target context exists and get previous SA name
	var previousSAName string
	targetCtx, targetExists := resolveContext(conf, contextName)
	if targetExists && targetCtx.AuthenticationType == "rsaKey" {
		previousSAName = targetCtx.Username // SA name is stored in Username field
	}

	// Step 2: Prompt for service account name (with previous SA pre-selected)
	saName, err := promptServiceAccountName(ctx, apiClient, previousSAName)
	if err != nil {
		return err
	}

	// Try to get the service account (might not exist if creating new)
	existingSA, err := api.GetServiceAccount(ctx, apiClient, saName)
	var currentScopes []string

	switch {
	case errors.As(err, &errutil.NotFound{}):
		// Service account doesn't exist yet, we'll create it below
		logutil.Debugf("Service account '%s' does not exist, will create it", saName)
		existingSA = api.ServiceAccountDetails{
			Name:               saName,
			AuthenticationType: "rsaKey",
			CredentialLifetime: 365, // days
		}
	case err != nil:
		return fmt.Errorf("fetching service account '%s': %w", saName, err)
	default:
		// Service account exists - verify it's an rsaKey service account
		if existingSA.AuthenticationType != "rsaKey" {
			return fmt.Errorf("service account '%s' has authentication type '%s', expected 'rsaKey'", saName, existingSA.AuthenticationType)
		}

		currentScopes = existingSA.Scopes
	}

	// Step 3: Fetch available scopes and prompt
	availableScopes, err := api.GetServiceAccountScopesByType(ctx, apiClient, "rsaKey")
	if err != nil {
		return fmt.Errorf("fetching available scopes: %w", err)
	}

	selectedScopes, err := promptScopeSelection(ctx, availableScopes, currentScopes)
	if err != nil {
		return err
	}

	// Step 4: Generate EC keypair
	ecKey, ecPub, err := genECKeyPair()
	if err != nil {
		return fmt.Errorf("generating EC key pair: %w", err)
	}

	// Check for duplicate roles
	err = checkDuplicateRoles(selectedScopes)
	if err != nil {
		return err
	}

	// Step 5: Create or update service account with public key and scopes
	var saID string
	if existingSA.Id.String() == "00000000-0000-0000-0000-000000000000" {
		// Service account doesn't exist - create it
		created, err := api.CreateServiceAccount(ctx, apiClient, api.ServiceAccountDetails{
			Name:               saName,
			CredentialLifetime: 365, // days
			Scopes:             selectedScopes,
			AuthenticationType: "rsaKey",
			PublicKey:          ecPub,
		})
		if err != nil {
			return fmt.Errorf("creating service account: %w", err)
		}
		saID = created.Id.String()
		logutil.Debugf("Service Account '%s' created with scopes: %s", saName, strings.Join(selectedScopes, ", "))
	} else {
		// Service account exists - update it
		desiredSA := existingSA
		desiredSA.PublicKey = ecPub
		desiredSA.Scopes = selectedScopes

		patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
		if err != nil {
			return fmt.Errorf("creating service account patch: %w", err)
		}

		if smthChanged {
			err = api.PatchServiceAccount(ctx, apiClient, existingSA.Id.String(), patch)
			if err != nil {
				return fmt.Errorf("updating service account: %w", err)
			}
			logutil.Debugf("Service Account '%s' updated with new public key and scopes: %s", saName, strings.Join(selectedScopes, ", "))
		}
		saID = existingSA.Id.String()
	}

	// Step 6: Sign JWT and exchange for access token
	signedJWT, err := signServiceAccountJWT(saID, ecKey, currentAuth.APIURL, 30*time.Minute)
	if err != nil {
		return fmt.Errorf("signing JWT: %w", err)
	}

	accessToken, err := exchangeServiceAccountJWT(ctx, currentAuth.APIURL, signedJWT)
	if err != nil {
		return fmt.Errorf("exchanging JWT for access token: %w", err)
	}

	// Save to context
	authToSave := Auth{
		APIURL:             currentAuth.APIURL,
		AuthenticationType: "rsaKey",
		ClientID:           saID,
		PrivateKey:         ecKey,
		AccessToken:        accessToken,
		Username:           saName,
	}

	authToSave, err = saveCurrentContext(ctx, authToSave, contextName, autoSwitch)
	if err != nil {
		return fmt.Errorf("saving configuration for context %v: %w", displayContextForSelection(authToSave), err)
	}

	logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(authToSave))
	return nil
}

// runLoginKeypairNonInteractive handles non-interactive mode with --sa flag:
// Creates/updates SA with generated keypair and authenticates without prompts.
func runLoginKeypairNonInteractive(ctx context.Context, saName, contextName, fromContextOverride string, scopes []string, autoSwitch bool) error {
	// Load config to get source context
	conf, err := loadFileConf(ctx)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	// Get source context for API access (fromContext or current)
	var current ToolContext
	if fromContextOverride != "" {
		var ok bool
		current, ok = resolveContext(conf, fromContextOverride)
		if !ok {
			return fmt.Errorf("--from-context '%s' not found. Run 'vcpctl switch' to see available contexts", fromContextOverride)
		}
	} else {
		var ok bool
		current, ok = currentFrom(conf)
		if !ok {
			if len(conf.ToolContexts) > 0 {
				return fmt.Errorf("no context set, but %d contexts exist. Run 'vcpctl switch' to select one", len(conf.ToolContexts))
			}
			return fmt.Errorf("not logged in. To authenticate, run 'vcpctl login'")
		}
	}

	currentAuth := ToolConf{
		APIURL:             strings.TrimRight(current.APIURL, "/"),
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
		ClientSecret:       current.ClientSecret,
		AuthURL:            current.AuthURL,
		TSGID:              current.TSGID,
	}

	if currentAuth.AuthenticationType != "apiKey" {
		return errutil.Fixable(fmt.Errorf("current context must use API key authentication. Please run 'vcpctl login' first or use 'vcpctl switch' to select an API key context"))
	}

	// Create API client
	apiClient, err := newAPIClient(currentAuth)
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	// Try to get the service account (might not exist if creating new)
	existingSA, err := api.GetServiceAccount(ctx, apiClient, saName)
	var currentScopes []string

	switch {
	case errors.As(err, &errutil.NotFound{}):
		// Service account doesn't exist yet, we'll create it below
		logutil.Debugf("Service account '%s' does not exist, will create it", saName)
		existingSA = api.ServiceAccountDetails{
			Name:               saName,
			AuthenticationType: "rsaKey",
			CredentialLifetime: 365, // days
		}
	case err != nil:
		return fmt.Errorf("fetching service account '%s': %w", saName, err)
	default:
		// Service account exists - verify it's an rsaKey service account
		if existingSA.AuthenticationType != "rsaKey" {
			return fmt.Errorf("service account '%s' has authentication type '%s', expected 'rsaKey'", saName, existingSA.AuthenticationType)
		}

		currentScopes = existingSA.Scopes
	}

	// Use provided scopes or keep existing ones
	selectedScopes := scopes
	if len(selectedScopes) == 0 {
		selectedScopes = currentScopes
	}

	// If still no scopes, default to all available scopes (with only one role)
	if len(selectedScopes) == 0 {
		availableScopes, err := api.GetServiceAccountScopesByType(ctx, apiClient, "rsaKey")
		if err != nil {
			return fmt.Errorf("fetching available scopes: %w", err)
		}

		// Use all available scopes, but only keep the first role scope
		var nonRoleScopes []string
		var firstRole string
		for _, scope := range availableScopes {
			if strings.Contains(scope, "role") {
				if firstRole == "" {
					firstRole = scope
				}
			} else {
				nonRoleScopes = append(nonRoleScopes, scope)
			}
		}

		selectedScopes = nonRoleScopes
		if firstRole != "" {
			selectedScopes = append(selectedScopes, firstRole)
		}

		logutil.Debugf("No scopes provided, defaulting to all available scopes: %s", strings.Join(selectedScopes, ", "))
	}

	// Generate EC keypair
	ecKey, ecPub, err := genECKeyPair()
	if err != nil {
		return fmt.Errorf("generating EC key pair: %w", err)
	}

	// Check for duplicate roles
	err = checkDuplicateRoles(selectedScopes)
	if err != nil {
		return err
	}

	// Create or update service account with public key and scopes
	var saID string
	if existingSA.Id.String() == "00000000-0000-0000-0000-000000000000" {
		// Service account doesn't exist - create it
		created, err := api.CreateServiceAccount(ctx, apiClient, api.ServiceAccountDetails{
			Name:               saName,
			CredentialLifetime: 365, // days
			Scopes:             selectedScopes,
			AuthenticationType: "rsaKey",
			PublicKey:          ecPub,
		})
		if err != nil {
			return fmt.Errorf("creating service account: %w", err)
		}
		saID = created.Id.String()
		logutil.Debugf("Service Account '%s' created with scopes: %s", saName, strings.Join(selectedScopes, ", "))
	} else {
		// Service account exists - update it
		desiredSA := existingSA
		desiredSA.PublicKey = ecPub
		desiredSA.Scopes = selectedScopes

		patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
		if err != nil {
			return fmt.Errorf("creating service account patch: %w", err)
		}

		if smthChanged {
			err = api.PatchServiceAccount(ctx, apiClient, existingSA.Id.String(), patch)
			if err != nil {
				return fmt.Errorf("updating service account: %w", err)
			}
			logutil.Debugf("Service Account '%s' updated with new public key and scopes: %s", saName, strings.Join(selectedScopes, ", "))
		}
		saID = existingSA.Id.String()
	}

	// Sign JWT and exchange for access token
	signedJWT, err := signServiceAccountJWT(saID, ecKey, currentAuth.APIURL, 30*time.Minute)
	if err != nil {
		return fmt.Errorf("signing JWT: %w", err)
	}

	accessToken, err := exchangeServiceAccountJWT(ctx, currentAuth.APIURL, signedJWT)
	if err != nil {
		return fmt.Errorf("exchanging JWT for access token: %w", err)
	}

	// Save to context
	authToSave := Auth{
		APIURL:             currentAuth.APIURL,
		AuthenticationType: "rsaKey",
		ClientID:           saID,
		PrivateKey:         ecKey,
		AccessToken:        accessToken,
		Username:           saName,
	}

	authToSave, err = saveCurrentContext(ctx, authToSave, contextName, autoSwitch)
	if err != nil {
		return fmt.Errorf("saving configuration for context %v: %w", displayContextForSelection(authToSave), err)
	}

	logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(authToSave))
	return nil
}

// promptServiceAccountName prompts the user to select a service account by name.
// previousSAName is pre-selected if it exists in the list, otherwise first SA is selected.
func promptServiceAccountName(ctx context.Context, apiClient *api.Client, previousSAName string) (string, error) {
	const createNewSAOption = "<create-new-sa>"

	// Fetch all service accounts
	allSAs, err := api.GetServiceAccounts(ctx, apiClient)
	if err != nil {
		return "", fmt.Errorf("fetching service accounts: %w", err)
	}

	// Filter to rsaKey only
	var rsaKeySAs []api.ServiceAccountDetails
	for _, sa := range allSAs {
		if sa.AuthenticationType == "rsaKey" {
			rsaKeySAs = append(rsaKeySAs, sa)
		}
	}

	// Build options - "Create new..." always first
	var options []huh.Option[string]
	options = append(options, huh.NewOption("Create new service account...", createNewSAOption))
	for _, sa := range rsaKeySAs {
		options = append(options, huh.NewOption(sa.Name, sa.Name))
	}

	// Pre-select: previousSAName if it exists, otherwise first rsaKey SA, otherwise "Create new..."
	var selected string
	if previousSAName != "" {
		// Check if previousSAName exists in the list
		found := false
		for _, sa := range rsaKeySAs {
			if sa.Name == previousSAName {
				selected = previousSAName
				found = true
				break
			}
		}
		if !found {
			// Previous SA doesn't exist anymore, fall back to first
			if len(rsaKeySAs) > 0 {
				selected = rsaKeySAs[0].Name
			} else {
				selected = createNewSAOption
			}
		}
	} else if len(rsaKeySAs) > 0 {
		selected = rsaKeySAs[0].Name
	} else {
		selected = createNewSAOption
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Which service account should be used?").
				Description("You can pass --sa to skip this prompt").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.RunWithContext(ctx); err != nil {
		return "", fmt.Errorf("service account selection cancelled: %w", err)
	}

	// If "Create new..." was selected, prompt for name
	if selected == createNewSAOption {
		var newName string
		input := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("New service account name:").
					Description("You can pass --sa <name> to skip this prompt").
					Value(&newName).
					Validate(func(s string) error {
						s = strings.TrimSpace(s)
						if s == "" {
							return fmt.Errorf("service account name cannot be empty")
						}
						return nil
					}),
			),
		)
		if err := input.RunWithContext(ctx); err != nil {
			return "", fmt.Errorf("service account name input cancelled: %w", err)
		}
		return strings.TrimSpace(newName), nil
	}

	return selected, nil
}

// promptScopeSelection prompts the user to select scopes via multi-select.
// currentScopes are pre-selected if they exist in availableScopes.
func promptScopeSelection(ctx context.Context, availableScopes, currentScopes []string) ([]string, error) {
	if len(availableScopes) == 0 {
		return nil, fmt.Errorf("no scopes available for rsaKey authentication type")
	}

	// Build huh options
	var options []huh.Option[string]
	currentScopesMap := make(map[string]bool)
	for _, s := range currentScopes {
		currentScopesMap[s] = true
	}

	for _, scope := range availableScopes {
		options = append(options, huh.NewOption(scope, scope))
	}

	// Pre-select current scopes
	var selected []string
	for _, scope := range availableScopes {
		if currentScopesMap[scope] {
			selected = append(selected, scope)
		}
	}

	// If no current scopes, pre-select all scopes (with only one role scope)
	if len(selected) == 0 {
		var firstRole string
		for _, scope := range availableScopes {
			if strings.Contains(scope, "role") {
				if firstRole == "" {
					firstRole = scope
				}
			} else {
				selected = append(selected, scope)
			}
		}
		// Add the first role scope at the end
		if firstRole != "" {
			selected = append(selected, firstRole)
		}
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select scopes for this service account").
				Description("Use space to select, enter to confirm. You can pass --scope to skip this prompt").
				Options(options...).
				Value(&selected),
		),
	)

	if err := form.RunWithContext(ctx); err != nil {
		return nil, fmt.Errorf("scope selection cancelled: %w", err)
	}

	return selected, nil
}
