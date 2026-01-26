package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	cmd := &cobra.Command{
		Use:           "login-keypair <json-file>",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		Short:         "Authenticate to a CyberArk Certificate Manager, SaaS tenant using a service account keypair.",
		Long: undent.Undent(`
			Authenticate to a CyberArk Certificate Manager, SaaS tenant using a service account keypair.

			This command expects a JSON file containing the service account credentials from 'vcpctl sa gen keypair'.
			Use '-' to read the JSON from stdin.
		`),
		Example: undent.Undent(`
			# Keypair login from file:
			vcpctl login-keypair sa-keypair.json

			# Keypair login from stdin:
			vcpctl sa gen keypair my-sa -ojson | vcpctl login-keypair -
		`),
		GroupID: groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errutil.Fixable(fmt.Errorf("a file path to the JSON authentication file or '-' for stdin is required"))
			}
			saKeyPath := args[0]

			saKey, err := readJSONAuthKeypair(cmd.Context(), saKeyPath)
			if err != nil {
				return err
			}

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

			current, err = saveCurrentContext(cmd.Context(), current, contextFlag)
			if err != nil {
				return fmt.Errorf("saving configuration for context %v: %w", displayContextForSelection(current), err)
			}

			logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(current))
			return nil
		},
	}
	cmd.Flags().StringVar(&contextFlag, "context", "", "Context name to create or update")
	return cmd
}

type jsonAuthKeypair struct {
	Type       string `json:"type"`
	ClientID   string `json:"client_id"`
	PrivateKey string `json:"private_key"`
	APIURL     string `json:"api_url"`

	// Optional. Useful because it lets us fill in the tenant URL in
	// ~/.config/vcpctl.yaml.
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

	audience := fmt.Sprintf("%s/v1/oauth/token/serviceaccount", strings.TrimPrefix(strings.TrimSuffix(apiURL, "/"), "https://"))
	logutil.Debugf("Using audience: %s", audience)
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
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
