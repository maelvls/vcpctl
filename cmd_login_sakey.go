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
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
)

type serviceAccountKeyInput struct {
	Type       string `json:"type"`
	ClientID   string `json:"client_id"`
	PrivateKey string `json:"private_key"`
	APIURL     string `json:"api_url"`
}

type serviceAccountTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func loginWithServiceAccountKey(ctx context.Context, args []string, saKeyPath, apiURLFlag string, contextName string) error {
	if saKeyPath == "" {
		return errutil.Fixable(fmt.Errorf("--sa-keypair requires a JSON file path or '-' for stdin"))
	}

	saKey, err := readServiceAccountKeyInput(saKeyPath)
	if err != nil {
		return err
	}

	// Determine the API URL.
	var apiURL string
	if apiURLFlag != "" {
		apiURL = apiURLFlag
	} else if len(args) > 0 {
		tenantURL := args[0]
		if !strings.HasPrefix(tenantURL, "https://") && !strings.HasPrefix(tenantURL, "http://") {
			tenantURL = "https://" + tenantURL
		}
		httpCl := http.Client{Transport: api.LogTransport}
		info, err := api.GetTenantInfoFromTenantURL(httpCl, tenantURL)
		if err != nil {
			return fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
		}
		apiURL = info.APIURL
	} else {
		return errutil.Fixable(fmt.Errorf("--api-url or tenant URL is required for --sa-keypair"))
	}

	apiURL = strings.TrimRight(apiURL, "/")
	if !strings.HasPrefix(apiURL, "https://") && !strings.HasPrefix(apiURL, "http://") {
		apiURL = "https://" + apiURL
	}

	signedJWT, err := signServiceAccountJWT(saKey.ClientID, saKey.PrivateKey, apiURL, 30*time.Minute)
	if err != nil {
		return fmt.Errorf("while signing JWT: %w", err)
	}

	accessToken, err := exchangeServiceAccountJWT(ctx, apiURL, signedJWT)
	if err != nil {
		return fmt.Errorf("while exchanging JWT for access token: %w", err)
	}

	cl, err := api.NewAccessTokenClient(apiURL, accessToken)
	if err != nil {
		return fmt.Errorf("while creating access-token client: %w", err)
	}

	self, tenantURL, err := api.SelfCheck(ctx, cl)
	if err != nil {
		return fmt.Errorf("while checking the access token's validity: %w", err)
	}

	current := Auth{
		TenantURL:          tenantURL,
		APIURL:             apiURL,
		AuthenticationType: "rsaKey",
		ClientID:           saKey.ClientID,
		PrivateKey:         saKey.PrivateKey,
		AccessToken:        accessToken,
		TenantID:           self.Company.Id.String(),
	}

	if err := saveCurrentContext(current, contextName); err != nil {
		return fmt.Errorf("saving configuration for %s: %w", current.TenantURL, err)
	}

	logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.TenantURL)
	return nil
}

func readServiceAccountKeyInput(path string) (serviceAccountKeyInput, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return serviceAccountKeyInput{}, fmt.Errorf("while reading %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return serviceAccountKeyInput{}, errutil.Fixable(fmt.Errorf("empty service account JSON"))
	}

	var input serviceAccountKeyInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return serviceAccountKeyInput{}, fmt.Errorf("while parsing JSON: %w", err)
	}

	input.ClientID = strings.TrimSpace(input.ClientID)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	if input.ClientID == "" {
		return serviceAccountKeyInput{}, errutil.Fixable(fmt.Errorf("missing 'client_id'"))
	}
	if input.PrivateKey == "" {
		return serviceAccountKeyInput{}, errutil.Fixable(fmt.Errorf("missing 'private_key'"))
	}
	if input.APIURL == "" {
		return serviceAccountKeyInput{}, errutil.Fixable(fmt.Errorf("missing 'api_url'"))
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
		return "", fmt.Errorf("token endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
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
