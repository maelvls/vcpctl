package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/cancellablereader"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"

	"github.com/golang-jwt/jwt/v5"
)

type jwksKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwksSet struct {
	Keys []jwksKey `json:"keys"`
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func generateWIFKeyPairAndJWKS() (privPEM string, kid string, jwksPayload []byte, _ error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", nil, err
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

	kid = jwkThumbprintEC(&priv.PublicKey)
	jwksPayload, err = json.MarshalIndent(jwksSet{
		Keys: []jwksKey{
			{
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()),
				Use: "sig",
				Alg: "ES256",
				Kid: kid,
			},
		},
	}, "", "  ")
	if err != nil {
		return "", "", nil, err
	}

	return privPEM, kid, jwksPayload, nil
}

func signWIFJWT(priv *ecdsa.PrivateKey, kid, issuer, subject, audience string, validity time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(time.Now().Add(validity)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	return token.SignedString(priv)
}

// The token exchange URL looks like this:
//
//	https://api.venafi.cloud/v1/oauth2/v2.0/<tenant-id>/token
//
// Body:
// BODY :
//
//	grant_type=client_credentials&\
//	client_assertion=<access token>&\
//	client_assertion_type=jwt-bearer
func exchangeJWTForAccessToken(ctx context.Context, apiURL, tenantID string, signedJWT string) (string, error) {
	apiURL = strings.TrimRight(apiURL, "/")
	endpoint := fmt.Sprintf("%s/v1/oauth2/v2.0/%s/token", apiURL, tenantID)
	form := url.Values{
		"grant_type":            []string{"client_credentials"},
		"client_assertion":      []string{signedJWT},
		"client_assertion_type": []string{"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("while creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	var parsed oauthTokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("while parsing token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token")
	}
	return parsed.AccessToken, nil
}

func jwkThumbprintEC(pub *ecdsa.PublicKey) string {
	h := sha256.New()
	fmt.Fprintf(h, `{"crv":"%s"`, pub.Curve.Params().Name)
	fmt.Fprintf(h, `,"kty":"EC"`)
	fmt.Fprintf(h, `,"x":"%s"`, base64.RawURLEncoding.EncodeToString(pub.X.Bytes()))
	fmt.Fprintf(h, `,"y":"%s"}`, base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func uploadJWKS0x0(jwks []byte) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "jwks.json")
	if err != nil {
		return "", fmt.Errorf("while creating multipart form: %w", err)
	}
	if _, err := part.Write(jwks); err != nil {
		return "", fmt.Errorf("while writing jwks file: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("while closing multipart writer: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://0x0.st", &body)
	if err != nil {
		return "", fmt.Errorf("while creating request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", api.UserAgent)

	client := &http.Client{Timeout: 30 * time.Second, Transport: api.LogTransport}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("while uploading JWKS: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("while reading 0x0.st response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("0x0.st returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	url := strings.TrimSpace(string(respBody))
	if url == "" {
		return "", fmt.Errorf("0x0.st returned an empty URL")
	}
	return url, nil
}

type wifJSON struct {
	Type string `json:"type"`

	// The client ID isn't really needed to authenticate (we only need the
	// tenant ID). However, it allows us to identify the service account used,
	// which is something we use to know when two contexts are the same.
	ClientID string `json:"client_id"`
	JWKSURL  string `json:"jwks_url"`

	// Allow you generate new ID tokens for requesting new access tokens.
	PrivateKey string `json:"private_key"`
	Iss        string `json:"iss"`
	Aud        string `json:"aud"`
	Sub        string `json:"sub"`

	// Optional. Useful because it lets us fill in the tenant URL in
	// ~/.config/vcpctl.yaml.
	TenantURL string `json:"tenant_url"`
}

func loginWithWIFJSON(ctx context.Context, wifJSONPath string, contextName string) error {
	if wifJSONPath == "" {
		return errutil.Fixable(fmt.Errorf("--sa-wif requires a JSON file path or '-' for stdin"))
	}

	var reader io.Reader
	if wifJSONPath == "-" {
		reader = os.Stdin
	} else {
		var err error
		reader, err = os.Open(wifJSONPath)
		if err != nil {
			return fmt.Errorf("while opening %s: %w", wifJSONPath, err)
		}
	}

	raw, err := cancellablereader.ReadAllWithContext(ctx, reader)
	if err != nil {
		return fmt.Errorf("while reading %s: %w", wifJSONPath, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return errutil.Fixable(fmt.Errorf("empty WIF JSON"))
	}

	var input wifJSON
	if err := json.Unmarshal(raw, &input); err != nil {
		return fmt.Errorf("while parsing JSON: %w", err)
	}

	input.ClientID = strings.TrimSpace(input.ClientID)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	input.TenantURL = strings.TrimSpace(input.TenantURL)

	if input.PrivateKey == "" {
		return errutil.Fixable(fmt.Errorf("missing 'private_key' in JSON"))
	}
	if input.ClientID == "" {
		return errutil.Fixable(fmt.Errorf("missing 'client_id' in JSON"))
	}
	if input.TenantURL == "" {
		return errutil.Fixable(fmt.Errorf("missing 'tenant_url' in JSON"))
	}
	if !strings.HasPrefix(input.TenantURL, "https://") && !strings.HasPrefix(input.TenantURL, "http://") {
		input.TenantURL = "https://" + input.TenantURL
	}

	privKey, kid, err := parseWIFPrivateKey(input.PrivateKey)
	if err != nil {
		return fmt.Errorf("while parsing private key: %w", err)
	}

	validity := 2 * time.Hour
	jwtString, err := signWIFJWT(privKey, kid, input.Iss, input.Sub, input.Aud, validity)
	if err != nil {
		return fmt.Errorf("while signing JWT: %w", err)
	}

	cl := http.Client{Transport: api.LogTransport}
	info, err := api.GetTenantInfoFromTenantURL(cl, input.TenantURL)
	if err != nil {
		return fmt.Errorf("while getting tenant info: %w", err)
	}

	// TODO: This logic should be run anytime a 401 is received, for for now,
	// let's just do it once.
	var accessToken string
	retryDeadline := time.Now().Add(5 * time.Minute)
	for {
		accessToken, err = exchangeJWTForAccessToken(ctx, info.APIURL, info.TenantID, jwtString)
		if err == nil {
			break
		}
		logutil.Debugf("While exchanging JWT for access token: %v", err)
		if time.Now().After(retryDeadline) {
			return fmt.Errorf("while exchanging JWT for access token: %w", err)
		}
		logutil.Infof("Waiting for WIF setup to be ready... Retrying in 5 seconds.")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	current := Auth{
		TenantURL:          input.TenantURL,
		APIURL:             info.APIURL,
		AuthenticationType: "rsaKeyFederated",
		ClientID:           input.ClientID,
		AccessToken:        accessToken,
		PrivateKey:         input.PrivateKey,
		TenantID:           info.TenantID,
	}

	if err := saveCurrentContext(ctx, current, contextName); err != nil {
		return fmt.Errorf("saving configuration for %s: %w", current.TenantURL, err)
	}

	logutil.Infof("✅  You are now authenticated with a WIF service account")
	return nil
}

func parseWIFPrivateKey(privateKeyPEM string) (*ecdsa.PrivateKey, string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, "", errutil.Fixable(fmt.Errorf("no PEM block found in private key"))
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("while parsing PKCS8 private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("private key is not an ECDSA key")
	}

	kid := jwkThumbprintEC(&ecKey.PublicKey)
	return ecKey, kid, nil
}

func deriveUIURL(apiURL string) string {
	apiURL = strings.TrimRight(apiURL, "/")
	apiURL = strings.TrimPrefix(apiURL, "https://")
	apiURL = strings.TrimPrefix(apiURL, "http://")

	if strings.HasPrefix(apiURL, "api-") {
		return "https://" + strings.Replace(apiURL, "api-", "ui-stack-", 1)
	}
	if strings.HasPrefix(apiURL, "api.") {
		parts := strings.Split(apiURL, ".")
		if len(parts) > 1 {
			return "https://" + strings.Join(parts[1:], ".")
		}
	}
	return "https://" + apiURL
}
