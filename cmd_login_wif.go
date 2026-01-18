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
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"

	"github.com/golang-jwt/jwt/v5"
)

type wifLoginParams struct {
	ServiceAccount string
	Scopes         []string
	APIURL         string
	APIKey         string
}

const (
	defaultWIFAudience = "venafi-cloud"
	defaultWIFIssuer   = "https://issuer.example.com"
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

func loginWithWIF(ctx context.Context, args []string, p wifLoginParams) error {
	if p.ServiceAccount == "" {
		return errutil.Fixable(fmt.Errorf("--wif requires a service account name that will be created or updated"))
	}

	apiURL, tenantURL, err := resolveLoginAPIURL(args, p.APIURL)
	if err != nil {
		return err
	}

	apiKey := p.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("VEN_API_KEY")
	}
	if apiKey == "" {
		key, err := promptString("API Key: ", func(input string) error {
			if strings.TrimSpace(input) == "" {
				return fmt.Errorf("API key cannot be empty")
			}
			return nil
		})
		if err != nil {
			return err
		}
		apiKey = key
	}

	apiURL = strings.TrimRight(apiURL, "/")
	cl, err := api.NewAPIKeyClient(apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while creating API client: %w", err)
	}

	selfCheck, err := api.SelfCheck(ctx, cl)
	if err != nil {
		return fmt.Errorf("while checking the API key's validity: %w", err)
	}

	if tenantURL == "" {
		tenantURL = fmt.Sprintf("%s.venafi.cloud", selfCheck.Company.UrlPrefix)
		if tenantURL == "stack" {
			tenantURL = apiURL
			tenantURL = strings.Replace(tenantURL, "api-", "ui-stack-", 1)
		}
	}

	privKey, privKeyPEM, kid, jwksPayload, err := generateWIFKeyPairAndJWKS()
	if err != nil {
		return fmt.Errorf("while generating key pair: %w", err)
	}

	jwksURL, err := uploadJWKS0x0(jwksPayload)
	if err != nil {
		return fmt.Errorf("while uploading JWKS to 0x0.st: %w", err)
	}
	logutil.Debugf("JWKS uploaded to: %s", jwksURL)

	saName := p.ServiceAccount
	subjectValue := ""
	audienceValue := ""
	issuerURL := ""
	saID := ""

	if subjectValue == "" {
		subjectValue = fmt.Sprintf("system:serviceaccount:default:%s", saName)
	}
	if audienceValue == "" {
		audienceValue = defaultWIFAudience
	}
	if issuerURL == "" {
		issuerURL = defaultWIFIssuer
	}

	existingSA, err := api.GetServiceAccount(ctx, cl, saName)
	if err != nil {
		if !errutil.ErrIsNotFound(err) {
			return fmt.Errorf("while getting service account: %w", err)
		}

		// Defaults already applied when values are empty.

		// For some reason, the service account requires at least one
		// application. Let's pick the first available one.
		var app api.ApplicationInformation
		availableApps, err := api.GetApplications(ctx, cl)
		if err != nil {
			return fmt.Errorf("while retrieving available applications: %w", err)
		}
		if len(availableApps) == 0 {
			return fmt.Errorf("no application provided and no application available in the account")
		}
		app = availableApps[0]
		logutil.Debugf("Using the first application found: %s (%s)", app.Name, app.Id.String())

		// For some reason, the service account requires an owner team. Let's
		// pick the first one that comes up.
		teams, err := api.GetTeams(ctx, cl)
		if err != nil {
			return fmt.Errorf("sa put wif: while retrieving available teams: %w", err)
		}
		if len(teams) == 0 {
			return fmt.Errorf("sa put wif: no owner team provided and no team available in the account")
		}
		owner := teams[0].Id
		logutil.Debugf("Using the first team found as an owner: %s (%s)", teams[0].Name, teams[0].Id.String())

		resp, err := api.CreateServiceAccount(ctx, cl, api.ServiceAccountDetails{
			Name:               saName,
			AuthenticationType: "rsaKeyFederated",
			Scopes:             p.Scopes,
			Subject:            subjectValue,
			Audience:           audienceValue,
			IssuerURL:          issuerURL,
			JwksURI:            jwksURL,
			Applications:       []uuid.UUID{app.Id},
			Owner:              owner,
		})
		if err != nil {
			return fmt.Errorf("while creating service account: %w", err)
		}
		saID = resp.Id.String()
		logutil.Debugf("Service Account '%s' created with JWKS URI: %s", saName, jwksURL)
	} else {
		if existingSA.AuthenticationType != "rsaKeyFederated" {
			return errutil.Fixable(fmt.Errorf("service account '%s' must be authenticationType 'rsaKeyFederated' for WIF", saName))
		}
		if existingSA.Subject == "" {
			return errutil.Fixable(fmt.Errorf("service account '%s' has an empty subject; set it with 'vcpctl sa put wif %s'", saName, saName))
		}
		if existingSA.Audience == "" {
			return errutil.Fixable(fmt.Errorf("service account '%s' has an empty audience; set it with 'vcpctl sa put wif %s'", saName, saName))
		}

		subjectValue = existingSA.Subject
		audienceValue = existingSA.Audience
		if issuerURL == "" {
			issuerURL = existingSA.IssuerURL
		}
		if issuerURL == "" {
			issuerURL = defaultWIFIssuer
		}

		desiredSA := existingSA
		desiredSA.JwksURI = jwksURL
		desiredSA.IssuerURL = issuerURL

		patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
		if err != nil {
			return fmt.Errorf("while creating service account patch: %w", err)
		}
		if smthChanged {
			err = api.PatchServiceAccount(ctx, cl, existingSA.Id.String(), patch)
			if err != nil {
				return fmt.Errorf("while patching service account: %w", err)
			}
		} else {
			logutil.Debugf("Service Account '%s' is already up to date.", saName)
		}
		saID = existingSA.Id.String()
	}

	// I found this to be the maximum accepted by Venafi Cloud.
	validity := 2 * time.Hour
	jwtString, err := signWIFJWT(privKey, kid, issuerURL, subjectValue, audienceValue, validity)
	if err != nil {
		return fmt.Errorf("while signing JWT: %w", err)
	}

	tenantID := selfCheck.Company.Id.String()

	// Try for 5 minutes to get the access token, in case the SA creation
	// or update hasn't fully propagated yet.
	var accessToken string
	retryDeadline := time.Now().Add(5 * time.Minute)
	for {
		accessToken, err = exchangeJWTForAccessToken(ctx, apiURL, tenantID, jwtString)
		if err == nil {
			break
		}
		logutil.Debugf("While exchanging JWT for access token: %v", err)
		if time.Now().After(retryDeadline) {
			return fmt.Errorf("while exchanging JWT for access token: %w", err)
		}
		logutil.Infof("Waiting for service account to be ready... Retrying in 5 seconds.")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	current := Auth{
		URL:           tenantURL,
		APIURL:        apiURL,
		APIKey:        apiKey,
		AccessToken:   accessToken,
		WIFPrivateKey: privKeyPEM,
		TenantID:      selfCheck.Company.Id.String(),
	}

	if err := saveCurrentTenant(current); err != nil {
		return fmt.Errorf("saving configuration for %s: %w", current.URL, err)
	}

	logutil.Infof("✅  You are now authenticated to tenant '%s'.", current.URL)
	logutil.Debugf("Service Account ID: %s", saID)
	return nil
}

func resolveLoginAPIURL(args []string, flagAPIURL string) (string, string, error) {
	if len(args) > 0 {
		tenantURL := strings.TrimRight(args[0], "/")
		if !strings.HasPrefix(tenantURL, "https://") && !strings.HasPrefix(tenantURL, "http://") {
			tenantURL = "https://" + tenantURL
		}
		httpCl := http.Client{Transport: api.LogTransport}
		apiURLFromTenant, err := api.GetAPIURLFromTenantURL(httpCl, tenantURL)
		switch {
		case err == nil:
			return apiURLFromTenant, tenantURL, nil
		case errors.As(err, &errutil.NotFound{}):
			return "", "", fmt.Errorf("URL '%s' doesn't seem to be a valid tenant. Please check the URL and try again.", tenantURL)
		default:
			return "", "", fmt.Errorf("while getting API URL for tenant '%s': %w", tenantURL, err)
		}
	}

	apiURL := flagAPIURL
	if apiURL == "" {
		apiURL = os.Getenv("VEN_API_URL")
	}
	if apiURL == "" {
		return "", "", errutil.Fixable(fmt.Errorf("--api-url (or VEN_API_URL) is required for --wif when no tenant URL is provided"))
	}
	if !strings.HasPrefix(apiURL, "https://") && !strings.HasPrefix(apiURL, "http://") {
		apiURL = "https://" + apiURL
	}
	return apiURL, "", nil
}

func generateWIFKeyPairAndJWKS() (*ecdsa.PrivateKey, string, string, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", "", nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	kid := jwkThumbprintEC(&priv.PublicKey)
	jwksPayload, err := json.MarshalIndent(jwksSet{
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
		return nil, "", "", nil, err
	}

	return priv, string(privPEM), kid, jwksPayload, nil
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
