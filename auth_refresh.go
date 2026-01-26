package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/logutil"
)

type accessTokenSource struct {
	mu    sync.RWMutex
	token string
}

func newAccessTokenSource(token string) *accessTokenSource {
	return &accessTokenSource{token: token}
}

func (s *accessTokenSource) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *accessTokenSource) Set(token string) {
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
}

type refreshingAccessTokenTransport struct {
	base    http.RoundTripper
	source  *accessTokenSource
	refresh func(context.Context) (string, error)
	mu      sync.Mutex
}

func (t *refreshingAccessTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.applyToken(req)

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || t.refresh == nil {
		return resp, err
	}

	if req.Body != nil && req.GetBody == nil {
		return resp, err
	}

	_, err = t.refreshIfNeeded(req.Context())
	if err != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}

	if resp.Body != nil {
		_ = resp.Body.Close()
	}

	retryReq, err := cloneRequest(req)
	if err != nil {
		return nil, err
	}
	t.applyToken(retryReq)

	return t.base.RoundTrip(retryReq)
}

func (t *refreshingAccessTokenTransport) applyToken(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+t.source.Token())
}

func (t *refreshingAccessTokenTransport) refreshIfNeeded(ctx context.Context) (string, error) {
	previous := t.source.Token()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.source.Token() != previous {
		return t.source.Token(), nil
	}

	newToken, err := t.refresh(ctx)
	if err != nil {
		return "", err
	}

	t.source.Set(newToken)
	return newToken, nil
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	newReq := req.Clone(req.Context())
	newReq.Header = req.Header.Clone()
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq.Body = body
	}
	return newReq, nil
}

func buildAccessTokenRefresher(conf ToolConf) func(context.Context) (string, error) {
	switch conf.AuthenticationType {
	case "rsaKeyFederated":
		return func(ctx context.Context) (string, error) {
			return refreshWIFAccessToken(ctx, conf)
		}
	case "rsaKey":
		return func(ctx context.Context) (string, error) {
			return refreshKeypairAccessToken(ctx, conf)
		}
	default:
		return nil
	}
}

func refreshWIFAccessToken(ctx context.Context, conf ToolConf) (string, error) {
	if conf.PrivateKey == "" {
		return "", fmt.Errorf("missing private key for WIF authentication")
	}
	if conf.IssuerURL == "" || conf.Subject == "" || conf.Audience == "" {
		return "", fmt.Errorf("missing issuer, subject, or audience for WIF authentication")
	}
	if conf.TenantID == "" {
		return "", fmt.Errorf("missing tenant ID for WIF authentication")
	}

	privKey, kid, err := parseWIFPrivateKey(conf.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("while parsing WIF private key: %w", err)
	}

	jwtString, err := signWIFJWT(privKey, kid, conf.IssuerURL, conf.Subject, conf.Audience, 2*time.Hour)
	if err != nil {
		return "", fmt.Errorf("while signing WIF JWT: %w", err)
	}

	accessToken, err := exchangeJWTForAccessToken(ctx, conf.APIURL, conf.TenantID, jwtString)
	if err != nil {
		if wrapped := maybeWrapTokenSignatureError(err, conf); wrapped != nil {
			return "", wrapped
		}
		return "", fmt.Errorf("while exchanging WIF JWT for access token: %w", err)
	}

	persistAccessToken(ctx, conf, accessToken)
	return accessToken, nil
}

func refreshKeypairAccessToken(ctx context.Context, conf ToolConf) (string, error) {
	if conf.PrivateKey == "" {
		return "", fmt.Errorf("missing private key for keypair authentication")
	}
	if conf.ClientID == "" {
		return "", fmt.Errorf("missing client ID for keypair authentication")
	}

	signedJWT, err := signServiceAccountJWT(conf.ClientID, conf.PrivateKey, conf.APIURL, 30*time.Minute)
	if err != nil {
		return "", fmt.Errorf("while signing service account JWT: %w", err)
	}

	accessToken, err := exchangeServiceAccountJWT(ctx, conf.APIURL, signedJWT)
	if err != nil {
		if wrapped := maybeWrapTokenSignatureError(err, conf); wrapped != nil {
			return "", wrapped
		}
		return "", fmt.Errorf("while exchanging service account JWT for access token: %w", err)
	}

	persistAccessToken(ctx, conf, accessToken)
	return accessToken, nil
}

func persistAccessToken(ctx context.Context, conf ToolConf, accessToken string) {
	if conf.ContextName == "" {
		return
	}

	fileConf, err := loadFileConf(ctx)
	if err != nil {
		logutil.Debugf("while loading config for token refresh: %v", err)
		return
	}

	for i := range fileConf.ToolContexts {
		if fileConf.ToolContexts[i].Name == conf.ContextName {
			fileConf.ToolContexts[i].AccessToken = accessToken
			if err := saveFileConf(fileConf); err != nil {
				logutil.Debugf("while saving refreshed access token: %v", err)
			}
			return
		}
	}

	logutil.Debugf("context %q not found while saving refreshed access token", conf.ContextName)
}

func newAccessTokenAPIClient(conf ToolConf) (*api.Client, error) {
	source := newAccessTokenSource(conf.AccessToken)
	refresh := buildAccessTokenRefresher(conf)

	var transport http.RoundTripper = api.LogTransport
	if refresh != nil {
		transport = &refreshingAccessTokenTransport{
			base:    api.LogTransport,
			source:  source,
			refresh: refresh,
		}
	}

	client := &http.Client{Transport: transport}
	return api.NewClient(conf.APIURL,
		api.WithHTTPClient(client),
		api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+source.Token())
			req.Header.Set("User-Agent", api.UserAgent)
			return nil
		}),
	)
}

type tokenExchangeError struct {
	StatusCode       int
	Status           string
	Body             string
	ErrorCode        string
	ErrorDescription string
}

func (e tokenExchangeError) Error() string {
	if e.ErrorCode != "" || e.ErrorDescription != "" {
		return fmt.Sprintf("token endpoint returned %s: %s %s", e.Status, e.ErrorCode, e.ErrorDescription)
	}
	if strings.TrimSpace(e.Body) == "" {
		return fmt.Sprintf("token endpoint returned %s", e.Status)
	}
	return fmt.Sprintf("token endpoint returned %s: %s", e.Status, strings.TrimSpace(e.Body))
}

func newTokenExchangeError(statusCode int, status string, body []byte) error {
	parsed := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{}

	bodyStr := strings.TrimSpace(string(body))
	if err := json.Unmarshal(body, &parsed); err != nil {
		return tokenExchangeError{
			StatusCode: statusCode,
			Status:     status,
			Body:       bodyStr,
		}
	}

	return tokenExchangeError{
		StatusCode:       statusCode,
		Status:           status,
		Body:             bodyStr,
		ErrorCode:        parsed.Error,
		ErrorDescription: parsed.ErrorDescription,
	}
}

func maybeWrapTokenSignatureError(err error, conf ToolConf) error {
	var tokenErr tokenExchangeError
	if !errors.As(err, &tokenErr) {
		return nil
	}
	if tokenErr.StatusCode != http.StatusBadRequest {
		return nil
	}
	if !strings.Contains(tokenErr.ErrorDescription, "token_signature_verification_error") {
		return nil
	}

	fingerprint, fpErr := publicKeyFingerprintFromPrivateKey(conf.PrivateKey)
	if fpErr != nil {
		return fmt.Errorf("while computing private key fingerprint after token signature error: %w", fpErr)
	}

	contextName := conf.ContextName
	if contextName == "" {
		contextName = "main"
	}

	clientID := conf.ClientID
	if clientID == "" {
		clientID = "<id>"
	}

	return fmt.Errorf(
		"The API returned the error %d %s, which may indicate a mismatch between the private key present in your context and the public key registered for this service account in the API. The SHA-256 fingerprint of the private key is:\n\n"+
			"  %s\n\n"+
			"Please switch context to an API key context with:\n\n"+
			"  vcpctl switch\n\n"+
			"Then, run the following command to compare this fingerprint with the fingerprint of the public key known to the API:\n\n"+
			"  vcpctl sa get %s --raw -ojson | jq .publicKey -r | openssl pkey -pubin -outform DER | openssl sha256",
		tokenErr.StatusCode,
		tokenErr.ErrorDescription,
		fingerprint,
		clientID,
	)
}

func publicKeyFingerprintFromPrivateKey(privateKeyPEM string) (string, error) {
	pubKey, err := publicKeyFromPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("while marshaling public key: %w", err)
	}

	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func publicKeyFromPrivateKeyPEM(privateKeyPEM string) (interface{}, error) {
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
				return nil, fmt.Errorf("while parsing PKCS8 private key: %w", err)
			}
			switch k := key.(type) {
			case *rsa.PrivateKey:
				return &k.PublicKey, nil
			case *ecdsa.PrivateKey:
				return &k.PublicKey, nil
			default:
				return nil, fmt.Errorf("unsupported private key type %T", key)
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("while parsing EC private key: %w", err)
			}
			return &key.PublicKey, nil
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("while parsing RSA private key: %w", err)
			}
			return &key.PublicKey, nil
		}
	}

	return nil, fmt.Errorf("no PEM block found in private key")
}
