package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

func saGenWifCmd() *cobra.Command {
	var outputFormat string
	var scopes []string
	var subject string
	var audience string
	var issuerURL string
	var apps []string
	var ownerTeam string
	cmd := &cobra.Command{
		Use:   "wif <sa-name>",
		Short: "Generates an EC private key, creates JWKS, uploads it to 0x0.st, and creates/updates a WIF Service Account",
		Long: undent.Undent(`
			Generates an EC private key, creates a JWKS (JSON Web Key Set), uploads
			it to 0x0.st, and creates or updates a Workload Identity Federation Service Account.

			This command is useful for setting up Workload Identity Federation authentication.
			The output can be piped directly to 'vcpctl login --sa-wif'.

			With '-ojson', the output looks like:

			  {
			    "type": "rsaKeyFederated",
			    "client_id": "b4dd2b31-f473-11f0-aa2c-f69f144f25db",
			    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
			    "api_url": "https://api.venafi.cloud",
				"jwks_url": "https://0x0.st/abcd.json",
				"iss": "https://0x0.st/abcd.json",
				"aud": "venafi-cloud",
				"sub": "system:serviceaccount:default:my-sa"
			  }
		`),
		Example: undent.Undent(`
			vcpctl sa gen wif my-sa -ojson
			vcpctl sa gen wif my-sa -ojson | vcpctl login --sa-wif -
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			saName := args[0]

			privKey, privKeyPEM, kid, jwksPayload, err := generateWIFKeyPairAndJWKS()
			if err != nil {
				return fmt.Errorf("while generating key pair: %w", err)
			}

			jwksURL, err := uploadJWKS0x0(jwksPayload)
			if err != nil {
				return fmt.Errorf("while uploading JWKS to 0x0.st: %w", err)
			}
			logutil.Debugf("JWKS uploaded to: %s", jwksURL)

			// Suppress unused variable warnings for now
			_ = privKey
			_ = kid

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Set defaults.
			if subject == "" {
				subject = fmt.Sprintf("system:serviceaccount:default:%s", saName)
			}
			if audience == "" {
				audience = "venafi-cloud"
			}
			if issuerURL == "" {
				issuerURL = jwksURL
			}

			// Parse applications (UUIDs).
			applications := make([]api.Application, len(apps))
			for i, app := range apps {
				appUUID := openapi_types.UUID{}
				err := appUUID.UnmarshalText([]byte(app))
				if err != nil {
					return fmt.Errorf("invalid application UUID '%s': %w", app, err)
				}
				applications[i] = appUUID
			}

			// If no application is provided, let's pick the first one available.
			if len(applications) == 0 {
				availableApps, err := api.GetApplications(context.Background(), apiClient)
				if err != nil {
					return fmt.Errorf("while retrieving available applications: %w", err)
				}
				if len(availableApps) == 0 {
					return fmt.Errorf("no application provided and no application available in the account")
				}
				applications = []api.Application{availableApps[0].Id}
				logutil.Debugf("No application provided, using the first available one: %s (%s)", availableApps[0].Name, availableApps[0].Id.String())
			}

			// Parse owner team (UUID) if provided.
			owner := openapi_types.UUID{}
			if ownerTeam != "" {
				err := owner.UnmarshalText([]byte(ownerTeam))
				if err != nil {
					return fmt.Errorf("invalid owner team UUID '%s': %w", ownerTeam, err)
				}
			}

			// If no owner team is provided, let's pick the first one available.
			if ownerTeam == "" {
				teams, err := api.GetTeams(context.Background(), apiClient)
				if err != nil {
					return fmt.Errorf("while retrieving available teams: %w", err)
				}
				if len(teams) == 0 {
					return fmt.Errorf("no owner team provided and no team available in the account")
				}
				owner = teams[0].Id
				logutil.Debugf("No owner team provided, using the first available one: %s (%s)", teams[0].Name, teams[0].Id.String())
			}

			// Scopes can't be empty. When empty, a '500 Internal Server Error'
			// is returned by the API. So, if the user doesn't set any scope,
			// let's go with the biggest set of scopes for that auth type.
			if len(scopes) == 0 {
				availScopes, err := api.GetServiceAccountScopes(cmd.Context(), apiClient)
				if err != nil {
					return fmt.Errorf("while retrieving service account scopes: %w", err)
				}
				for _, s := range availScopes {
					if s.AuthenticationType != "rsaKeyFederated" {
						continue
					}
					scopes = append(scopes, s.Id)
				}
			}
			if len(scopes) == 0 {
				return fmt.Errorf("at least one scope must be specified for the service account using --scope")
			}

			// Check if service account exists.
			existingSA, err := api.GetServiceAccount(context.Background(), apiClient, saName)
			var clientID string
			switch {
			case errutil.ErrIsNotFound(err):
				// Doesn't exist yet, create it.
				resp, err := api.CreateServiceAccount(context.Background(), apiClient, api.ServiceAccountDetails{
					Name:               saName,
					AuthenticationType: "rsaKeyFederated",
					Scopes:             scopes,
					Subject:            subject,
					Audience:           audience,
					IssuerURL:          issuerURL,
					JwksURI:            jwksURL,
					Applications:       applications,
					Owner:              owner,
				})
				if err != nil {
					return fmt.Errorf("while creating service account: %w", err)
				}
				clientID = resp.Id.String()

				logutil.Debugf("Service Account '%s' created with JWKS URI: %s", saName, jwksURL)
			case err == nil:
				// Exists, update it
				desiredSA := existingSA
				desiredSA.Subject = subject
				desiredSA.Audience = audience
				desiredSA.IssuerURL = issuerURL
				desiredSA.JwksURI = jwksURL
				if len(scopes) > 0 {
					desiredSA.Scopes = scopes
				}
				if len(applications) > 0 {
					desiredSA.Applications = applications
				}

				patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
				if err != nil {
					return fmt.Errorf("while creating service account patch: %w", err)
				}
				if !smthChanged {
					logutil.Debugf("Service Account '%s' is already up to date.", saName)
				} else {
					err = api.PatchServiceAccount(context.Background(), apiClient, existingSA.Id.String(), patch)
					if err != nil {
						return fmt.Errorf("while patching service account: %w", err)
					}
					logutil.Debugf("Service Account '%s' updated.", saName)
				}
				clientID = existingSA.Id.String()
			default:
				return fmt.Errorf("while checking if service account exists: %w", err)
			}

			// At this point, we need to know the tenant URL; if we are
			// authenticated using an API key, then we can fetch it.
			var tenantURL string
			if conf.APIKey != "" {
				_, tenantURL, err = api.SelfCheck(cmd.Context(), apiClient)
				if err != nil {
					return fmt.Errorf("while getting tenant URL from API key: %w", err)
				}
			} else {
				return fmt.Errorf("can only use an API key to generate WIF credentials. This is because we need to determine the tenant URL, but /v1/useraccounts is only available for API key authentication, not when using an access token tied to a service account")
			}

			switch outputFormat {
			case "json":
				output := wifJSON{
					Type:       "rsaKeyFederated",
					ClientID:   clientID,
					PrivateKey: privKeyPEM,
					TenantURL:  tenantURL,
					JWKSURL:    jwksURL,
					Iss:        issuerURL,
					Aud:        audience,
					Sub:        subject,
				}

				bytes, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					return fmt.Errorf("while marshaling JSON: %w", err)
				}
				fmt.Println(string(bytes))
			default:
				return errutil.Fixable(fmt.Errorf("invalid output format: %s (only 'json' is supported)", outputFormat))
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (only 'json' is supported)")
	cmd.Flags().StringArrayVar(&scopes, "scope", []string{}, "Scopes for the Service Account (can be specified multiple times)")
	cmd.Flags().StringVar(&subject, "subject", "", "The subject of the entity (defaults to 'system:serviceaccount:default:<sa-name>')")
	cmd.Flags().StringVar(&audience, "audience", "", "The intended audience (defaults to 'venafi-cloud')")
	cmd.Flags().StringVar(&issuerURL, "issuer-url", "", "The issuer URL (defaults to the JWKS URL)")
	cmd.Flags().StringArrayVar(&apps, "app", []string{}, "Application UUID (can be specified multiple times, defaults to first available)")
	cmd.Flags().StringVar(&ownerTeam, "owner-team", "", "Owner team UUID (defaults to first available)")
	return cmd
}

func saPutWifCmd() *cobra.Command {
	var scopes []string
	var subject string
	var audience string
	var issuerURL string
	var jwksURI string
	var apps []string
	var ownerTeam string
	cmd := &cobra.Command{
		Use:   "wif <sa-name>",
		Short: "Creates or updates the given Workload Identity Federation Service Account (authenticationType: 'rsaKeyFederated')",
		Long: undent.Undent(`
			Creates or updates the given 'Workload Identity Federation'
			(also known as 'RSA Key Federated') Service Account in
			CyberArk Certificate Manager, SaaS. Returns the Service Account's
			client ID.

			To know the scopes you can assign to a Service Account, use:

			  vcpctl sa scopes

			Note that you can only use the scopes that are compatible with
			the authentication type 'rsaKeyFederated' (aka Workload Identity
			Federation).
		`),
		Example: undent.Undent(`
			vcpctl sa put wif my-sa \
			  --scope kubernetes-discovery-federated \
			  --scope certificate-issuance \
			  --subject "system:serviceaccount:default:my-sa" \
			  --audience "venafi-cloud" \
			  --issuer-url "https://oidc.example.com" \
			  --jwks-uri "https://oidc.example.com/.well-known/jwks.json"
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa put wif: %w", err)
			}

			saName := args[0]

			if subject == "" {
				return fmt.Errorf("sa put wif: --subject is required")
			}
			if audience == "" {
				return fmt.Errorf("sa put wif: --audience is required")
			}
			if issuerURL == "" {
				return fmt.Errorf("sa put wif: --issuer-url is required")
			}
			if jwksURI == "" {
				return fmt.Errorf("sa put wif: --jwks-uri is required")
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Parse applications (UUIDs).
			applications := make([]api.Application, len(apps))
			for i, app := range apps {
				appUUID := openapi_types.UUID{}
				err := appUUID.UnmarshalText([]byte(app))
				if err != nil {
					return fmt.Errorf("sa put wif: invalid application UUID '%s': %w", app, err)
				}
				applications[i] = appUUID
			}

			// If no application is provided, let's pick the first one available.
			if len(applications) == 0 {
				availableApps, err := api.GetApplications(context.Background(), apiClient)
				if err != nil {
					return fmt.Errorf("sa put wif: while retrieving available applications: %w", err)
				}
				if len(availableApps) == 0 {
					return fmt.Errorf("sa put wif: no application provided and no application available in the account")
				}
				applications = []api.Application{availableApps[0].Id}
				logutil.Infof("No application provided, using the first available one: %s (%s)", availableApps[0].Name, availableApps[0].Id.String())
			}

			// Parse owner team (UUID) if provided.
			ownerUUID := openapi_types.UUID{}
			if ownerTeam != "" {
				err := ownerUUID.UnmarshalText([]byte(ownerTeam))
				if err != nil {
					return fmt.Errorf("sa put wif: invalid owner team UUID '%s': %w", ownerTeam, err)
				}
			}

			// If no owner team is provided, let's pick the first one available.
			if ownerTeam == "" {
				teams, err := api.GetTeams(context.Background(), apiClient)
				if err != nil {
					return fmt.Errorf("sa put wif: while retrieving available teams: %w", err)
				}
				if len(teams) == 0 {
					return fmt.Errorf("sa put wif: no owner team provided and no team available in the account")
				}
				ownerUUID = teams[0].Id
				logutil.Infof("No owner team provided, using the first available one: %s (%s)", teams[0].Name, teams[0].Id.String())
			}

			// Check if service account exists
			existingSA, err := api.GetServiceAccount(context.Background(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				// Doesn't exist yet, create it
				resp, err := api.CreateServiceAccount(context.Background(), apiClient, api.ServiceAccountDetails{
					Name:               saName,
					AuthenticationType: "rsaKeyFederated",
					CredentialLifetime: 365, // days
					Scopes:             scopes,
					Subject:            subject,
					Audience:           audience,
					IssuerURL:          issuerURL,
					JwksURI:            jwksURI,
					Applications:       applications,
					Owner:              ownerUUID,
				})
				if err != nil {
					return fmt.Errorf("sa put wif: while creating service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' created.\nScopes: %s\nSubject: %s\nAudience: %s\nIssuer URL: %s\nJWKS URI: %s",
					saName, strings.Join(scopes, ", "), subject, audience, issuerURL, jwksURI)

				fmt.Println(resp.Id.String())
				return nil
			case err == nil:
				// Exists, update it
				desiredSA := existingSA
				desiredSA.Scopes = scopes
				desiredSA.Subject = subject
				desiredSA.Audience = audience
				desiredSA.IssuerURL = issuerURL
				desiredSA.JwksURI = jwksURI
				if len(applications) > 0 {
					desiredSA.Applications = applications
				}

				patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
				if err != nil {
					return fmt.Errorf("sa put wif: while creating service account patch: %w", err)
				}
				if !smthChanged {
					logutil.Debugf("Service Account '%s' is already up to date.", saName)
					fmt.Println(existingSA.Id.String())
					return nil
				}

				err = api.PatchServiceAccount(context.Background(), apiClient, existingSA.Id.String(), patch)
				if err != nil {
					return fmt.Errorf("sa put wif: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					updatedSA, err := api.GetServiceAccountByID(context.Background(), apiClient, existingSA.Id.String())
					if err != nil {
						return fmt.Errorf("sa put wif: while retrieving updated service account: %w", err)
					}
					d := api.ANSIDiff(existingSA, updatedSA)
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}

				fmt.Println(existingSA.Id.String())
				return nil
			default:
				return fmt.Errorf("sa put wif: while checking if service account exists: %w", err)
			}
		},
	}
	cmd.Flags().StringArrayVar(&scopes, "scope", []string{}, "Scopes for the Service Account (can be specified multiple times, e.g. '--scope kubernetes-discovery-federated --scope certificate-issuance')")
	cmd.Flags().StringVar(&subject, "subject", "", "The subject of the entity (required)")
	cmd.Flags().StringVar(&audience, "audience", "", "The intended audience or recipients of the entity (required)")
	cmd.Flags().StringVar(&issuerURL, "issuer-url", "", "The URL of the entity issuer (required)")
	cmd.Flags().StringVar(&jwksURI, "jwks-uri", "", "The URI pointing to the JSON Web Key Set (JWKS) (required)")
	cmd.Flags().StringArrayVar(&apps, "app", []string{}, "Application UUID to associate with the service account (can be specified multiple times)")
	cmd.Flags().StringVar(&ownerTeam, "owner-team", "", "Owner team UUID (if not provided, the first team will be used)")
	return cmd
}
