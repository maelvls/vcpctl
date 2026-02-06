package main

import (
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
		ValidArgsFunction: completeSANameOrID(func(sad api.ServiceAccountDetails) bool {
			return sad.AuthenticationType == "rsaKeyFederated"
		}),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			saName := args[0]

			privKeyPEM, _, jwksPayload, err := generateWIFKeyPairAndJWKS()
			if err != nil {
				return fmt.Errorf("while generating key pair: %w", err)
			}

			jwksURL, err := uploadJWKS0x0(jwksPayload)
			if err != nil {
				return fmt.Errorf("while uploading JWKS to 0x0.st: %w", err)
			}
			logutil.Debugf("JWKS uploaded to: %s", jwksURL)

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Check if service account exists.
			existingSA, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			switch {
			case errutil.ErrIsNotFound(err):
				// Doesn't exist yet, error out.
				return fmt.Errorf("service account '%s' does not exist. Please create it first using:\n    vcpctl sa put wif %s'", saName, saName)
			case err == nil:
				// Exists, let's update it below.
			default:
				return fmt.Errorf("while checking if service account exists: %w", err)
			}

			iss := jwksURL
			sub := existingSA.Id.String()
			aud := conf.APIURL

			desiredSA := existingSA
			desiredSA.JwksURI = jwksURL
			desiredSA.IssuerURL = iss
			desiredSA.Subject = sub
			desiredSA.Audience = aud

			patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
			if err != nil {
				return fmt.Errorf("while creating service account patch: %w", err)
			}
			if !smthChanged {
				logutil.Debugf("Service Account '%s' is already up to date.", saName)
			} else {
				err = api.PatchServiceAccount(cmd.Context(), apiClient, existingSA.Id.String(), patch)
				if err != nil {
					return fmt.Errorf("while patching service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' updated.", saName)
			}

			// At this point, we need to know the tenant URL; if we are
			// authenticated using an API key, then we can fetch it.
			var tenantURL string
			if conf.APIKey != "" {
				_, tenantURL, err = api.SelfCheckAPIKey(cmd.Context(), apiClient)
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
					ClientID:   existingSA.Id.String(),
					PrivateKey: privKeyPEM,
					TenantURL:  tenantURL,
					JWKSURL:    jwksURL,
					Iss:        iss,
					Aud:        aud,
					Sub:        sub,
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
	return cmd
}

func saPutWifCmd() *cobra.Command {
	var scopes []string
	var sub string
	var aud string
	var iss string
	var jwksURL string
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

			To know the scopes you can assign to a wif Service Account (i.e., a service
			account for which the authenticationType is "rsaKeyFederated"), use:

			  vcpctl sa scopes --type rsaKeyFederated

			Note that only one scope that contains the word "role" can appear in the list
			of scopes assigned to a service account.
		`),
		Example: undent.Undent(`
			vcpctl sa put wif my-sa \
			  --scope all \
			  --sub "system:serviceaccount:default:my-sa" \
			  --aud "api.venafi.cloud" \
			  --iss "https://oidc.example.com" \
			  --jwks-url "https://oidc.example.com/.well-known/jwks.json"
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

			// These will be changed by the 'gen'.
			if sub == "" {
				sub = "dummy-subject"
			}
			if aud == "" {
				aud = "dummy-audience"
			}
			if iss == "" {
				iss = "https://dummy.issuer.venafi.cloud"
			}
			if jwksURL == "" {
				jwksURL = "https://dummy.jwks.venafi.cloud"
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			if len(scopes) == 1 && scopes[0] == "all" {
				scopes, err = api.GetServiceAccountScopesByType(cmd.Context(), apiClient, "rsaKeyFederated")
				if err != nil {
					return fmt.Errorf("while retrieving available scopes for 'rsaKeyFederated' authentication type: %w", err)
				}

				scopes = replaceRolesWith(scopes, "platform-admin-role")
				logutil.Debugf("Using all available scopes for 'rsaKeyFederated' authentication type: %s", strings.Join(scopes, ", "))
			}

			err = checkDuplicateRoles(scopes)
			if err != nil {
				return err
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
				availableApps, err := api.GetApplications(cmd.Context(), apiClient)
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
			ownerUUID := openapi_types.UUID{}
			if ownerTeam != "" {
				err := ownerUUID.UnmarshalText([]byte(ownerTeam))
				if err != nil {
					return fmt.Errorf("invalid owner team UUID '%s': %w", ownerTeam, err)
				}
			}

			// If no owner team is provided, let's pick the first one available.
			if ownerTeam == "" {
				teams, err := api.GetTeams(cmd.Context(), apiClient)
				if err != nil {
					return fmt.Errorf("while retrieving available teams: %w", err)
				}
				if len(teams) == 0 {
					return fmt.Errorf("no owner team provided and no team available in the account")
				}
				ownerUUID = teams[0].Id
				logutil.Debugf("No owner team provided, using the first available one: %s (%s)", teams[0].Name, teams[0].Id.String())
			}

			// Check if service account exists
			existingSA, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				// Doesn't exist yet, create it.
				resp, err := api.CreateServiceAccount(cmd.Context(), apiClient, api.ServiceAccountDetails{
					Name:               saName,
					AuthenticationType: "rsaKeyFederated",
					Scopes:             scopes,
					Subject:            sub,
					Audience:           aud,
					IssuerURL:          iss,
					JwksURI:            jwksURL,
					Applications:       applications,
					Owner:              ownerUUID,
				})
				if err != nil {
					return fmt.Errorf("while creating service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' created.\nScopes: %s\nSubject: %s\nAudience: %s\nIssuer URL: %s\nJWKS URI: %s",
					saName, strings.Join(scopes, ", "), sub, aud, iss, jwksURL)

				fmt.Println(resp.Id.String())
				return nil
			case err == nil:
				// Exists, update it
				desiredSA := existingSA
				desiredSA.Scopes = scopes
				desiredSA.Subject = sub
				desiredSA.Audience = aud
				desiredSA.IssuerURL = iss
				desiredSA.JwksURI = jwksURL
				if len(applications) > 0 {
					desiredSA.Applications = applications
				}

				patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
				if err != nil {
					return fmt.Errorf("while creating service account patch: %w", err)
				}
				if !smthChanged {
					logutil.Debugf("Service Account '%s' is already up to date.", saName)
					fmt.Println(existingSA.Id.String())
					return nil
				}

				err = api.PatchServiceAccount(cmd.Context(), apiClient, existingSA.Id.String(), patch)
				if err != nil {
					return fmt.Errorf("while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					updatedSA, err := api.GetServiceAccountByID(cmd.Context(), apiClient, existingSA.Id.String())
					if err != nil {
						return fmt.Errorf("while retrieving updated service account: %w", err)
					}
					d := api.ANSIDiff(existingSA, updatedSA)
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}

				fmt.Println(existingSA.Id.String())
				return nil
			default:
				return fmt.Errorf("while checking if service account exists: %w", err)
			}
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"all"}, "Scopes for the service account .The flag --scope can be specified multiple times, or a comma-separated list can be provided instead. With --scope=all, all available scopes for 'rsaKeyFederated' authentication type are set.")
	cmd.Flags().StringVar(&sub, "sub", "", "Expected subject claim")
	cmd.Flags().StringVar(&aud, "aud", "", "Expected audience claim")
	cmd.Flags().StringVar(&iss, "iss", "", "Expected issuer URL claim")
	cmd.Flags().StringVar(&jwksURL, "jwks-url", "", "The URL pointing to the JSON Web Key Set (JWKS). You can leave this field empty and use 'vcpctl sa gen wif' to let the tool upload a JWKS to 0x0.st for you.")
	cmd.Flags().StringArrayVar(&apps, "app", []string{}, "Application UUID to associate with the service account (can be specified multiple times)")
	cmd.Flags().StringVar(&ownerTeam, "owner-team", "", "Owner team UUID (if not provided, the first team will be used)")
	return cmd
}

// Only a single scope containing the word "role" should ever exist in a service
// account. Otherwise, you will get:
//
//	400 Bad Request
//	{
//	    "errors": [
//	        {
//	            "code": 60223,
//	            "message": "Invalid scopes. Check and make sure that you have selected only one role scope"
//	        }
//	    ]
//	}
func checkDuplicateRoles(scopes []string) error {
	var roleScopes []string
	for _, scope := range scopes {
		if strings.Contains(scope, "role") {
			roleScopes = append(roleScopes, scope)
		}
	}
	if len(roleScopes) > 1 {
		return errutil.Fixable(fmt.Errorf("only one role scope can be assigned to a service account, but multiple role scopes were found: %s", strings.Join(roleScopes, ", ")))
	}
	return nil
}

func replaceRolesWith(scopes []string, newScopeRole string) []string {
	var newScopes []string
	for _, scope := range scopes {
		if strings.Contains(scope, "role") {
			continue
		}
		newScopes = append(newScopes, scope)

	}
	newScopes = append(newScopes, newScopeRole)
	return newScopes
}
