package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

func saCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sa",
		Short: "Manage Service Accounts",
		Long: undent.Undent(`
			Manage Service Accounts.
		`),
		Example: undent.Undent(`
			vcpctl sa ls
			vcpctl sa rm <sa-name>
			vcpctl sa get <sa-name>
			vcpctl sa put wif <sa-name>
			vcpctl sa put keypair <sa-name>
			vcpctl sa gen keypair <sa-name>
			vcpctl sa scopes
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		saLsCmd(),
		saRmCmd(),
		saPutCmd(),
		saGenCmd(),
		saGetCmd(),
		saScopesCmd(),
		&cobra.Command{Use: "gen-rsa", Deprecated: "the 'gen-rsa' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE},
		&cobra.Command{Use: "keygen", Deprecated: "the 'keygen' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE},
		&cobra.Command{Use: "get-clientid", Deprecated: "the 'get-clientid' command is deprecated, please use 'get-clientid' instead.", RunE: saGenkeypairCmd().RunE},
	)
	return cmd
}

func saLsCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "ls [-o json|id]",
		Short: "List Service Accounts",
		Long: undent.Undent(`
			List service accounts. Service accounts authenticate applications that
			use WIM (Workload Identity Manager) configurations.

			You can use -oid to only display the Service Account client IDs.
		`),
		Example: undent.Undent(`
			vcpctl sa ls
			vcpctl sa ls -ojson
			vcpctl sa ls -oid
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa ls: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			svcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("sa ls: while listing service accounts: %w", err)
			}

			switch outputFormat {
			case "json":
				b, err := marshalIndent(svcaccts, "", "  ")
				if err != nil {
					return fmt.Errorf("sa ls: while marshaling service accounts to JSON: %w", err)
				}
				fmt.Println(string(b))
				return nil
			case "table":
				var rows [][]string
				for _, sa := range svcaccts {
					rows = append(rows, []string{
						sa.Id.String(),
						uniqueColor(sa.AuthenticationType),
						sa.Name,
					})
				}
				printTable([]string{"Client ID", "Auth Type", "Service Account Name"}, rows)
				return nil
			case "id":
				for _, sa := range svcaccts {
					fmt.Println(sa.Id.String())
				}
				return nil
			default:
				return errutil.Fixable(fmt.Errorf("sa ls: invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table, id)")
	return cmd
}

func saGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate the key pair for a Service Account",
		Long: undent.Undent(`
			Generate the key pair for a Service Account.
		`),
		Example: undent.Undent(`
			vcpctl sa gen keypair <sa-name>
			vcpctl sa gen keypair <sa-name> -ojson
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(saGenkeypairCmd())
	return cmd
}

func saPutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Creates or updates a Service Account",
		Long: undent.Undent(`
			Creates or updates a Service Account in CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa put keypair <sa-name>
			vcpctl sa put wif <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(saPutKeypairCmd())
	cmd.AddCommand(saPutWifCmd())
	return cmd
}

func saGenkeypairCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "keypair <sa-name>",
		Short: "Generates an EC private key and registers it to the given Service Account (authenticationType: 'rsaKey')",
		Long: undent.Undent(`
			Generates an EC private key and registers it to the given Service
			Account in CyberArk Certificate Manager, SaaS.

			The private key is printed to stdout in PEM, you can use it to
			create a Kubernetes secret, for example:

			  vcpctl sa gen keypair my-sa | \
			    kubectl create secret generic venafi-credentials \
			    --from-file=svc-acct.key=/dev/stdin

			Once that's done, you can grab the client ID with:

			  vcpctl sa get -oid my-sa

			You can use '-ojson' to get the client ID and the private key in
			JSON format in a venctl-compatible format that looks like this:

			  {
					"client_id": "123e4567-e89b-12d3-a456-426614174000",
					"private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
			  }
		`),
		Example: undent.Undent(`
			vcpctl sa gen keypair <sa-name>
			vcpctl sa gen keypair <sa-name> -ojson
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expects a single argument (the service account name), got: %s", args)
			}

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa gen keypair: %w", err)
			}

			saName := args[0]

			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Does it already exist?
			existingSA, err := api.GetServiceAccount(context.Background(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return fmt.Errorf(undent.Undent(`
					service account '%s' not found. You can create it with:
						vcpctl sa put keypair %s
				`), saName, saName)
			case err == nil:
				// Exists, we will be updating it.
			default:
				return fmt.Errorf("sa gen keypair: while checking if service account exists: %w", err)
			}

			ecKey, ecPub, err := genECKeyPair()
			if err != nil {
				return fmt.Errorf("sa gen keypair: while generating EC key pair: %w", err)
			}

			desiredSA := existingSA
			desiredSA.PublicKey = ecPub
			patch, _, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while creating service account patch: %w", err)
			}

			err = api.PatchServiceAccount(context.Background(), apiClient, existingSA.Id.String(), patch)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while patching service account: %w", err)
			}

			if logutil.EnableDebug {
				updatedSA, err := api.GetServiceAccountByID(context.Background(), apiClient, existingSA.Id.String())
				if err != nil {
					return fmt.Errorf("sa gen keypair: while retrieving updated service account: %w", err)
				}
				d := api.ANSIDiff(existingSA, updatedSA)
				logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
			}
			logutil.Debugf("Client ID: %s", existingSA.Id.String())

			switch outputFormat {
			case "pem":
				fmt.Println(ecKey)
			case "json":
				bytes, err := marshalIndent(struct {
					ClientID   string `json:"client_id"`
					PrivateKey string `json:"private_key"`
				}{ClientID: existingSA.Id.String(), PrivateKey: ecKey}, "", "  ")
				if err != nil {
					return fmt.Errorf("sa gen keypair: while marshaling JSON: %w", err)
				}
				fmt.Println(string(bytes))
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "pem", "Output format (pem, json)")
	return cmd
}

func saPutKeypairCmd() *cobra.Command {
	var outputFormat string
	var scopes []string
	cmd := &cobra.Command{
		Use:   "keypair <sa-name>",
		Short: "Creates or updates the given Key Pair Authentication Service Account (authenticationType: 'rsaKey')",
		Long: undent.Undent(`
			Creates or updates the given 'Private Key JWT' authentication
			(also known as 'Key Pair Authentication') Service Account in
			CyberArk Certificate Manager, SaaS. Returns the Service Account's client ID.

			To know the scopes you can assign to a Service Account, use:

			  vcpctl sa scopes

			Note that you can only use the scopes that are compatible with
			the authentication type 'rsaKey' (aka Key Pair Authentication).
		`),
		Example: undent.Undent(`
			vcpctl sa put keypair <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa put keypair: %w", err)
			}

			saName := args[0]

			// Does it already exist?
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			existingSA, err := api.GetServiceAccount(context.Background(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				// Doesn't exist yet.
				resp, err := api.CreateServiceAccount(context.Background(), apiClient, api.ServiceAccountDetails{
					Name:               saName,
					CredentialLifetime: 365, // days
					Scopes:             scopes,
				})
				if err != nil {
					return fmt.Errorf("sa put keypair: while creating service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' created.\nScopes: %s", saName, strings.Join(scopes, ", "))

				fmt.Println(resp.Id.String())
				return nil
			case err == nil:
				// Exists, we will be updating it.
				desiredSA := existingSA
				desiredSA.Scopes = scopes
				patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
				if err != nil {
					return fmt.Errorf("sa put keypair: while creating service account patch: %w", err)
				}
				if !smthChanged {
					logutil.Debugf("Service Account '%s' is already up to date.", saName)
					fmt.Println(existingSA.Id.String())
					return nil
				}

				err = api.PatchServiceAccount(context.Background(), apiClient, existingSA.Id.String(), patch)
				if err != nil {
					return fmt.Errorf("sa put keypair: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					updatedSA, err := api.GetServiceAccountByID(context.Background(), apiClient, existingSA.Id.String())
					if err != nil {
						return fmt.Errorf("sa put keypair: while retrieving updated service account: %w", err)
					}
					d := api.ANSIDiff(existingSA, updatedSA)
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}

				fmt.Println(existingSA.Id.String())
				return nil
			default:
				return fmt.Errorf("sa put keypair: while checking if service account exists: %w", err)
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "pem", "Output format (pem, json)")
	cmd.Flags().StringArrayVar(&scopes, "scopes", []string{"distributed-issuance"}, "Scopes for the Service Account (comma-separated, e.g. 'distributed-issuance,read-only')")
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

			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
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

			// Parse owner team (UUID) if provided.
			ownerUUID := openapi_types.UUID{}
			if ownerTeam != "" {
				err := ownerUUID.UnmarshalText([]byte(ownerTeam))
				if err != nil {
					return fmt.Errorf("sa put wif: invalid owner team UUID '%s': %w", ownerTeam, err)
				}
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

func saGetCmd() *cobra.Command {
	var format string
	var raw bool
	cmd := &cobra.Command{
		Use:   "get <sa-name>",
		Short: "Get the information about an existing Service Account",
		Long: undent.Undent(`
			Get the Service Account's details. By default, displays the service
			account as a manifest.ServiceAccount. Use --raw to display the raw
			API response. You can use -o clientid to only display the client ID
			of the Service Account.
		`),
		Example: undent.Undent(`
			vcpctl sa get <sa-name>
			vcpctl sa get <sa-name> --raw
			vcpctl sa get <sa-name> -o json
			vcpctl sa get <sa-name> -o clientid
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument (the service account name), got: %s", args)
			}

			saName := args[0]

			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			sa, err := api.GetServiceAccount(context.Background(), apiClient, saName)
			if err != nil {
				if errutil.ErrIsNotFound(err) {
					return fmt.Errorf("service account '%s' not found", saName)
				}
				return fmt.Errorf("while getting service account by name: %w", err)
			}

			if sa.Id.String() == "" {
				return fmt.Errorf("service account '%s' has no client ID", saName)
			}

			// Convert to manifest unless --raw is specified
			var outputData interface{}
			if raw {
				outputData = sa
			} else {
				outputData = serviceAccountManifest{
					Kind:           kindServiceAccount,
					ServiceAccount: apiToManifestServiceAccount(sa),
				}
			}

			switch format {
			case "yaml":
				bytes, err := yaml.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling service account to YAML: %w", err)
				}
				coloredYAMLPrint(string(bytes) + "\n") // Not sure why '\n' is needed, but it is.
				return nil
			case "id":
				fmt.Println(sa.Id.String())
				return nil
			case "json":
				data, err := json.Marshal(outputData)
				if err != nil {
					return fmt.Errorf("while marshaling service account to JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			default:
				return fmt.Errorf("unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "yaml", "Output format (id, json, yaml). The 'id' is the service account's client ID.")
	cmd.Flags().BoolVar(&raw, "raw", false, "Display raw API response instead of manifest format")
	return cmd
}

func saScopesCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "List all available Service Account scopes",
		Long: undent.Undent(`
			List all available Service Account scopes. Scopes define what
			permissions a service account has when authenticating with
			CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa scopes
			vcpctl sa scopes -o json
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa scopes: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			scopes, err := api.GetServiceAccountScopes(context.Background(), apiClient)
			if err != nil {
				return fmt.Errorf("sa scopes: while listing scopes: %w", err)
			}

			switch outputFormat {
			case "json":
				b, err := marshalIndent(scopes, "", "  ")
				if err != nil {
					return fmt.Errorf("sa scopes: while marshaling scopes to JSON: %w", err)
				}
				fmt.Println(string(b))
				return nil
			case "table":
				var rows [][]string
				for _, scope := range scopes {
					authType := scope.AuthenticationType
					if authType == "" {
						authType = "-"
					}
					rows = append(rows, []string{
						scope.Id,
						authType,
						scope.ReadableName,
					})
				}
				printTable([]string{"Scope ID", "Auth Type", "Description"}, rows)
				return nil
			default:
				return errutil.Fixable(fmt.Errorf("sa scopes: invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table)")
	return cmd
}

func saRmCmd() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{
		Use:   "rm (<sa-name> | -i)",
		Short: "Remove a Service Account",
		Long: undent.Undent(`
			Remove a Service Account. This will delete the Service Account from
			CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl sa rm <sa-name>
			vcpctl sa rm -i
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if interactive {
				if len(args) > 0 {
					return fmt.Errorf("expected no arguments when using --interactive, got %s", args)
				}
				// In interactive mode, we will list the service accounts and let the user
				// select one to remove.
				conf, err := getToolConfig(cmd)
				if err != nil {
					return fmt.Errorf("%w", err)
				}
				apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				svcaccts, err := api.GetServiceAccounts(context.Background(), apiClient)
				if err != nil {
					return fmt.Errorf("while listing service accounts: %w", err)
				}

				// Use a simple prompt to select the service account to remove.
				selected := rmInteractive(svcaccts)
				for _, saID := range selected {
					err = api.RemoveServiceAccount(context.Background(), apiClient, saID)
					if err != nil {
						return fmt.Errorf("while removing service account '%s': %w", saID, err)
					}
				}

				logutil.Debugf("Service Account(s) removed successfully:\n%s", strings.Join(selected, "\n"))
				return nil
			}

			if len(args) != 1 {
				return fmt.Errorf("sa rm: expected a single argument (the service account name), got: %s", args)
			}
			saName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa rm: %w", err)
			}
			apiClient, err := api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = api.RemoveServiceAccount(context.Background(), apiClient, saName)
			if err != nil {
				return fmt.Errorf("sa rm: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactively select the service account to remove.")
	return cmd
}
