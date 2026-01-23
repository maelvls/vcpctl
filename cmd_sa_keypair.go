package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

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
			    "type": "rsaKey",
			    "api_url": "https://api.venafi.cloud",
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
				return fmt.Errorf("%w", err)
			}

			saName := args[0]

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Does it already exist?
			existingSA, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return fmt.Errorf(undent.Undent(`
					service account '%s' not found. You can create it with:
						vcpctl sa put keypair %s
				`), saName, saName)
			case err == nil:
				// Exists, we will be updating it.
			default:
				return fmt.Errorf("while checking if service account exists: %w", err)
			}

			// Check that it is an 'rsaKey' service account.
			if existingSA.AuthenticationType != "rsaKey" {
				return fmt.Errorf("service account '%s' has authentication type '%s', expected 'rsaKey'. You can only generate a key pair for 'rsaKey' service accounts.", saName, existingSA.AuthenticationType)
			}

			ecKey, ecPub, err := genECKeyPair()
			if err != nil {
				return fmt.Errorf("while generating EC key pair: %w", err)
			}

			desiredSA := existingSA
			desiredSA.PublicKey = ecPub
			patch, _, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
			if err != nil {
				return fmt.Errorf("while creating service account patch: %w", err)
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
			logutil.Debugf("Client ID: %s", existingSA.Id.String())

			switch outputFormat {
			case "pem":
				fmt.Println(ecKey)
			case "json":
				bytes, err := marshalIndent(jsonAuthKeypair{
					Type:       "rsaKey",
					ClientID:   existingSA.Id.String(),
					PrivateKey: ecKey,
					APIURL:     conf.APIURL,
				}, "", "  ")
				if err != nil {
					return fmt.Errorf("while marshaling JSON: %w", err)
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
			vcpctl sa put keypair <sa-name> --scope platform-admin-role --scope distributed-issuance
			vcpctl sa put keypair <sa-name> --scope platform-admin-role,distributed-issuance
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

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Does it already exist?
			existingSA, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				// Doesn't exist yet.
				resp, err := api.CreateServiceAccount(cmd.Context(), apiClient, api.ServiceAccountDetails{
					Name:               saName,
					CredentialLifetime: 365, // days
					Scopes:             scopes,
					AuthenticationType: "rsaKey",
				})
				if err != nil {
					return fmt.Errorf("while creating service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' created with the scopes %v", saName, strings.Join(scopes, ", "))

				fmt.Println(resp.Id.String())
				return nil
			case err == nil:
				// Exists, we will be updating it below.
			default:
				return fmt.Errorf("while checking if service account exists: %w", err)
			}

			// Check that it is an 'rsaKey' service account.
			if existingSA.AuthenticationType != "rsaKey" {
				return fmt.Errorf("service account '%s' has authentication type '%s', expected 'rsaKey'. You can only use this command for 'rsaKey' service accounts.", saName, existingSA.AuthenticationType)
			}

			desiredSA := existingSA
			desiredSA.Scopes = scopes
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
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "pem", "Output format (pem, json)")
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"platform-admin-role"}, "Scope for the service account. You can give multiple scopes by separating them with commas, or repeating the --scope flag. To list the scopes you can use with this command, run 'vcpctl sa scopes --type rsaKey'.")
	return cmd
}
