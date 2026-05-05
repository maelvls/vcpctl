package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

func saPutOciCmd() *cobra.Command {
	var scopes []string
	cmd := &cobra.Command{
		Use:   "oci <sa-name>",
		Short: "Creates or updates the given OCI Token Service Account (authenticationType: 'ociToken')",
		Long: undent.Undent(`
			Creates or updates the given OCI Token Service Account in
			CyberArk Certificate Manager, SaaS. Returns the Service Account's client ID.

			OCI token service accounts are used to authenticate with OCI registries
			such as private-registry.venafi.cloud.

			To know the scopes you can assign to an OCI token Service Account, use:

			  vcpctl sa scopes --type ociToken
		`),
		Example: undent.Undent(`
			vcpctl sa put oci <sa-name>
			vcpctl sa put oci <sa-name> --scope oci-registry-firefly-ent
			vcpctl sa put oci <sa-name> --scope oci-registry-cm,oci-registry-firefly-ent
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

			if len(scopes) == 1 && scopes[0] == "all" {
				scopes, err = api.GetServiceAccountScopesByType(cmd.Context(), apiClient, "ociToken")
				if err != nil {
					return fmt.Errorf("while retrieving available scopes for 'ociToken' authentication type: %w", err)
				}
				logutil.Debugf("Using all available scopes for 'ociToken': %s", strings.Join(scopes, ", "))
			}

			id, err := ensureOciServiceAccount(cmd.Context(), apiClient, saName, scopes)
			if err != nil {
				return err
			}

			fmt.Println(id)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"all"}, "Scopes for the service account. Use 'all' to assign all available ociToken scopes. Run 'vcpctl sa scopes --type ociToken' to see available scopes.")
	return cmd
}

// ociCreds holds Docker-compatible OCI registry credentials.
type ociCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Server   string `json:"server"`
}

func saGenOciCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oci <sa-name>",
		Short: "Generates a new OCI registry token for the given Service Account (authenticationType: 'ociToken')",
		Long: undent.Undent(`
			Generates a new OCI registry token for the given OCI Token Service Account.
			The existing token is rotated (the previous one is invalidated).

			The output is a JSON object with the username, password, and auth fields,
			suitable for use with 'docker login' or as a Kubernetes docker-registry secret.
		`),
		Example: undent.Undent(`
			vcpctl sa gen oci <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		ValidArgsFunction: completeSAName(func(sa api.ServiceAccountDetails) bool {
			return sa.AuthenticationType == "ociToken"
		}),
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

			existingSA, err := api.GetServiceAccount(cmd.Context(), apiClient, saName)
			switch {
			case errors.As(err, &errutil.NotFound{}):
				return fmt.Errorf("service account '%s' not found. Create it with:\n\tvcpctl sa put oci %s", saName, saName)
			case err == nil:
			default:
				return fmt.Errorf("while getting service account: %w", err)
			}

			if existingSA.AuthenticationType != "ociToken" {
				return fmt.Errorf("service account '%s' has authentication type '%s', expected 'ociToken'", saName, existingSA.AuthenticationType)
			}

			registry, err := ociRegistryFromConf(conf)
			if err != nil {
				return err
			}

			creds, err := genOciCreds(cmd.Context(), apiClient, existingSA.Id.String(), conf.APIURL, registry)
			if err != nil {
				return err
			}

			b, err := json.MarshalIndent(creds, "", "  ")
			if err != nil {
				return fmt.Errorf("while marshaling credentials: %w", err)
			}
			fmt.Println(string(b))
			return nil
		},
	}
	return cmd
}

// ensureOciServiceAccount creates (if absent) or updates the ociToken service
// account. Returns the SA ID.
func ensureOciServiceAccount(ctx context.Context, apiClient *api.Client, saName string, scopes []string) (string, error) {
	existingSA, err := api.GetServiceAccount(ctx, apiClient, saName)
	switch {
	case errors.As(err, &errutil.NotFound{}):
		resp, err := api.CreateServiceAccount(ctx, apiClient, api.ServiceAccountDetails{
			Name:               saName,
			CredentialLifetime: 365,
			Scopes:             scopes,
			AuthenticationType: "ociToken",
		})
		if err != nil {
			return "", fmt.Errorf("while creating service account '%s': %w", saName, err)
		}
		logutil.Debugf("Service Account '%s' created with scopes %s", saName, strings.Join(scopes, ", "))
		return resp.Id.String(), nil
	case err == nil:
		// Exists — check type and patch if needed.
	default:
		return "", fmt.Errorf("while looking up service account '%s': %w", saName, err)
	}

	if existingSA.AuthenticationType != "ociToken" {
		return "", fmt.Errorf("service account '%s' has authentication type '%s', expected 'ociToken'", saName, existingSA.AuthenticationType)
	}

	if len(scopes) > 0 {
		desiredSA := existingSA
		desiredSA.Scopes = scopes
		patch, smthChanged, err := api.DiffToPatchServiceAccount(existingSA, desiredSA)
		if err != nil {
			return "", fmt.Errorf("while creating service account patch: %w", err)
		}
		if smthChanged {
			if err := api.PatchServiceAccount(ctx, apiClient, existingSA.Id.String(), patch); err != nil {
				return "", fmt.Errorf("while patching service account: %w", err)
			}
			logutil.Debugf("Service Account '%s' updated with scopes %s", saName, strings.Join(scopes, ", "))
		} else {
			logutil.Debugf("Service Account '%s' is already up to date", saName)
		}
	}

	return existingSA.Id.String(), nil
}

// genOciCreds rotates the OCI token and returns Docker-compatible credentials.
func genOciCreds(ctx context.Context, apiClient *api.Client, saID, apiURL, registry string) (ociCreds, error) {
	tokenResp, err := api.GenOCIToken(ctx, apiClient, saID)
	if err != nil {
		return ociCreds{}, fmt.Errorf("while generating OCI token: %w", err)
	}

	return ociCreds{
		Username: ociAccountNameFromSAID(apiURL, saID),
		Password: tokenResp.OciRegistryToken,
		Server:   registry,
	}, nil
}

// ociAccountNameFromSAID reconstructs the OCI robot account name from the API
// URL and SA ID. The format is sa-{region}@{saID} for VCP prod regions, or
// sa@{saID} for QA/dev/NGTS environments that have no region.
func ociAccountNameFromSAID(apiURL, saID string) string {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "sa@" + saID
	}
	parts := strings.Split(u.Hostname(), ".")

	// api.venafi.cloud → ["api", "venafi", "cloud"] → us
	if len(parts) == 3 && parts[0] == "api" && parts[1] == "venafi" && parts[2] == "cloud" {
		return "sa-us@" + saID
	}
	// api.eu.venafi.cloud → ["api", "eu", "venafi", "cloud"] → eu / au / etc.
	if len(parts) == 4 && parts[0] == "api" && parts[2] == "venafi" && parts[3] == "cloud" {
		return "sa-" + parts[1] + "@" + saID
	}
	return "sa@" + saID
}
