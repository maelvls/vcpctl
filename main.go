package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/google/go-cmp/cmp"
	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/njayp/ophis"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

const userAgent = "vcpctl/v0.0.1"

// Type aliases to map custom types to OpenAPI-generated types
type (
	// ServiceAccount represents a service account from the API
	ServiceAccount = api.ServiceAccountDetails

	// Policy represents a policy from the API
	Policy = api.ExtendedPolicyInformation

	// SubCa represents a sub-CA provider from the API
	SubCa = api.SubCaProviderInformation

	// Config represents a configuration from the API
	Config = api.ExtendedConfigurationInformation

	// ServiceAccountPatch represents a service account patch request
	ServiceAccountPatch = api.ServiceAccountPatchBaseObject

	// PolicyPatch represents a policy patch request
	PolicyPatch = api.PolicyUpdateRequest

	// SubCaProviderPatch represents a sub-CA provider patch request
	SubCaProviderPatch = api.SubCaProviderUpdateRequest

	// ConfigPatch represents a configuration patch request
	ConfigPatch = api.ConfigurationUpdateRequest

	// PKCS11 represents PKCS11 configuration
	PKCS11 = api.SubCaProviderPkcs11ConfigurationInformation

	// SubCaProviderCreateRequest represents a sub-CA provider create request
	SubCaProviderCreateRequest = api.SubCaProviderCreateRequest

	// SubCaProviderUpdateRequest represents a sub-CA provider update request
	SubCaProviderUpdateRequest = api.SubCaProviderUpdateRequest

	// SubCaProviderPkcs11ConfigurationInformation represents PKCS11 configuration
	SubCaProviderPkcs11ConfigurationInformation = api.SubCaProviderPkcs11ConfigurationInformation
)

// Replace the old flag-based main() with cobra execution.
func main() {
	var apiURLFlag, apiKeyFlag string
	rootCmd := &cobra.Command{
		Use:   "vcpctl",
		Short: "CLI tool for managing WIM (formerly Firefly) configs in CyberArk Certificate Manager, SaaS",
		Long: undent.Undent(`
			vcpctl is a CLI tool for managing WIM (Workload Identity Manager,
			formerly Firefly) configurations in CyberArk Certificate Manager, SaaS
			(formerly known as Venafi Control Plane and Venafi Cloud).
            To configure it, set the APIKEY environment variable to your
            CyberArk Certificate Manager, SaaS API key. You can also set the
            APIURL environment variable to override the default API URL.
        `),
		Example: undent.Undent(`
			vcpctl ls
			vcpctl apply -f config.yaml
			vcpctl edit <config-name>
			vcpctl get <config-name> > config.yaml
			vcpctl attach-sa <config-name> --sa <sa-name>
			vcpctl sa ls
			vcpctl sa rm <sa-name>
			vcpctl sa put keypair <sa-name>
			vcpctl sa gen keypair <sa-name>
			vcpctl subca ls
			vcpctl subca rm <subca-name>
			vcpctl policy ls
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Run: func(cmd *cobra.Command, args []string) {
			logutil.Errorf(undent.Undent(`
				no command specified. To get started, run:
					vcpctl auth login
			`))
		},
	}

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "api-url", "", "Use the given CyberArk Certificate Manager, SaaS API URL. You can also set APIURL. Flag takes precedence. When using this flag, the configuration file is not used.")
	rootCmd.PersistentFlags().StringVar(&apiKeyFlag, "api-key", "", "Use the given CyberArk Certificate Manager, SaaS API key. You can also set APIKEY. Flag takes precedence. When using this flag, the configuration file is not used.")

	rootCmd.PersistentFlags().BoolVar(&logutil.EnableDebug, "debug", false, "Enable debug logging (set to 'true' to enable)")
	rootCmd.AddCommand(
		authCmd(),
		apiCmd(),
		lsCmd(),
		editCmd(),
		attachSaCmd(),
		applyCmd(),
		deprecatedPutCmd(),
		rmCmd(),
		getCmd(),
		saCmd(),
		subcaCmd(),
		policyCmd(),
	)

	rootCmd.AddCommand(ophis.Command(nil))

	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	switch {
	case errors.Is(err, APIKeyInvalid):
		logutil.Errorf("API key is invalid, try logging in again with:\n  vcpctl auth login\n")
		os.Exit(1)
	case err != nil:
		logutil.Errorf("%v", err)
		os.Exit(1)
	}
}

// Turn `serviceAccountIds` into `serviceAccounts` in the config.
func populateServiceAccountsInConfig(config *Config, sa []ServiceAccount) {
	// If the Service Account already exists in the config, update it.
	for _, saItem := range sa {
		if slices.Contains(config.ServiceAccountIds, saItem.Id) {
			// ServiceAccounts field doesn't exist, using ServiceAccountIds instead
		}
	}

	// Let's hide the IDs so that the user only sees the Service Accounts names.
	// ServiceAccountIds field doesn't exist in Config type
}

// Turn `clientAuthentication.clients[].allowedPolicyIds` into
// `clientAuthentication.clients[].allowedPolicies` with the real policy names.
// NOTE: ClientAuthenticationInformation is a union type and doesn't have a Clients field.
// This function is currently disabled as the union type structure doesn't support direct field access.
func populatePoliciesInConfig(config *Config, knownPolicies []Policy) {
	// TODO: Implement proper union type handling for ClientAuthenticationInformation
	// ClientAuthenticationInformation is a union type with only Type and union json.RawMessage fields.
	// To access Clients, we would need to unmarshal the union field based on the Type.
	// For now, this function is a no-op.
}

// In Go, you can't compare structs that contain slices, maps, or functions
// directly, so it was impossible to do:
//
//	if p == (PKCS11{})...
//
// Alternatively, we could use reflect.DeepEqual, but that would have been
// overkill.
func isZeroPKCS11(p PKCS11) bool {
	return len(p.AllowedClientLibraries) == 0 &&
		p.PartitionLabel == "" &&
		p.PartitionSerialNumber == "" &&
		p.Pin == "" &&
		!p.SigningEnabled
}

// For now we aren't yet using ~/.config/vcpctl.yml.
type ToolConf struct {
	APIURL string `json:"apiURL"`
	APIKey string `json:"apiKey"`
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
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa ls: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			svcaccts, err := getServiceAccounts(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
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
				return Fixable(fmt.Errorf("sa ls: invalid output format: %s", outputFormat))
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table, id)")
	return cmd
}

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
			vcpctl sa put keypair <sa-name>
			vcpctl sa gen keypair <sa-name>
			vcpctl sa get <sa-name>
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
		&cobra.Command{Use: "gen-rsa", Deprecated: "the 'gen-rsa' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE},
		&cobra.Command{Use: "keygen", Deprecated: "the 'keygen' command is deprecated, please use 'keypair' instead.", RunE: saGenkeypairCmd().RunE},
		&cobra.Command{Use: "get-clientid", Deprecated: "the 'get-clientid' command is deprecated, please use 'get-clientid' instead.", RunE: saGenkeypairCmd().RunE},
	)
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
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(saPutKeypairCmd())
	return cmd
}

func saGenkeypairCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "keypair <sa-name>",
		Short: "Generates an EC private key and registers it to the given Service Account, or create it if it doesn't exist",
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

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa gen keypair: %w", err)
			}

			saName := args[0]

			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			// Does it already exist?
			existingSA, err := getServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, saName)
			switch {
			case errors.As(err, &NotFound{}):
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
			patch, _, err := diffToPatchServiceAccount(existingSA, desiredSA)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while creating service account patch: %w", err)
			}

			err = patchServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String(), patch)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while patching service account: %w", err)
			}

			if logutil.EnableDebug {
				updatedSA, err := getServiceAccountByID(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String())
				if err != nil {
					return fmt.Errorf("sa gen keypair: while retrieving updated service account: %w", err)
				}
				d := ANSIDiff(existingSA, updatedSA)
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
		Short: "Creates or updates the given Key Pair Authentication Service Account",
		Long: undent.Undent(`
			Creates or updates the given 'Private Key JWT' authentication
			(also known as 'Key Pair Authentication') Service Account in
			CyberArk Certificate Manager, SaaS. Returns the Service Account's client ID.
		`),
		Example: undent.Undent(`
			vcpctl sa put keypair <sa-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa put keypair: %w", err)
			}

			saName := args[0]

			// Does it already exist?
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			existingSA, err := getServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, saName)
			switch {
			case errors.As(err, &NotFound{}):
				// Doesn't exist yet.
				resp, err := createServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, ServiceAccount{
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
				patch, smthChanged, err := diffToPatchServiceAccount(existingSA, desiredSA)
				if err != nil {
					return fmt.Errorf("sa put keypair: while creating service account patch: %w", err)
				}
				if !smthChanged {
					logutil.Debugf("Service Account '%s' is already up to date.", saName)
					fmt.Println(existingSA.Id.String())
					return nil
				}

				err = patchServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String(), patch)
				if err != nil {
					return fmt.Errorf("sa put keypair: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					updatedSA, err := getServiceAccountByID(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String())
					if err != nil {
						return fmt.Errorf("sa put keypair: while retrieving updated service account: %w", err)
					}
					d := ANSIDiff(existingSA, updatedSA)
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

func saGetCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "get <sa-name>",
		Short: "Get the information about an existing Service Account",
		Long: undent.Undent(`
			Get the Service Account's details. You can use -o clientid to only
			display the client ID of the Service Account.
		`),
		Example: undent.Undent(`
			vcpctl sa get <sa-name>
			vcpctl sa get <sa-name> -o json
			vcpctl sa get <sa-name> -o clientid
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa get: %w", err)
			}

			if len(args) != 1 {
				return fmt.Errorf("sa get: expected a single argument (the service account name), got: %s", args)
			}

			saName := args[0]

			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			sa, err := getServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, saName)
			if err != nil {
				if errors.As(err, &NotFound{}) {
					return fmt.Errorf("sa get: service account '%s' not found", saName)
				}
				return fmt.Errorf("sa get: while getting service account by name: %w", err)
			}

			if sa.Id.String() == "" {
				return fmt.Errorf("sa get: service account '%s' has no client ID", saName)
			}

			switch format {
			case "yaml":
				bytes, err := yaml.Marshal(sa)
				if err != nil {
					return fmt.Errorf("sa get: while marshaling service account to YAML: %w", err)
				}
				coloredYAMLPrint(string(bytes) + "\n") // Not sure why '\n' is needed, but it is.
				return nil
			case "id":
				fmt.Println(sa.Id.String())
				return nil
			case "json":
				data, err := json.Marshal(sa)
				if err != nil {
					return fmt.Errorf("sa get: while marshaling service account to JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			default:
				return fmt.Errorf("sa get: unknown output format: %s", format)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "output", "o", "yaml", "Output format (id, json, yaml). The 'id' is the service account's client ID.")
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
			cl := http.Client{Transport: Transport}
			if interactive {
				if len(args) > 0 {
					return fmt.Errorf("sa rm -i: expected no arguments when using --interactive, got %s", args)
				}
				// In interactive mode, we will list the service accounts and let the user
				// select one to remove.
				conf, err := getToolConfig(cmd)
				if err != nil {
					return fmt.Errorf("sa rm -i: %w", err)
				}
				apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
				if err != nil {
					return fmt.Errorf("while creating API client: %w", err)
				}
				svcaccts, err := getServiceAccounts(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
				if err != nil {
					return fmt.Errorf("sa rm -i: while listing service accounts: %w", err)
				}

				// Use a simple prompt to select the service account to remove.
				selected := rmInteractive(svcaccts)
				for _, saID := range selected {
					err = removeServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, saID)
					if err != nil {
						return fmt.Errorf("sa rm -i: while removing service account '%s': %w", saID, err)
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
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = removeServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, saName)
			if err != nil {
				return fmt.Errorf("sa rm: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactively select the service account to remove.")
	return cmd
}

// List Workload Identity Manager configurations.
func lsCmd() *cobra.Command {
	var showSaIDs bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List WIM (Workload Identity Manager, formerly Firefly) configurations",
		Long: undent.Undent(`
			List WIM (Workload Identity Manager, formerly Firefly) configurations in
			CyberArk Certificate Manager, SaaS.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("ls: %w", err)
			}

			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			confs, err := listConfigs(context.Background(), *apiClient)
			if err != nil {
				return fmt.Errorf("ls: while listing configurations: %w", err)
			}

			knownSvcaccts, err := getServiceAccounts(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("ls: fetching service accounts: %w", err)
			}

			saByID := make(map[string]ServiceAccount)
			for _, sa := range knownSvcaccts {
				saByID[sa.Id.String()] = sa
			}

			// Build a map to store formatted service account names for each config
			configSANames := make(map[string][]string)

			for _, m := range confs {
				type resolvedEntry struct {
					name  string
					id    string
					found bool
				}
				var (
					entries    []resolvedEntry
					namesInCfg = make(map[string]int)
				)
				for _, saID := range m.ServiceAccountIds {
					sa, found := saByID[saID.String()]
					if found {
						entries = append(entries, resolvedEntry{name: sa.Name, id: sa.Id.String(), found: true})
						namesInCfg[sa.Name]++
						continue
					}
					entries = append(entries, resolvedEntry{id: saID.String(), found: false})
				}

				var saNames []string
				for _, entry := range entries {
					if !entry.found {
						saNames = append(saNames, entry.id+redBold(" (deleted)"))
						continue
					}

					needsID := showSaIDs || namesInCfg[entry.name] > 1
					if needsID {
						saNames = append(saNames, fmt.Sprintf("%s (%s)", entry.name, lightGray(entry.id)))
						continue
					}

					saNames = append(saNames, entry.name)
				}
				configSANames[m.Id.String()] = saNames
			}

			var rows [][]string
			for _, m := range confs {
				rows = append(rows, []string{
					m.Name,
					strings.Join(configSANames[m.Id.String()], ", "),
				})
			}

			printTable([]string{"WIM CONFIGURATION", "Attached Service Accounts"}, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showSaIDs, "show-sa-ids", false, "Show service account IDs even when names are unique")
	return cmd
}

func subcaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subca",
		Short: "Manage SubCA Providers",
		Long: undent.Undent(`
			Manage SubCA Providers. SubCA Providers issue certificates from a SubCA.
			You can list, create, delete, and set a SubCA Provider for a WIM
			(Workload Identity Manager, formerly Firefly) configuration.

			Example:
			  vcpctl subca ls
			  vcpctl subca create --name foo
			  vcpctl subca rm foo
			  vcpctl subca pull foo
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		subcaLsCmd(),
		subcaRmCmd(),
	)
	return cmd
}

func subcaLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List SubCA Providers",
		Long: undent.Undent(`
			List SubCA Providers. SubCA Providers are used to issue certificates
			from a SubCA.
		`),
		Example: undent.Undent(`
			vcpctl subca ls
			vcpctl subca rm <subca-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("subca ls: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			providers, err := getSubCas(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("subca ls: while listing subCA providers: %w", err)
			}

			var rows [][]string
			for _, provider := range providers {
				rows = append(rows, []string{
					provider.Id.String(),
					uniqueColor(string(provider.CaType)),
					provider.Name,
				})
			}
			printTable([]string{"ID", "Type", "Sub CA Name"}, rows)
			return nil
		},
	}
	return cmd
}

func subcaRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <subca-name-or-id>",
		Short: "Remove a SubCA Provider",
		Long: undent.Undent(`
			Remove a SubCA Provider. This deletes the SubCA Provider from CyberArk
			Certificate Manager, SaaS. You cannot remove a SubCA Provider that is
			attached to a WIM (Workload Identity Manager, formerly Firefly)
			configuration.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the Sub CA name), got %s", args)
			}
			providerNameOrID := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = removeSubCaProvider(context.Background(), *apiClient, conf.APIURL, conf.APIKey, providerNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}

			return nil
		},
	}
	return cmd
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Policies",
		Long: undent.Undent(`
			Manage policies. Policies define the rules for issuing certificates.
			You can list, create, delete, and set a policy for a WIM (Workload
			Identity Manager, formerly Firefly) configuration.
		`),
		Example: undent.Undent(`
			vcpctl policy ls
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		policyLsCmd(),
		policyRmCmd(),
	)
	return cmd
}

func policyLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List Policies",
		Long: undent.Undent(`
			List Policies. Policies are used to define the rules for issuing
			certificates.
		`),
		Example: undent.Undent(`
			vcpctl policy ls
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("policy ls: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			policies, err := getPolicies(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("policy ls: while listing policies: %w", err)
			}
			var rows [][]string
			for _, policy := range policies {
				rows = append(rows, []string{
					policy.Id.String(),
					policy.Name,
					policy.ValidityPeriod,
					strings.Join(policy.Subject.CommonName.DefaultValues, ", "),
					strings.Join(policy.Sans.DnsNames.DefaultValues, ", "),
				})
			}

			printTable([]string{"ID", "Policy Name", "Validity", "Common Name", "DNS Names"}, rows)
			return nil
		},
	}
	return cmd
}

func policyRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <policy-name-or-id>",
		Short: "Remove a Policy",
		Long: undent.Undent(`
			Remove a policy. This deletes the policy from CyberArk Certificate
			Manager, SaaS. You cannot remove a policy that is attached to a WIM
			(Workload Identity Manager, formerly Firefly) configuration. Remove the
			policy from the WIM configuration first.
		`),
		Example: undent.Undent(`
			vcpctl policy rm <policy-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the Policy name), got %s", args)
			}
			policyNameOrID := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = removePolicy(context.Background(), *apiClient, conf.APIURL, conf.APIKey, policyNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			logutil.Debugf("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}

func removePolicy(ctx context.Context, cl api.Client, apiURL, apiKey, policyName string) error {
	// Find the policy by name.
	policy, err := getPolicy(ctx, cl, apiURL, apiKey, policyName)
	if err != nil {
		return fmt.Errorf("removePolicy: while getting policy by name %q: %w", policyName, err)
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL+"/v1/distributedissuers/policies/"+policy.Id.String(), nil)
	if err != nil {
		return fmt.Errorf("removePolicy: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", "vcpctl/1.0")
	resp, err := cl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("removePolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return HTTPErrorf(resp, "removePolicy: http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func getSubCas(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]SubCa, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", "vcpctl/1.0")
	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return nil, HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCa `json:"subCaProviders"`
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while reading response body: %w", err)
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, fmt.Errorf("getSubCas: while decoding %s response: %w, body was: %s", resp.Status, err, string(bytes))
	}

	return result.SubCaProviders, nil
}

func getSubCaByID(ctx context.Context, cl api.Client, apiURL, apiKey, id string) (SubCa, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/v1/distributedissuers/subcaproviders/"+id, nil)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", "vcpctl/1.0")
	resp, err := cl.Client.Do(req)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	case http.StatusNotFound:
		return SubCa{}, &NotFound{NameOrID: id}
	default:
		return SubCa{}, HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result SubCa
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while reading response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	if result.Id.String() == "" {
		return SubCa{}, Fixable(fmt.Errorf("getSubCaByID: SubCA provider '%s' not found", id))
	}
	return result, nil
}

func removeSubCaProvider(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) error {
	if looksLikeAnID(nameOrID) {
		return removeSubCaProviderByID(ctx, cl, nameOrID)
	}

	subCA, err := getSubCa(ctx, cl, apiURL, apiKey, nameOrID)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while getting SubCA provider by name '%s': %w", nameOrID, err)
	}
	if subCA.Id.String() == "" {
		return Fixable(fmt.Errorf("removeSubCaProvider: SubCA provider '%s' not found", nameOrID))
	}
	return removeSubCaProviderByID(ctx, cl, subCA.Id.String())
}

func removeSubCaProviderByID(ctx context.Context, cl api.Client, id string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", cl.Server+"/v1/distributedissuers/subcaproviders/"+id, nil)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while creating request: %w", err)
	}
	// API key and user agent should be set by the client's request editors
	resp, err := cl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func attachSaCmd() *cobra.Command {
	var saName string
	cmd := &cobra.Command{
		Use:   "attach-sa <config-name> --sa <sa-name>",
		Short: "Attach a service account to a WIM configuration",
		Long: undent.Undent(`
			Attach the given service account to the WIM (Workload Identity Manager,
			formerly Firefly) configuration.
		`),
		Example: undent.Undent(`
			vcpctl attach-sa "config-name" --sa "sa-name"
			vcpctl attach-sa "config-name" --sa "03931ba6-3fc5-11f0-85b8-9ee29ab248f0"
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("attach-sa: expected a single argument (the WIM configuration name), got %s", args)
			}
			confName := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}
			err = attachSAToConf(context.Background(), *apiClient, conf.APIURL, conf.APIKey, confName, saName)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&saName, "sa", "s", "", "Service account name or client ID to attach to the WIM configuration")
	_ = cmd.MarkFlagRequired("sa")
	return cmd
}

func attachSAToConf(ctx context.Context, cl api.Client, apiURL, apiKey, confName, saName string) error {
	// Get configuration name by ID.
	existing, err := getConfig(ctx, cl, apiURL, apiKey, confName)
	if err != nil {
		return fmt.Errorf("while fetching the ID of the Workload Identity Manager configuration '%s': %w", confName, err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(context.Background(), cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	var sa *ServiceAccount
	// First, check if saName is actually a client ID (direct match with ID).
	for _, knownSa := range knownSvcaccts {
		if knownSa.Id.String() == saName {
			sa = &knownSa
			break
		}
	}

	// If no client ID match, try looking up by name.
	if sa == nil {
		for _, knownSa := range knownSvcaccts {
			if knownSa.Name == saName {
				if sa != nil {
					return fmt.Errorf("service account name '%s' is ambiguous, please use the client ID instead", saName)
				}
				sa = &knownSa
			}
		}
	}

	if sa == nil {
		return Fixable(fmt.Errorf("service account '%s' not found (not a valid name or client ID)", saName))
	}

	// Is this SA already in the configuration?
	if slices.Contains(existing.ServiceAccountIds, sa.Id) {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.Id.String(), existing.Name)
		return nil
	}

	// Add the service account to the configuration.
	desired := existing
	desired.ServiceAccountIds = append(desired.ServiceAccountIds, sa.Id)
	patch, changed, err := diffToPatchConfig(existing, desired)
	if err != nil {
		return fmt.Errorf("while creating patch to attach service account '%s' to configuration '%s': %w", saName, confName, err)
	}
	if !changed {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.Id.String(), existing.Name)
		return nil
	}
	updated, err := patchConfig(ctx, cl, apiURL, apiKey, existing.Id, patch)
	if err != nil {
		return fmt.Errorf("while patching Workload Identity Manager configuration: %w", err)
	}

	if logutil.EnableDebug {
		d := ANSIDiff(existing, updated)
		logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
	}

	return nil
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit a WIM configuration",
		Long: undent.Undent(`
			Edit a WIM (Workload Identity Manager, formerly Firefly) configuration.
			The temporary file opened in your editor is a multi-document manifest
			containing the ServiceAccount, WIMIssuerPolicy, and WIMConfiguration
			objects in dependency order.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("edit: expected a single argument (the WIM configuration name), got %s", args)
			}

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			client, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&http.Client{Transport: Transport}), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			err = editConfig(context.Background(), *client, conf.APIURL, conf.APIKey, args[0])
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			return nil
		},
	}
}

func applyCmd() *cobra.Command {
	return newApplyLikeCmd("apply")
}

func deprecatedPutCmd() *cobra.Command {
	cmd := newApplyLikeCmd("put")
	cmd.Deprecated = "use \"vcpctl apply\" instead; this alias will be removed in a future release"
	return cmd
}

func newApplyLikeCmd(name string) *cobra.Command {
	var filePath string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   name,
		Short: "Create or update a WIM configuration",
		Long: undent.Undent(`
			Create or update a WIM (Workload Identity Manager, formerly Firefly)
			configuration in CyberArk Certificate Manager, SaaS. The configuration
			name is read from the manifest's 'name' field.
			Provide a kubectl-style multi-document manifest: declare ServiceAccount
			manifests first, followed by WIMIssuerPolicy manifests, and finish with
			a WIMConfiguration manifest.
		`),
		Example: undent.Undent(fmt.Sprintf(`
			vcpctl %s -f config.yaml
			vcpctl %s -f - < config.yaml
			vcpctl %s -f config.yaml --dry-run
		`, name, name, name)),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApply(cmd, filePath, args, dryRun)
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the WIM configuration file (YAML). Use '-' to read from stdin.")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be created/updated without making API calls")
	return cmd
}

func runApply(cmd *cobra.Command, filePath string, args []string, dryRun bool) error {
	cmdName := cmd.Name()
	var file *os.File
	switch filePath {
	case "":
		return fmt.Errorf("%s: no file specified, use --file or -f to specify a file path. You can use '-f -' to read from stdin.", cmdName)
	case "-":
		filePath = "/dev/stdin"
		file = os.Stdin
	default:
		var err error
		file, err = os.Open(filePath)
		if err != nil {
			return fmt.Errorf("%s: opening file '%s': %w", cmdName, filePath, err)
		}
		defer file.Close()
	}

	if len(args) != 0 {
		return fmt.Errorf("%s: expected no arguments. The configuration name is read from the 'name' field in the provided YAML manifest.", cmdName)
	}

	cl := http.Client{Transport: Transport}
	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdName, err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("%s: while reading WIM configuration from '%s': %w", cmdName, filePath, err)
	}

	manifests, err := parseManifests(data)
	if err != nil {
		return fmt.Errorf("%s: while decoding WIM manifests from '%s': %w", cmdName, filePath, err)
	}

	apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&cl), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
	if err != nil {
		return fmt.Errorf("%s: while creating API client: %w", cmdName, err)
	}
	err = applyManifests(apiClient, conf.APIURL, conf.APIKey, manifests, dryRun)
	if err != nil {
		return fmt.Errorf("%s: while applying manifests: %w", cmdName, err)
	}

	return nil
}

func rmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <config-name>",
		Short: "Remove a WIM configuration",
		Long: undent.Undent(`
			Remove a WIM (Workload Identity Manager, formerly Firefly)
			configuration. This deletes the configuration from CyberArk Certificate
			Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl rm my-config
			vcpctl rm 03931ba6-3fc5-11f0-85b8-9ee29ab248f0
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the WIM configuration name or ID), got %s", args)
			}
			nameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&http.Client{Transport: Transport}), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("rm: while creating API client: %w", err)
			}
			// Get the configuration by name or ID.
			c, err := getConfig(context.Background(), *apiClient, conf.APIURL, conf.APIKey, nameOrID)
			if err != nil {
				if errors.As(err, &NotFound{}) {
					return fmt.Errorf("rm: Workload Identity Manager configuration '%s' not found", nameOrID)
				}
				return fmt.Errorf("rm: while getting Workload Identity Manager configuration by name or ID '%s': %w", nameOrID, err)
			}
			// Remove the configuration.
			err = removeConfig(context.Background(), *apiClient, conf.APIURL, conf.APIKey, c.Id.String())
			if err != nil {
				return fmt.Errorf("rm: while removing Workload Identity Manager configuration '%s': %w", nameOrID, err)
			}
			logutil.Debugf("Workload Identity Manager configuration '%s' removed successfully.", nameOrID)
			return nil
		},
	}
	return cmd
}

func getPolicy(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) (Policy, error) {
	if looksLikeAnID(nameOrID) {
		return getPolicyByID(ctx, cl, apiURL, apiKey, nameOrID)
	}

	policies, err := getPolicies(ctx, cl, apiURL, apiKey)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicy: while getting policies: %w", err)
	}

	// Find the policy by name. Error out if duplicate names are found.
	var found []Policy
	for _, cur := range policies {
		if cur.Name == nameOrID {
			found = append(found, cur)
		}
	}
	if len(found) == 0 {
		return Policy{}, NotFound{NameOrID: nameOrID}
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, cur := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", cur.Name, cur.Id.String(), cur.CreationDate))
		}
		return Policy{}, fmt.Errorf(undent.Undent(`
			getPolicy: duplicate policies found with name '%s':
			%s
			Please use an ID instead, or try to remove one of the service accounts
			first with:
			    vcpctl sa rm %s
			`), nameOrID, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func getPolicyByID(ctx context.Context, cl api.Client, apiURL, apiKey, id string) (Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies/"+id, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return Policy{}, HTTPErrorf(resp, "getPolicyByID: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
	var result Policy
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while reading %s response body: %w", resp.Status, err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result, nil
}

func getSubCa(ctx context.Context, cl api.Client, apiURL, apiKey, name string) (SubCa, error) {
	if looksLikeAnID(name) {
		return getSubCaByID(ctx, cl, apiURL, apiKey, name)
	}

	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCa: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCa: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return SubCa{}, HTTPErrorf(resp, "getSubCa: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCa `json:"subCaProviders"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return SubCa{}, fmt.Errorf("getSubCa: while decoding response: %w", err)
	}

	// Error out if a duplicate name is found.
	var found []SubCa
	for _, provider := range result.SubCaProviders {
		if provider.Name == name {
			found = append(found, provider)
		}
	}
	if len(found) == 0 {
		return SubCa{}, fmt.Errorf("subCA provider: %w", NotFound{NameOrID: name})
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, cur := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s)\n", cur.Name, cur.Id.String()))
		}
		return SubCa{}, fmt.Errorf(undent.Undent(`
			getSubCa: duplicate sub CAs found with name '%s':
			%s
			Either use the subCA ID instead of the name, or remove one of the
			subCAs first with:
			    vcpctl subca rm %s
		`), name, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func getConfig(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) (Config, error) {
	if looksLikeAnID(nameOrID) {
		return getConfigByID(ctx, cl, apiURL, apiKey, nameOrID)
	}

	confs, err := getConfigs(ctx, cl, apiURL, apiKey)
	if err != nil {
		return Config{}, fmt.Errorf("getConfigByName:urations: %w", err)
	}

	// We need to error out if duplicate names are found.
	var found []Config
	for _, cur := range confs {
		if cur.Name == nameOrID || cur.Id.String() == nameOrID {
			found = append(found, cur)
		}
	}
	if len(found) == 0 {
		return Config{}, NotFound{NameOrID: nameOrID}
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, f := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", f.Name, f.Id.String(), f.CreationDate))
		}
		return Config{}, fmt.Errorf(undent.Undent(`
			getConfigByName: duplicate Workload Identity Manager configurations found with name '%s':
			%s
			Either use the Workload Identity Manager configuration ID instead of the name, or try
			removing the duplicates first with:
			    vcpctl rm %s
		`), nameOrID, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func getConfigs(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]Config, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "getConfigs: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
	var result struct {
		Configurations []Config `json:"configurations"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while reading response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("getConfigs: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.Configurations, nil
}

func removeConfig(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		config, err := getConfig(ctx, cl, apiURL, apiKey, nameOrID)
		if err != nil {
			return fmt.Errorf("removeConfig:uration by name %q: %w", nameOrID, err)
		}
		id = config.Id.String()
	}

	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/configurations/"+id, nil)
	if err != nil {
		return fmt.Errorf("removeConfig: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("removeConfig: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return &NotFound{NameOrID: nameOrID}
	default:
		return HTTPErrorf(resp, "removeConfig: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func getPolicies(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, parseJSONErrorOrDumpBody(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while reading response body: %w", err)
	}

	var result struct {
		Policies []Policy `json:"policies"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("getPolicies: while decoding response: %w, body was: %s", err, string(body))
	}
	return result.Policies, nil
}

// TODO: schema.json needs to be generated or the embed should point to an existing file
//
//go:embed genschema/schema.json
var jsonSchema []byte

func getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Export a WIM configuration",
		Long: undent.Undent(`
			Get a WIM (Workload Identity Manager, formerly Firefly) configuration
			from CyberArk Certificate Manager, SaaS. The configuration is written
			to stdout in YAML format.
		`),
		Example: undent.Undent(`
			vcpctl get <config-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("get: expected a single argument (the WIM configuration name), got %s", args)
			}
			idOrName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("get: %w", err)
			}
			apiClient, err := api.NewClient(conf.APIURL, api.WithHTTPClient(&http.Client{Transport: Transport}), api.WithBearerToken(conf.APIKey), api.WithUserAgent())
			if err != nil {
				return fmt.Errorf("get: while creating API client: %w", err)
			}

			knownSvcaccts, err := getServiceAccounts(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("get: while fetching service accounts: %w", err)
			}
			knownPolicies, err := getPolicies(context.Background(), *apiClient, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("get: while fetching policies: %w", err)
			}

			config, err := getConfig(context.Background(), *apiClient, conf.APIURL, conf.APIKey, idOrName)
			if err != nil {
				return fmt.Errorf("get: while getting original Workload Identity Manager configuration: %w", err)
			}
			populateServiceAccountsInConfig(&config, knownSvcaccts)
			populatePoliciesInConfig(&config, knownPolicies)
			hideMisleadingFields(&config)

			yamlData, err := renderToYAML(saResolver(knownSvcaccts), config)
			if err != nil {
				return err
			}

			schemaFile, err := saveSchemaToWellKnownPath()
			if err != nil {
				return fmt.Errorf("get: while saving schema.json to disk so that YAML can reference it: %w", err)
			}

			yamlData = appendSchemaComment(yamlData, schemaFile)

			coloredYAMLPrint(string(yamlData))

			return nil
		},
	}
}

func saResolver(svcAccts []ServiceAccount) func(id openapi_types.UUID) (ServiceAccount, error) {
	return func(id openapi_types.UUID) (ServiceAccount, error) {
		found := ServiceAccount{}
		for _, sa := range svcAccts {
			if sa.Id == openapi_types.UUID(id) {
				found = sa
				break
			}
		}
		if found.Id.String() == "" {
			return ServiceAccount{}, fmt.Errorf("service account with ID %s not found", id.String())
		}
		return found, nil
	}
}

// Zero out the config ID, subCA provider ID, and policy IDs in the
// configuration. Service account IDs are kept. Useful for removing misleading
// fields before marshalling to YAML.
func hideMisleadingFields(c *Config) {
	// Zero out all IDs in the configuration, so that we can use it to create
	// a new configuration without any IDs.
	c.Id = openapi_types.UUID{}
	c.CreationDate = ""
	c.ModificationDate = ""
	c.SubCaProvider.Id = openapi_types.UUID{}
	c.SubCaProvider.CaAccountId = openapi_types.UUID{}
	c.SubCaProvider.CaProductOptionId = openapi_types.UUID{}

	for i := range c.Policies {
		c.Policies[i].Id = openapi_types.UUID{}
		c.Policies[i].CreationDate = ""
		c.Policies[i].ModificationDate = ""
	}

	// ServiceAccounts field doesn't exist in Config - it uses ServiceAccountIds instead
	// which is already a slice of UUIDs, so we don't need to zero out individual IDs
}

// createConfig creates a new Workload Identity Manager configuration or updates an
// existing one. Also deals with creating the subCA policies.
func createConfig(ctx context.Context, cl api.Client, apiURL, apiKey string, config api.ConfigurationCreateRequest) (api.ExtendedConfigurationInformation, error) {
	body, err := json.Marshal(config)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while marshaling configuration: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL+"/v1/distributedissuers/configurations", bytes.NewReader(body))
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return api.ExtendedConfigurationInformation{}, HTTPErrorf(resp, "createConfig: got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while reading response body: %w", err)
	}

	var result api.ExtendedConfigurationInformation
	err = json.Unmarshal(body, &result)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

func createPolicy(ctx context.Context, cl api.Client, apiURL, apiKey string, policy api.PolicyCreateRequest) (api.ExtendedPolicyInformation, error) {
	body, err := json.Marshal(policy)
	if err != nil {
		return api.ExtendedPolicyInformation{}, fmt.Errorf("createFireflyPolicy: while marshaling policy: %w", err)
	}
	req, err := http.NewRequest("POST", apiURL+"/v1/distributedissuers/policies", bytes.NewReader(body))
	if err != nil {
		return api.ExtendedPolicyInformation{}, fmt.Errorf("createFireflyPolicy: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return api.ExtendedPolicyInformation{}, fmt.Errorf("createFireflyPolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return api.ExtendedPolicyInformation{}, HTTPErrorf(resp, "createFireflyPolicy: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return api.ExtendedPolicyInformation{}, fmt.Errorf("createFireflyPolicy: while reading response body: %w", err)
	}

	var result api.ExtendedPolicyInformation
	err = json.Unmarshal(body, &result)
	if err != nil {
		return api.ExtendedPolicyInformation{}, fmt.Errorf("createFireflyPolicy: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

func createSubCaProvider(ctx context.Context, cl api.Client, apiURL, apiKey string, provider SubCaProviderCreateRequest) (SubCa, error) {
	resp, err := cl.SubcaprovidersCreate(ctx, provider)
	if err != nil {
		return SubCa{}, fmt.Errorf("createSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return SubCa{}, HTTPErrorf(resp, "createSubCaProvider: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SubCa{}, fmt.Errorf("createSubCaProvider: while reading response body: %w", err)
	}

	var result SubCa
	err = json.Unmarshal(body, &result)
	if err != nil {
		return SubCa{}, fmt.Errorf("createSubCaProvider: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

func patchSubCaProvider(ctx context.Context, cl api.Client, apiURL, apiKey string, id string, patch SubCaProviderUpdateRequest) (SubCa, error) {
	resp, err := cl.SubcaprovidersUpdate(ctx, id, patch)
	if err != nil {
		return SubCa{}, fmt.Errorf("patchSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		var updated SubCa
		if err := decodeJSON(resp.Body, &updated); err != nil {
			return SubCa{}, fmt.Errorf("patchSubCaProvider: while decoding response: %w", err)
		}
		return updated, nil
	case http.StatusNotFound:
		return SubCa{}, fmt.Errorf("WIMSubCAProvider: %w", NotFound{NameOrID: id})
	default:
		return SubCa{}, HTTPErrorf(resp, "patchSubCaProvider: http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

type ConfigInfo struct {
	Name              string
	ServiceAccountIds []string
}

func listConfigs(ctx context.Context, cl api.Client) ([]api.ExtendedConfigurationInformation, error) {
	resp, err := cl.ConfigurationsGetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "/v1/distributedissuers/configurations: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while reading response: %w", err)
	}

	var result api.ConfigurationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.Configurations, nil
}

type NotFound struct {
	NameOrID string `json:"id"`
}

func (e NotFound) Error() string {
	return fmt.Sprintf("'%s' not found", e.NameOrID)
}

func getConfigByID(ctx context.Context, cl api.Client, apiURL, apiKey, id string) (Config, error) {
	resp, err := cl.ConfigurationsGetById(ctx, id)
	if err != nil {
		return Config{}, fmt.Errorf("getConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return api.ExtendedConfigurationInformation{}, HTTPErrorf(resp, "getConfig: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result Config
	if err := decodeJSON(resp.Body, &result); err != nil {
		return Config{}, fmt.Errorf("getConfig: while decoding response: %w", err)
	}
	return result, nil
}

func fullToPatchConfig(full Config) ConfigPatch {
	patch := ConfigPatch{
		CloudProviders:   full.CloudProviders,
		AdvancedSettings: full.AdvancedSettings,
	}

	if full.Name != "" {
		patch.Name = full.Name
	}

	if full.MinTlsVersion != "" {
		patch.MinTlsVersion = api.ConfigurationUpdateRequestMinTlsVersion(full.MinTlsVersion)
	}

	if len(full.ServiceAccountIds) > 0 {
		patch.ServiceAccountIds = full.ServiceAccountIds
	}

	if len(full.PolicyIds) > 0 {
		patch.PolicyIds = full.PolicyIds
	}

	if full.SubCaProvider.Id != (openapi_types.UUID{}) {
		patch.SubCaProviderId = full.SubCaProvider.Id
	}

	return patch
}

// diffToPatchConfig computes the difference between existing and desired
// configs and returns a patch with only the changed fields.
func diffToPatchConfig(existing, desired Config) (ConfigPatch, bool, error) {
	patch := ConfigPatch{}
	var smthChanged, fieldChanged bool
	var err error

	if desired.AdvancedSettings.EnableIssuanceAuditLog != existing.AdvancedSettings.EnableIssuanceAuditLog {
		patch.AdvancedSettings.EnableIssuanceAuditLog = desired.AdvancedSettings.EnableIssuanceAuditLog
		smthChanged = true
	}
	if desired.AdvancedSettings.IncludeRawCertDataInAuditLog != existing.AdvancedSettings.IncludeRawCertDataInAuditLog {
		patch.AdvancedSettings.IncludeRawCertDataInAuditLog = desired.AdvancedSettings.IncludeRawCertDataInAuditLog
		smthChanged = true
	}
	if desired.AdvancedSettings.RequireFIPSCompliantBuild != existing.AdvancedSettings.RequireFIPSCompliantBuild {
		patch.AdvancedSettings.RequireFIPSCompliantBuild = desired.AdvancedSettings.RequireFIPSCompliantBuild
		smthChanged = true
	}

	patch.ClientAuthentication, fieldChanged, err = diffToPatchClientAuthentication(existing.ClientAuthentication, desired.ClientAuthentication)
	if err != nil {
		return ConfigPatch{}, false, fmt.Errorf("diffToPatchConfig: while comparing the 'clientAuthentication' field on the existing and desired configurations: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.ClientAuthorization, fieldChanged = diffToPatchClientAuthorization(existing.ClientAuthorization, desired.ClientAuthorization)
	smthChanged = smthChanged || fieldChanged

	patch.CloudProviders, fieldChanged = diffToPatchCloudProviders(existing.CloudProviders, desired.CloudProviders)
	smthChanged = smthChanged || fieldChanged

	if desired.CompanyId != (openapi_types.UUID{}) && desired.CompanyId != existing.CompanyId {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'companyId' field in an existing configuration")
	}

	if desired.ControllerAllowedPolicyIds != nil && !slicesEqual(desired.ControllerAllowedPolicyIds, existing.ControllerAllowedPolicyIds) {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'controllerAllowedPolicyIds' field in an existing configuration")
	}

	if desired.CreationDate != "" && desired.CreationDate != existing.CreationDate {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'creationDate' field in an existing configuration")
	}

	if desired.Id != (openapi_types.UUID{}) && desired.Id != existing.Id {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'id' field in an existing configuration")
	}

	if desired.LongLivedCertCount != 0 && desired.LongLivedCertCount != existing.LongLivedCertCount {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'longLivedCertCount' field in an existing configuration")
	}

	if desired.MinTlsVersion != "" && desired.MinTlsVersion != existing.MinTlsVersion {
		patch.MinTlsVersion = api.ConfigurationUpdateRequestMinTlsVersion(desired.MinTlsVersion)
		smthChanged = true
	}

	if desired.ModificationDate != "" && desired.ModificationDate != existing.ModificationDate {
		return ConfigPatch{}, false, fmt.Errorf("cannot change ModificationDate of existing configuration")
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Policies != nil && !policiesEqual(existing.Policies, desired.Policies) {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'policies' field of an existing configuration")
	}

	if desired.PolicyDefinitions != nil && !policiesEqual(existing.PolicyDefinitions, desired.PolicyDefinitions) {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'policyDefinitions' field of an existing configuration")
	}

	if len(desired.PolicyIds) > 0 && !slicesEqual(desired.PolicyIds, existing.PolicyIds) {
		patch.PolicyIds = desired.PolicyIds
		smthChanged = true
	}

	// Compare ShortLivedCertCount.
	if desired.ShortLivedCertCount != 0 && desired.ShortLivedCertCount != existing.ShortLivedCertCount {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'shortLivedCertCount' field of an existing configuration")
	}

	_, changed, _ := diffToPatchSubCAProvider(existing.SubCaProvider, desired.SubCaProvider)
	if changed {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'subCaProvider' field of an existing configuration")
	}

	if desired.UltraShortLivedCertCount != 0 && desired.UltraShortLivedCertCount != existing.UltraShortLivedCertCount {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'ultraShortLivedCertCount' field of an existing configuration")
	}

	if desired.UnixSocketAllowedPolicyIds != nil && !slicesEqual(desired.UnixSocketAllowedPolicyIds, existing.UnixSocketAllowedPolicyIds) {
		return ConfigPatch{}, false, fmt.Errorf("cannot change the 'unixSocketAllowedPolicyIds' field in an existing configuration")
	}

	return patch, smthChanged, nil
}

func policiesEqual(a, b []api.PolicyInformation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].CompanyId != b[i].CompanyId {
			return false
		}
		if a[i].CreationDate != b[i].CreationDate {
			return false
		}

		if !slicesEqual(a[i].ExtendedKeyUsages, b[i].ExtendedKeyUsages) {
			return false
		}

		if a[i].Id != b[i].Id {
			return false
		}

		_, changed, _ := diffToPatchKeyAlgorithmInformation(a[i].KeyAlgorithm, b[i].KeyAlgorithm)
		if changed {
			return false
		}

		if !slicesEqual(a[i].KeyUsages, b[i].KeyUsages) {
			return false
		}

		if a[i].ModificationDate != b[i].ModificationDate {
			return false
		}

		if a[i].Name != b[i].Name {
			return false
		}

		_, changed, _ = diffToPatchSansInformation(a[i].Sans, b[i].Sans)
		if changed {
			return false
		}

		_, changed, _ = diffToPatchSubjectAttributesInformation(a[i].Subject, b[i].Subject)
		if changed {
			return false
		}

		if a[i].ValidityPeriod != b[i].ValidityPeriod {
			return false
		}
	}

	return true
}

func diffToPatchSubCAProvider(existing, desired SubCa) (SubCaProviderUpdateRequest, bool, error) {
	patch := SubCaProviderUpdateRequest{}
	var smthChanged bool

	if desired.CaAccountId != (openapi_types.UUID{}) && desired.CaAccountId != existing.CaAccountId {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CaAccountId of existing subCA provider")
	}

	if desired.CaProductOptionId != (openapi_types.UUID{}) && desired.CaProductOptionId != existing.CaProductOptionId {
		patch.CaProductOptionId = desired.CaProductOptionId
		smthChanged = true
	}

	if desired.CaType != "" && desired.CaType != existing.CaType {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CaType of existing subCA provider")
	}

	if desired.CommonName != "" && desired.CommonName != existing.CommonName {
		patch.CommonName = desired.CommonName
		smthChanged = true
	}

	if desired.Country != "" && desired.Country != existing.Country {
		patch.Country = desired.Country
		smthChanged = true
	}

	if desired.CreationDate != "" && desired.CreationDate != existing.CreationDate {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CreationDate of existing subCA provider")
	}

	if desired.Id != (openapi_types.UUID{}) && desired.Id != existing.Id {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change Id of existing subCA provider")
	}

	if desired.KeyAlgorithm != "" && desired.KeyAlgorithm != existing.KeyAlgorithm {
		patch.KeyAlgorithm = api.SubCaProviderUpdateRequestKeyAlgorithm(desired.KeyAlgorithm)
		smthChanged = true
	}

	if desired.Locality != "" && desired.Locality != existing.Locality {
		patch.Locality = desired.Locality
		smthChanged = true
	}

	if desired.ModificationDate != "" && desired.ModificationDate != existing.ModificationDate {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change ModificationDate of existing subCA provider")
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Organization != "" && desired.Organization != existing.Organization {
		patch.Organization = desired.Organization
		smthChanged = true
	}

	if desired.OrganizationalUnit != "" && desired.OrganizationalUnit != existing.OrganizationalUnit {
		patch.OrganizationalUnit = desired.OrganizationalUnit
		smthChanged = true
	}

	patch.Pkcs11 = diffToPatchSubCaProviderPkcs11ConfigurationInformation(existing.Pkcs11, desired.Pkcs11)

	if desired.StateOrProvince != "" && desired.StateOrProvince != existing.StateOrProvince {
		patch.StateOrProvince = desired.StateOrProvince
		smthChanged = true
	}

	if desired.ValidityPeriod != "" && desired.ValidityPeriod != existing.ValidityPeriod {
		patch.ValidityPeriod = desired.ValidityPeriod
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func diffToPatchSubCaProviderPkcs11ConfigurationInformation(existing, desired SubCaProviderPkcs11ConfigurationInformation) SubCaProviderPkcs11ConfigurationInformation {
	patch := SubCaProviderPkcs11ConfigurationInformation{}

	if desired.AllowedClientLibraries != nil && !slicesEqual(desired.AllowedClientLibraries, existing.AllowedClientLibraries) {
		patch.AllowedClientLibraries = desired.AllowedClientLibraries
	}

	if desired.PartitionSerialNumber != "" && desired.PartitionSerialNumber != existing.PartitionSerialNumber {
		patch.PartitionSerialNumber = desired.PartitionSerialNumber
	}

	if desired.PartitionLabel != "" && desired.PartitionLabel != existing.PartitionLabel {
		patch.PartitionLabel = desired.PartitionLabel
	}

	if desired.Pin != "" && desired.Pin != existing.Pin {
		patch.Pin = desired.Pin
	}

	if desired.SigningEnabled != existing.SigningEnabled {
		patch.SigningEnabled = desired.SigningEnabled
	}

	return patch
}

func diffToPatchPolicy(existing, desired Policy) (api.PolicyUpdateRequest, bool, error) {
	patch := api.PolicyUpdateRequest{}
	var smthChanged, fieldChanged bool

	if desired.CompanyId.ID() != 0 && desired.CompanyId != existing.CompanyId {
		return api.PolicyUpdateRequest{}, false, fmt.Errorf("cannot change CompanyId of existing policy")
	}

	if len(desired.Configurations) > 0 && !reflect.DeepEqual(desired.Configurations, existing.Configurations) {
		return api.PolicyUpdateRequest{}, false, fmt.Errorf("cannot change Configurations of existing policy")
	}

	if len(desired.ExtendedKeyUsages) > 0 && !slicesEqual(desired.ExtendedKeyUsages, existing.ExtendedKeyUsages) {
		for _, eku := range desired.ExtendedKeyUsages {
			patch.ExtendedKeyUsages = append(patch.ExtendedKeyUsages, api.PolicyUpdateRequestExtendedKeyUsages(eku))
		}
		smthChanged = true
	}

	var err error
	patch.KeyAlgorithm, fieldChanged, err = diffToPatchKeyAlgorithmInformation(existing.KeyAlgorithm, desired.KeyAlgorithm)
	if err != nil {
		return api.PolicyUpdateRequest{}, false, err
	}
	smthChanged = smthChanged || fieldChanged

	if len(desired.KeyUsages) > 0 && !slicesEqual(desired.KeyUsages, existing.KeyUsages) {
		var usages []api.PolicyUpdateRequestKeyUsages
		for _, ku := range desired.KeyUsages {
			usages = append(usages, api.PolicyUpdateRequestKeyUsages(ku))
		}
		patch.KeyUsages = usages
		smthChanged = true
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	patch.Sans, fieldChanged, err = diffToPatchSansInformation(existing.Sans, desired.Sans)
	if err != nil {
		return api.PolicyUpdateRequest{}, false, fmt.Errorf("diffToPatchPolicy: while comparing the 'sans' field on the existing and desired policies: %w", err)
	}
	patch.Subject, fieldChanged, err = diffToPatchSubjectAttributesInformation(existing.Subject, desired.Subject)
	if err != nil {
		return api.PolicyUpdateRequest{}, false, fmt.Errorf("diffToPatchPolicy: while comparing the 'subject' field on the existing and desired policies: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	if desired.ValidityPeriod != "" && desired.ValidityPeriod != existing.ValidityPeriod {
		patch.ValidityPeriod = desired.ValidityPeriod
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func diffToPatchKeyAlgorithmInformation(existing, desired api.KeyAlgorithmInformation) (api.KeyAlgorithmInformation, bool, error) {
	patch := api.KeyAlgorithmInformation{}
	var smthChanged bool

	if desired.AllowedValues != nil && !slicesEqual(desired.AllowedValues, existing.AllowedValues) {
		patch.AllowedValues = desired.AllowedValues
		smthChanged = true
	}

	if desired.DefaultValue != "" && desired.DefaultValue != existing.DefaultValue {
		patch.DefaultValue = desired.DefaultValue
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func diffToPatchSansInformation(existing, desired api.SansInformation) (api.SansInformation, bool, error) {
	patch := api.SansInformation{}
	var fieldWasChanged, somethingChanged bool
	var err error

	patch.DnsNames, fieldWasChanged, err = diffToPatchPropertyInformation(existing.DnsNames, desired.DnsNames)
	if err != nil {
		return api.SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'dnsNames' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.IpAddresses, fieldWasChanged, err = diffToPatchPropertyInformation(existing.IpAddresses, desired.IpAddresses)
	if err != nil {
		return api.SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'ipAddresses' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.Rfc822Names, fieldWasChanged, err = diffToPatchPropertyInformation(existing.Rfc822Names, desired.Rfc822Names)
	if err != nil {
		return api.SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'rfc822Names' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.UniformResourceIdentifiers, fieldWasChanged, err = diffToPatchPropertyInformation(existing.UniformResourceIdentifiers, desired.UniformResourceIdentifiers)
	if err != nil {
		return api.SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'uniformResourceIdentifiers' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	return patch, somethingChanged, nil
}

func diffToPatchSubjectAttributesInformation(existing, desired api.SubjectAttributesInformation) (api.SubjectAttributesInformation, bool, error) {
	patch := api.SubjectAttributesInformation{}
	var smthChanged, fieldChanged bool
	var err error

	patch.CommonName, fieldChanged, err = diffToPatchPropertyInformation(existing.CommonName, desired.CommonName)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'commonName' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Country, fieldChanged, err = diffToPatchPropertyInformation(existing.Country, desired.Country)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'country' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Locality, fieldChanged, err = diffToPatchPropertyInformation(existing.Locality, desired.Locality)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'locality' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Organization, fieldChanged, err = diffToPatchPropertyInformation(existing.Organization, desired.Organization)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'organization' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.OrganizationalUnit, fieldChanged, err = diffToPatchPropertyInformation(existing.OrganizationalUnit, desired.OrganizationalUnit)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'organizationalUnit' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.StateOrProvince, fieldChanged, err = diffToPatchPropertyInformation(existing.StateOrProvince, desired.StateOrProvince)
	if err != nil {
		return api.SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'stateOrProvince' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	return patch, smthChanged, nil
}

func diffToPatchPropertyInformation(existing, desired api.PropertyInformation) (api.PropertyInformation, bool, error) {
	patch := api.PropertyInformation{}
	changed := false

	if desired.AllowedValues != nil && !slicesEqual(desired.AllowedValues, existing.AllowedValues) {
		changed = true
	}

	if desired.DefaultValues != nil && !slicesEqual(desired.DefaultValues, existing.DefaultValues) {
		changed = true
	}

	if desired.MaxOccurrences != existing.MaxOccurrences {
		changed = true
	}

	if desired.MinOccurrences != existing.MinOccurrences {
		changed = true
	}

	if desired.Type != "" && desired.Type != existing.Type {
		changed = true
	}

	if changed {
		// All fields are mandatory if a change needs to be made to one of the
		// values. Thus, if a change is needed in one of the fields, the
		// existing values are carried over so that the API doesn't fail.
		// Otherwise, we keep everything zeroed out so that this field isn't
		// rendered to JSON.
		patch.Type = desired.Type
		patch.MinOccurrences = desired.MinOccurrences
		patch.MaxOccurrences = desired.MaxOccurrences
		patch.AllowedValues = desired.AllowedValues
		patch.DefaultValues = desired.DefaultValues

		err := validatePropertyInformation(patch)
		if err != nil {
			return api.PropertyInformation{}, false, err
		}
	}

	return patch, changed, nil
}

func validatePropertyInformation(pi api.PropertyInformation) error {
	if pi.Type == "" &&
		pi.MinOccurrences == 0 &&
		pi.MaxOccurrences == 0 &&
		len(pi.AllowedValues) == 0 &&
		len(pi.DefaultValues) == 0 {
		// The JSON object is omitted entirely if all fields are zeroed out.
		// That's why it is allowed.
		return nil
	}

	if pi.Type == "" {
		return Fixable(fmt.Errorf("property information 'type' field is required"))
	}

	switch pi.Type {
	case "IGNORED", "FORBIDDEN":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		if len(pi.AllowedValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'allowedValues' field must be empty, but was %v", pi.Type, pi.AllowedValues)
		}
		if len(pi.DefaultValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must be empty, but was %v", pi.Type, pi.DefaultValues)
		}
	case "OPTIONAL":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences <= 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be greater than 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		for _, v := range pi.AllowedValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'allowedValues' field must not contain blank values, but was %v", pi.Type, pi.AllowedValues)
			}
		}
		for _, v := range pi.DefaultValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not contain blank values, but was %v", pi.Type, pi.DefaultValues)
			}
		}
	case "REQUIRED":
		if pi.MinOccurrences <= 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be greater than 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences < pi.MinOccurrences {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be greater than or equal to 'minOccurrences', but was %d", pi.Type, pi.MaxOccurrences)
		}
		for _, v := range pi.AllowedValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'allowedValues' field must not contain blank values, but was %v", pi.Type, pi.AllowedValues)
			}
		}
		if len(pi.DefaultValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must be empty, but was %v", pi.Type, pi.DefaultValues)
		}
	case "LOCKED":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		if len(pi.AllowedValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'allowedValues' field must be empty, but was %v", pi.Type, pi.AllowedValues)
		}
		if len(pi.DefaultValues) == 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not be empty, but was %v", pi.Type, pi.DefaultValues)
		}
		for _, v := range pi.DefaultValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not contain blank values, but was %v", pi.Type, pi.DefaultValues)
			}
		}
	default:
		return Fixable(fmt.Errorf("property information 'type' field has invalid value: %s", pi.Type))
	}

	return nil
}

func slicesEqual[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffToPatchCloudProviders(existing, desired api.CloudProvidersInformation) (api.CloudProvidersInformation, bool) {
	patch := api.CloudProvidersInformation{}
	var fieldChanged, smthChanged bool

	patch.Aws, fieldChanged = diffToPatchAwsCloudProviderInformation(existing.Aws, desired.Aws)
	smthChanged = smthChanged || fieldChanged
	patch.Azure, fieldChanged = diffToPatchAzureCloudProviderInformation(existing.Azure, desired.Azure)
	smthChanged = smthChanged || fieldChanged
	patch.Google, fieldChanged = diffToPatchGoogleCloudProviderInformation(existing.Google, desired.Google)
	smthChanged = smthChanged || fieldChanged

	return patch, smthChanged
}

func diffToPatchAwsCloudProviderInformation(existing, desired api.AwsCloudProviderInformation) (api.AwsCloudProviderInformation, bool) {
	patch := api.AwsCloudProviderInformation{}
	var smthChanged bool

	if desired.AccountIds != nil && !slicesEqual(desired.AccountIds, existing.AccountIds) {
		patch.AccountIds = desired.AccountIds
		smthChanged = true
	}

	if desired.Regions != nil && !slicesEqual(desired.Regions, existing.Regions) {
		patch.Regions = desired.Regions
		smthChanged = true
	}

	return patch, smthChanged
}

func diffToPatchAzureCloudProviderInformation(existing, desired api.AzureCloudProviderInformation) (api.AzureCloudProviderInformation, bool) {
	patch := api.AzureCloudProviderInformation{}
	var smthChanged bool

	if desired.SubscriptionIds != nil && !slicesEqual(desired.SubscriptionIds, existing.SubscriptionIds) {
		patch.SubscriptionIds = desired.SubscriptionIds
		smthChanged = true
	}

	return patch, smthChanged
}

func diffToPatchGoogleCloudProviderInformation(existing, desired api.GoogleCloudProviderInformation) (api.GoogleCloudProviderInformation, bool) {
	patch := api.GoogleCloudProviderInformation{}
	var smthChanged bool

	if desired.ProjectIdentifiers != nil && !slicesEqual(desired.ProjectIdentifiers, existing.ProjectIdentifiers) {
		patch.ProjectIdentifiers = desired.ProjectIdentifiers
		smthChanged = true
	}

	if desired.Regions != nil && !slicesEqual(desired.Regions, existing.Regions) {
		patch.Regions = desired.Regions
		smthChanged = true
	}

	return patch, smthChanged
}

func diffToPatchClientAuthentication(existing, desired api.ClientAuthenticationInformation) (api.ClientAuthenticationInformation, bool, error) {
	patch := api.ClientAuthenticationInformation{}
	var smthChanged bool

	desiredRaw, err := desired.ValueByDiscriminator()
	if err != nil {
		return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the desired 'clientAuthentication' field: %w", err)
	}
	existingRaw, err := existing.ValueByDiscriminator()
	if err != nil {
		return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the existing 'clientAuthentication' field: %w", err)
	}

	switch desiredVal := desiredRaw.(type) {
	case api.JwtJwksAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case api.JwtJwksAuthenticationInformation:
			var patchVal api.JwtJwksAuthenticationInformation
			if desiredVal.Urls != nil && !slicesEqual(desiredVal.Urls, existingVal.Urls) {
				patchVal.Urls = desiredVal.Urls
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtJwksAuthenticationInformation(patchVal)
				if err != nil {
					return api.ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_JWKS in patch: %w", err)
				}
			}

		default:
			err = patch.FromJwtJwksAuthenticationInformation(desiredVal)
			smthChanged = true
		}
	case api.JwtOidcAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case api.JwtOidcAuthenticationInformation:
			var patchVal api.JwtOidcAuthenticationInformation
			if desiredVal.Audience != "" && desiredVal.Audience != existingVal.Audience {
				patchVal.Audience = desiredVal.Audience
				smthChanged = true
			}

			if desiredVal.BaseUrl != "" && desiredVal.BaseUrl != existingVal.BaseUrl {
				patchVal.BaseUrl = desiredVal.BaseUrl
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtOidcAuthenticationInformation(patchVal)
				if err != nil {
					return api.ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_OIDC in patch: %w", err)
				}
			}
		default:
			err = patch.FromJwtOidcAuthenticationInformation(desiredVal)
			smthChanged = true
		}
	case api.JwtStandardClaimsAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case api.JwtStandardClaimsAuthenticationInformation:
			var patchVal api.JwtStandardClaimsAuthenticationInformation
			if desiredVal.Audience != "" && desiredVal.Audience != existingVal.Audience {
				patchVal.Audience = desiredVal.Audience
				smthChanged = true
			}

			patchJwtCl, fieldChanged := diffToPatchJwtClientInformation(existingVal.Clients, desiredVal.Clients)
			smthChanged = smthChanged || fieldChanged
			patchVal.Clients = patchJwtCl

			if smthChanged {
				err = patch.FromJwtStandardClaimsAuthenticationInformation(patchVal)
				if err != nil {
					return api.ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_STANDARD_CLAIMS in patch: %w", err)
				}
			}
		default:
			err = patch.FromJwtStandardClaimsAuthenticationInformation(desiredVal)
			if err != nil {
				return api.ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_STANDARD_CLAIMS in patch: %w", err)
			}
			smthChanged = true
		}
	default:
		return api.ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: unexpected, ValueByDiscriminator should have errored first for unsupported 'type' field value, got %T", desiredRaw)
	}
	return patch, smthChanged, nil
}

func diffToPatchJwtClientInformation(existing, desired []api.JwtClientInformation) ([]api.JwtClientInformation, bool) {
	patch := []api.JwtClientInformation{}
	var smthChanged bool

	if len(desired) != len(existing) {
		patch = desired
		smthChanged = true
		return patch, smthChanged
	}

	patch = make([]api.JwtClientInformation, len(desired))
	for i := range len(desired) {
		if desired[i].AllowedPolicyIds != nil && !slicesEqual(desired[i].AllowedPolicyIds, existing[i].AllowedPolicyIds) {
			patch[i].AllowedPolicyIds = desired[i].AllowedPolicyIds
			smthChanged = true
		}

		if desired[i].Issuer != "" && desired[i].Issuer != existing[i].Issuer {
			patch[i].Issuer = desired[i].Issuer
			smthChanged = true
		}

		if desired[i].JwksUri != "" && desired[i].JwksUri != existing[i].JwksUri {
			patch[i].JwksUri = desired[i].JwksUri
			smthChanged = true
		}

		if desired[i].Name != "" && desired[i].Name != existing[i].Name {
			patch[i].Name = desired[i].Name
			smthChanged = true
		}

		if desired[i].Subjects != nil && !slicesEqual(desired[i].Subjects, existing[i].Subjects) {
			patch[i].Subjects = desired[i].Subjects
			smthChanged = true
		}
	}

	return patch, smthChanged
}

func diffToPatchClientAuthorization(existing, desired api.ClientAuthorizationInformation) (api.ClientAuthorizationInformation, bool) {
	patch := api.ClientAuthorizationInformation{}
	var smthChanged bool

	if desired.CustomClaimsAliases.Configuration != "" && existing.CustomClaimsAliases.Configuration != desired.CustomClaimsAliases.Configuration {
		patch.CustomClaimsAliases.Configuration = desired.CustomClaimsAliases.Configuration
		smthChanged = true
	}

	if desired.CustomClaimsAliases.AllowAllPolicies != "" && existing.CustomClaimsAliases.AllowAllPolicies != desired.CustomClaimsAliases.AllowAllPolicies {
		patch.CustomClaimsAliases.AllowAllPolicies = desired.CustomClaimsAliases.AllowAllPolicies
		smthChanged = true
	}

	if desired.CustomClaimsAliases.AllowedPolicies != "" && existing.CustomClaimsAliases.AllowedPolicies != desired.CustomClaimsAliases.AllowedPolicies {
		patch.CustomClaimsAliases.AllowedPolicies = desired.CustomClaimsAliases.AllowedPolicies
		smthChanged = true
	}

	return patch, smthChanged
}

func diffToPatchServiceAccount(existing, desired ServiceAccount) (ServiceAccountPatch, bool, error) {
	patch := ServiceAccountPatch{}
	var smthChanged bool

	if desired.Applications != nil && !slicesEqual(desired.Applications, existing.Applications) {
		patch.Applications = desired.Applications
		smthChanged = true
	}

	if desired.Audience != "" && desired.Audience != existing.Audience {
		patch.Audience = desired.Audience
		smthChanged = true
	}

	if desired.CredentialLifetime != 0 && desired.CredentialLifetime != existing.CredentialLifetime {
		patch.CredentialLifetime = desired.CredentialLifetime
		smthChanged = true
	}

	if desired.IssuerURL != "" && desired.IssuerURL != existing.IssuerURL {
		patch.IssuerURL = desired.IssuerURL
		smthChanged = true
	}

	if desired.JwksURI != "" && desired.JwksURI != existing.JwksURI {
		patch.JwksURI = desired.JwksURI
		smthChanged = true
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Owner.ID() != 0 && desired.Owner != existing.Owner {
		return ServiceAccountPatch{}, false, fmt.Errorf("cannot change Owner of existing service account")
	}

	if desired.PublicKey != "" && desired.PublicKey != existing.PublicKey {
		patch.PublicKey = desired.PublicKey
		smthChanged = true
	}

	if desired.Scopes != nil && !slicesEqual(desired.Scopes, existing.Scopes) {
		patch.Scopes = desired.Scopes
		smthChanged = true
	}

	if desired.Subject != "" && desired.Subject != existing.Subject {
		patch.Subject = desired.Subject
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if a[k] != v {
			return false
		}
	}
	return true
}

func PatchToManifest(patch ConfigPatch) (manifest.WIMConfiguration, error) {
	var policies []string
	for _, pid := range patch.PolicyIds {
		policies = append(policies, pid.String())
	}

	subCaProviderID := ""
	if patch.SubCaProviderId != (openapi_types.UUID{}) {
		subCaProviderID = patch.SubCaProviderId.String()
	}

	minTLS := ""
	if patch.MinTlsVersion != "" {
		minTLS = string(patch.MinTlsVersion)
	}

	name := ""
	if patch.Name != "" {
		name = patch.Name
	}

	return manifest.WIMConfiguration{
		Name:              name,
		SubCaProviderName: subCaProviderID,
		PolicyNames:       policies,
		CloudProviders:    patch.CloudProviders,
		MinTLSVersion:     minTLS,
		AdvancedSettings:  apiToManifestAdvancedSettings(patch.AdvancedSettings),
	}, nil
}

func editConfig(ctx context.Context, cl api.Client, apiURL, apiKey, name string) error {
	knownSvcaccts, err := getServiceAccounts(ctx, cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}
	knownPolicies, err := getPolicies(ctx, cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching policies: %w", err)
	}

	config, err := getConfig(ctx, cl, apiURL, apiKey, name)
	switch {
	case errors.Is(err, NotFound{}):
		return Fixable(fmt.Errorf("configuration '%s' not found. Please create it first using 'vcpctl apply config.yaml'", name))
	case err != nil:
		return fmt.Errorf("while getting configuration ID: %w", err)
	}

	populateServiceAccountsInConfig(&config, knownSvcaccts)
	populatePoliciesInConfig(&config, knownPolicies)
	hideMisleadingFields(&config)

	yamlData, err := renderToYAML(saResolver(knownSvcaccts), config)
	if err != nil {
		return err
	}

	schemaFile, err := saveSchemaToWellKnownPath()
	if err != nil {
		return fmt.Errorf("while saving schema.json to disk so that YAML can reference it: %w", err)
	}
	defer os.Remove(schemaFile)

	yamlData = appendSchemaComment(yamlData, schemaFile)

	tmpfile, err := os.CreateTemp("", "vcp-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(yamlData); err != nil {
		return err
	}
	defer tmpfile.Close()

	info, _ := os.Stat(tmpfile.Name())
	lastSaved := info.ModTime()
	justSaved := func() {
		info, _ := os.Stat(tmpfile.Name())
		lastSaved = info.ModTime()
	}
edit:
	// Open editor to let you edit YAML.
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf(`%s "%s"`, editor, tmpfile.Name()))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	// Read and parse the modified YAML.
	modifiedRaw, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		return err
	}

	// Abort if the file is empty or if the file hasn't been written to.
	if len(modifiedRaw) == 0 {
		logutil.Debugf("the configuration file is empty, aborting")
		return nil
	}
	info, _ = os.Stat(tmpfile.Name())
	if info.ModTime().Equal(lastSaved) {
		logutil.Infof("No edits, aborting.")
		return nil
	}

	modified, err := parseManifests(modifiedRaw)
	switch {
	case errors.As(err, &FixableError{}):
		err = addErrorNoticeToFile(tmpfile.Name(), err)
		if err != nil {
			return fmt.Errorf("while showing notice for fixable error: %w", err)
		}
		justSaved()
		goto edit
	case err != nil:
		return fmt.Errorf("while parsing modified Workload Identity Manager manifests: %w", err)
	}

	apiClient, err := api.NewClient(apiURL, api.WithHTTPClient(&http.Client{Transport: Transport}), api.WithBearerToken(apiKey), api.WithUserAgent())
	if err != nil {
		return fmt.Errorf("edit: while creating API client: %w", err)
	}
	err = applyManifests(apiClient, apiURL, apiKey, modified, false)
	switch {
	// In case we were returned a 400 Bad Request or if it's a fixable error,
	// let's give a chance to the user to fix the problem.
	case errors.As(err, &FixableError{}), IsHTTPBadRequest(err):
		err = addErrorNoticeToFile(tmpfile.Name(), err)
		if err != nil {
			return fmt.Errorf("while showing notice for fixable error: %w", err)
		}
		justSaved()
		goto edit
	case err != nil:
		return fmt.Errorf("while merging and patching Workload Identity Manager configuration: %w", err)
	}

	return nil
}

func addErrorNoticeToFile(tmpfile string, err error) error {
	if err == nil {
		logutil.Errorf("addErrorNoticeToFile: err is nil")
		return nil
	}

	// Read and parse the modified YAML.
	modifiedRaw, rerr := os.ReadFile(tmpfile)
	if rerr != nil {
		logutil.Errorf("while reading temporary file to show notice: %s", rerr)
		return fmt.Errorf("while reading temporary file to show notice: %w", rerr)
	}

	logutil.Debugf("the configuration you have modified has an issue:\n%s", err)

	modifiedRaw = removeNoticeFromYAML(modifiedRaw)
	notice := "# NOTICE: Errors were found, please edit the configuration.\n" +
		"# NOTICE: You can abort editing by emptying this file.\n" +
		"# NOTICE:\n" +
		"# NOTICE: " + strings.ReplaceAll(err.Error(), "\n", "\n# NOTICE: ") + "\n\n"
	err = os.WriteFile(tmpfile, append([]byte(notice), modifiedRaw...), 0644)
	if err != nil {
		return fmt.Errorf("while writing notice to temporary file: %w", err)
	}

	return nil
}

var re = regexp.MustCompile(`(?m)^# NOTICE:.*\n`)

// Remove the NOTICE lines from the YAML data.
func removeNoticeFromYAML(yamlData []byte) []byte {
	return re.ReplaceAll(yamlData, []byte{})
}

// Doesn't work anymore since `serviceAccountIds` is hidden in the 'get', 'put,
// and 'edit' commands.
var ErrPINRequired = Fixable(fmt.Errorf("subCaProvider.pkcs11.pin is required when patching the subCA provider"))

// To check whether an error is fixable by the user, wrap it with Fixable(err).
// Then, check with errors.As(err, Fixable{}).
func Fixable(err error) error {
	return FixableError{Err: err}
}

type FixableError struct {
	Err error
}

func (f FixableError) Error() string {
	return f.Err.Error()
}
func (f FixableError) Unwrap() error {
	return f.Err
}

var APIKeyInvalid = errors.New("API key is invalid")

// Use errors.Is(err, APIKeyInvalid{}) to check if the error is due to the API
// key having a problem.
func parseJSONErrorOrDumpBody(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	// For some reason, CyberArk Certificate Manager, SaaS returns a plain text error message when the
	// API key is invalid.
	if resp.Header.Get("Content-Type") == "text/plain" && bytes.Equal(body, []byte("Invalid api key")) {
		return Fixable(APIKeyInvalid)
	}

	var v VenafiError
	err := json.Unmarshal(body, &v)
	if err != nil {
		return fmt.Errorf("unexpected error: '%s'", string(body))
	}

	return v
}

// Examples:
//
//	{"errors":[{"code":1006,"message":"request object parsing failed","args":["request object parsing failed"]}]}
//	{"errors":[{"code":10051,"message":"Unable to find VenafiCaIssuerPolicy for key [c549e230-454c-11f0-906f-19aebcf83bb8]","args":["VenafiCaIssuerPolicy",["c549e230-454c-11f0-906f-19aebcf83bb8"]]}]}
type VenafiError struct {
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (e VenafiError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d: %s", err.Code, err.Message))
	}
	return fmt.Sprintf("\n* %s", strings.Join(msgs, "\n* "))
}

func fullToPatchSubCAProvider(full SubCa) SubCaProviderUpdateRequest {
	return SubCaProviderUpdateRequest{
		CaProductOptionId:  full.CaProductOptionId,
		CommonName:         full.CommonName,
		Country:            full.Country,
		KeyAlgorithm:       api.SubCaProviderUpdateRequestKeyAlgorithm(full.KeyAlgorithm),
		Locality:           full.Locality,
		Name:               full.Name,
		Organization:       full.Organization,
		OrganizationalUnit: full.OrganizationalUnit,
		Pkcs11:             full.Pkcs11,
		StateOrProvince:    full.StateOrProvince,
		ValidityPeriod:     full.ValidityPeriod,
	}
}

func fullToPatchPolicy(full Policy) PolicyPatch {
	keyUsages := make([]api.PolicyUpdateRequestKeyUsages, len(full.KeyUsages))
	for i, ku := range full.KeyUsages {
		keyUsages[i] = api.PolicyUpdateRequestKeyUsages(ku)
	}
	extendedKeyUsages := make([]api.PolicyUpdateRequestExtendedKeyUsages, len(full.ExtendedKeyUsages))
	for i, eku := range full.ExtendedKeyUsages {
		extendedKeyUsages[i] = api.PolicyUpdateRequestExtendedKeyUsages(eku)
	}
	return PolicyPatch{
		Name:              full.Name,
		KeyAlgorithm:      full.KeyAlgorithm,
		KeyUsages:         keyUsages,
		ExtendedKeyUsages: extendedKeyUsages,
		Sans:              full.Sans,
		Subject:           full.Subject,
		ValidityPeriod:    full.ValidityPeriod,
	}
}

// https://api.venafi.cloud/v1/distributedissuers/policies/{id}
func patchPolicy(ctx context.Context, cl api.Client, apiURL, apiKey string, id string, patch PolicyPatch) (Policy, error) {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return Policy{}, err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/distributedissuers/policies/%s", apiURL, id), bytes.NewReader(patchJSON))
	if err != nil {
		return Policy{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return Policy{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		var updated Policy
		err := decodeJSON(resp.Body, &updated)
		if err != nil {
			return Policy{}, fmt.Errorf("while decoding response: %w, body: %s", err, resp.Body)
		}
		return updated, nil
	case http.StatusNotFound:
		return Policy{}, fmt.Errorf("Workload Identity Manager policy: %w", NotFound{NameOrID: id})
	default:
		return Policy{}, HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

// https://api.venafi.cloud/v1/distributedissuers/configurations/{id}
func patchConfig(ctx context.Context, cl api.Client, apiURL, apiKey string, id openapi_types.UUID, patch ConfigPatch) (Config, error) {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return Config{}, fmt.Errorf("patchConfig: while marshaling patch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", apiURL, id.String()), bytes.NewReader(patchJSON))
	if err != nil {
		return Config{}, fmt.Errorf("patchConfig: while creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return Config{}, fmt.Errorf("patchConfig: while sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful, continue below.
	case http.StatusNotFound:
		return Config{}, fmt.Errorf("WIM configuration: %w", NotFound{NameOrID: id.String()})
	default:
		return Config{}, HTTPErrorf(resp, "patchConfig: unexpected http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body := new(bytes.Buffer)
	_, err = io.Copy(body, resp.Body)
	if err != nil {
		return Config{}, fmt.Errorf("while reading service accounts: %w", err)
	}

	var result api.ExtendedConfigurationInformation
	err = json.Unmarshal(body.Bytes(), &result)
	if err != nil {
		return Config{}, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result, nil
}

func getServiceAccounts(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]ServiceAccount, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/serviceaccounts", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return nil, HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("while reading service accounts: %w", err)
	}

	var result []ServiceAccount
	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result, nil
}

func removeServiceAccount(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		sa, err := getServiceAccount(ctx, cl, apiURL, apiKey, nameOrID)
		if err != nil {
			if errors.Is(err, NotFound{}) {
				return fmt.Errorf("service account '%s' not found", nameOrID)
			}
			return fmt.Errorf("while getting service account by name '%s': %w", nameOrID, err)
		}
		id = sa.Id.String()
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("service account: %w", NotFound{NameOrID: id})
	case http.StatusNoContent:
		// The deletion was successful.
		return nil
	default:
		return HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func findServiceAccount(nameOrID string, allSAs []ServiceAccount) (ServiceAccount, error) {
	if looksLikeAnID(nameOrID) {
		for _, sa := range allSAs {
			if sa.Id.String() == nameOrID {
				return sa, nil
			}
		}
		return ServiceAccount{}, NotFound{NameOrID: nameOrID}
	}

	for _, sa := range allSAs {
		if sa.Name == nameOrID {
			return sa, nil
		}
	}
	return ServiceAccount{}, NotFound{NameOrID: nameOrID}
}

func getServiceAccount(ctx context.Context, cl api.Client, apiURL, apiKey, nameOrID string) (ServiceAccount, error) {
	if looksLikeAnID(nameOrID) {
		return getServiceAccountByID(ctx, cl, apiURL, apiKey, nameOrID)
	}

	sas, err := getServiceAccounts(ctx, cl, apiURL, apiKey)
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("getServiceAccount: while getting service accounts: %w", err)
	}

	// Error out if a duplicate service account name is found.
	var found []ServiceAccount
	for _, sa := range sas {
		if sa.Name == nameOrID {
			found = append(found, sa)
		}
	}

	if len(found) == 0 {
		return ServiceAccount{}, NotFound{NameOrID: nameOrID}
	}
	if len(found) == 1 {
		return found[0], nil
	}

	// If we have multiple service accounts with the same name, let the user
	// know about the duplicates.
	var b strings.Builder
	for _, sa := range found {
		_, _ = b.WriteString(fmt.Sprintf("  - %s (%s)\n", sa.Name, sa.Id))
	}
	return ServiceAccount{}, fmt.Errorf(undent.Undent(`
		getServiceAccount: duplicate service account name '%s' found.
		The conflicting service accounts are:
		%s
		Please use a client ID (that's the same as the service account ID), or
		remove the duplicates using:
		    vcpctl sa rm %s
		`), nameOrID, b.String(), found[0].Id.String())
}

func getServiceAccountByID(ctx context.Context, cl api.Client, apiURL, apiKey, id string) (ServiceAccount, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), nil)
	if err != nil {
		return ServiceAccount{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return ServiceAccount{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return ServiceAccount{}, HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result ServiceAccount
	if err := decodeJSON(resp.Body, &result); err != nil {
		return ServiceAccount{}, fmt.Errorf("getServiceAccountByID: while decoding response: %w", err)
	}
	return result, nil
}

// Returns the PEM-encoded private and public keys.
func genECKeyPair() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while generating EC key pair: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while marshalling private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("genECKeyPair: while marshalling public key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return string(privPEM), string(pubPEM), nil
}

// Owner can be left empty, in which case the first team will be used as the
// owner.
func createServiceAccount(ctx context.Context, cl api.Client, apiURL, apiKey string, desired ServiceAccount) (api.CreateServiceAccountResponseBody, error) {
	// If no owner is specified, let's just use the first team we can find.
	if desired.Owner == (openapi_types.UUID{}) {
		teams, err := getTeams(ctx, cl, apiURL, apiKey)
		if err != nil {
			return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: no teams found, please specify an owner")
		}
		ownerUUID := openapi_types.UUID{}
		err = ownerUUID.UnmarshalText([]byte(teams[0].ID))
		if err != nil {
			return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: while parsing the first team's ID '%s' as UUID: %w", teams[0].ID, err)
		}

		logutil.Infof("no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].ID)
		desired.Owner = ownerUUID
	}

	jsonStr, err := json.Marshal(desired)
	if err != nil {
		return api.CreateServiceAccountResponseBody{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/serviceaccounts", apiURL), bytes.NewReader(jsonStr))
	if err != nil {
		return api.CreateServiceAccountResponseBody{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return api.CreateServiceAccountResponseBody{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// The creation was successful. Continue below to decode the response.
	case http.StatusConflict:
		return api.CreateServiceAccountResponseBody{}, fmt.Errorf("service account with the same name already exists, please choose a different name")
	default:
		return api.CreateServiceAccountResponseBody{}, HTTPErrorf(resp, "http %s: please check the Status account fields: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result api.CreateServiceAccountResponseBody
	err = decodeJSON(resp.Body, &result)
	if err != nil {
		return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: while decoding response: %w", err)
	}
	return result, nil
}

func patchServiceAccount(ctx context.Context, cl api.Client, apiURL, apiKey string, id string, patch ServiceAccountPatch) error {
	// If no owner is specified, let's just use the first team we can find.
	if patch.Owner == (openapi_types.UUID{}) {
		teams, err := getTeams(ctx, cl, apiURL, apiKey)
		if err != nil {
			return fmt.Errorf("patchServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return fmt.Errorf("patchServiceAccount: no teams found, please specify an owner")
		}
		ownerUUID := openapi_types.UUID{}
		_ = ownerUUID.UnmarshalText([]byte(teams[0].ID))
		patch.Owner = ownerUUID
		logutil.Debugf("no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].ID)
	}

	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("patchServiceAccount: while marshalling patch: %w", err)
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), bytes.NewReader(patchJSON))
	if err != nil {
		return fmt.Errorf("patchServiceAccount: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("patchServiceAccount: while sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// The patch was successful.
	case http.StatusNotFound:
		return fmt.Errorf("service account: %w", NotFound{NameOrID: id})
	default:
		return HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	return nil
}

// Without this, cmp.Diff would not be able to compare two
// 'ClientAuthenticationInformation' values as they contain the 'union' field,
// which is unexported and prevents comparison. Using this transformer changes a
// ClientAuthenticationInformation into one of the three concrete structs.
var transformClientAuthentication = cmp.Transformer("transformClientAuthentication", func(o api.ClientAuthenticationInformation) any {
	value, err := o.ValueByDiscriminator()
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return value
})

func ANSIDiff(x, y any, opts ...cmp.Option) string {
	escapeCode := func(code int) string {
		return fmt.Sprintf("\x1b[%dm", code)
	}
	diff := cmp.Diff(x, y, opts...)
	if diff == "" {
		return ""
	}
	ss := strings.Split(diff, "\n")
	for i, s := range ss {
		switch {
		case strings.HasPrefix(s, "-"):
			ss[i] = escapeCode(31) + s + escapeCode(0)
		case strings.HasPrefix(s, "+"):
			ss[i] = escapeCode(32) + s + escapeCode(0)
		}
	}
	return strings.Join(ss, "\n")
}

func getIssuingTemplates(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]any, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/certificateissuingtemplates", nil)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		CertificateIssuingTemplates []any `json:"certificateIssuingTemplates"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while reading response body: %w", err)
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result.CertificateIssuingTemplates, nil
}

type CheckResp struct {
	User struct {
		Username        string   `json:"username"`
		ID              string   `json:"id"`
		CompanyID       string   `json:"companyId"`
		Firstname       string   `json:"firstname"`
		Lastname        string   `json:"lastname"`
		EmailAddress    string   `json:"emailAddress"`
		UserType        string   `json:"userType"`
		UserAccountType string   `json:"userAccountType"`
		SsoStatus       string   `json:"ssoStatus"`
		UserStatus      string   `json:"userStatus"`
		SystemRoles     []string `json:"systemRoles"`
		ProductRoles    struct {
		} `json:"productRoles"`
		LocalLoginDisabled           bool      `json:"localLoginDisabled"`
		HasPassword                  bool      `json:"hasPassword"`
		ForceLocalPasswordExpiration bool      `json:"forceLocalPasswordExpiration"`
		FirstLoginDate               time.Time `json:"firstLoginDate"`
		CreationDate                 time.Time `json:"creationDate"`
		OwnedTeams                   []any     `json:"ownedTeams"`
		MemberedTeams                []any     `json:"memberedTeams"`
		Disabled                     bool      `json:"disabled"`
		SignupAttributes             struct {
		} `json:"signupAttributes"`
	} `json:"user"`
	Company struct {
		ID                  string    `json:"id"`
		Name                string    `json:"name"`
		URLPrefix           string    `json:"urlPrefix"` // e.g. "ven-cert-manager-uk"
		CompanyType         string    `json:"companyType"`
		Active              bool      `json:"active"`
		CreationDate        time.Time `json:"creationDate"`
		Domains             []string  `json:"domains"`
		ProductEntitlements []struct {
			Label        string `json:"label"`
			Capabilities []struct {
				Name              string    `json:"name"`
				ProductExpiryDate time.Time `json:"productExpiryDate"`
				IsTrial           bool      `json:"isTrial"`
			} `json:"capabilities"`
			VisibilityConstraintsInformation struct {
			} `json:"visibilityConstraintsInformation"`
		} `json:"productEntitlements"`
	} `json:"company"`
	APIKey struct {
		UserID            string    `json:"userId"`
		Username          string    `json:"username"`
		CompanyID         string    `json:"companyId"`
		APIVersion        string    `json:"apiVersion"`
		APIKeyStatus      string    `json:"apiKeyStatus"`
		CreationDate      time.Time `json:"creationDate"`
		ValidityStartDate time.Time `json:"validityStartDate"`
		ValidityEndDate   time.Time `json:"validityEndDate"`
	} `json:"apiKey"`
}

func checkAPIKey(ctx context.Context, cl api.Client, apiURL, apiKey string) (CheckResp, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/useraccounts", apiURL), nil)
	if err != nil {
		return CheckResp{}, fmt.Errorf("while creating request for GET /v1/useraccounts: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return CheckResp{}, fmt.Errorf("while making request to GET /v1/useraccounts: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	// The request was successful, the token is valid. Continue below.
	case http.StatusUnauthorized:
		return CheckResp{}, HTTPErrorf(resp, "please check your API key")
	case http.StatusForbidden:
		return CheckResp{}, HTTPErrorf(resp, "please check your API key and permissions")
	default:
		return CheckResp{}, HTTPErrorf(resp, "while checking API key, got unexpected http %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CheckResp{}, fmt.Errorf("while reading response body: %w", err)
	}
	var result CheckResp
	if err := json.Unmarshal(body, &result); err != nil {
		return CheckResp{}, fmt.Errorf("while decoding response body: %w, body was: %s", err, string(body))
	}

	return result, nil
}

type HTTPError struct {
	Err error

	Status     string
	StatusCode int
	Body       string
}

// Body must not have been read yet.
func HTTPErrorf(resp *http.Response, format string, values ...any) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("while reading response body: %w", err)
	}

	return HTTPError{
		Err:        fmt.Errorf(format, values...),
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}
}

func IsHTTPBadRequest(err error) bool {
	var httpErr HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode == http.StatusBadRequest
	}
	return false
}

func (e HTTPError) Error() string {
	return e.Err.Error()
}

type Team struct {
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	SystemRoles       []string            `json:"systemRoles"`
	ProductRoles      map[string][]string `json:"productRoles"`
	Role              string              `json:"role"`
	Members           []string            `json:"members"`
	Owners            []string            `json:"owners"`
	UserMatchingRules []any               `json:"userMatchingRules"`
	ModificationDate  time.Time           `json:"modificationDate"`
}

// URL: https://api-dev210.qa.venafi.io/v1/teams?includeSystemGenerated=true
func getTeams(ctx context.Context, cl api.Client, apiURL, apiKey string) ([]Team, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/teams?includeSystemGenerated=true", nil)
	if err != nil {
		return nil, fmt.Errorf("getTeams: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getTeams: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "getTeams: got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		Teams []Team `json:"teams"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("getTeams: while decoding response: %w", err)
	}
	return result.Teams, nil
}

// The temp schema.json file needs to be removed manually when no longer needed.
func saveSchemaToWellKnownPath() (string, error) {
	// Open the file /tmp/vcpctl.schema.json.
	tmpSchemaFile, err := os.Create("/tmp/vcpctl.schema.json")
	if err != nil {
		return "", fmt.Errorf("while creating /tmp/vcpctl.schema.json so that it can be referenced from the YAML manifest and help you get squiggles in your editor: %w", err)
	}
	defer tmpSchemaFile.Close()

	if _, err := tmpSchemaFile.Write(jsonSchema); err != nil {
		return "", fmt.Errorf("while writing to /tmp/vcpctl.schema.json: %w", err)
	}
	return tmpSchemaFile.Name(), nil
}

// For anyone who uses the Red Hat YAML LSP server.
func appendSchemaComment(b []byte, schemaAbsPath string) []byte {
	return appendLines(b,
		"# yaml-language-server: $schema=file://"+schemaAbsPath,
	)
}

func appendLines(b []byte, line ...string) []byte {
	if len(line) == 0 {
		return b
	}
	for _, l := range line {
		b = append(b, []byte("\n"+l+"\n")...)
	}
	return b
}

func coloredYAMLPrint(yamlBytes string) {
	// If not a TTY, let's not color the output.
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Print(yamlBytes)
		return
	}

	const escape = "\x1b"
	format := func(attr color.Attribute) string {
		return fmt.Sprintf("%s[%dm", escape, attr)
	}

	tokens := lexer.Tokenize(yamlBytes)

	var p printer.Printer
	p.LineNumber = false
	p.LineNumberFormat = func(num int) string {
		fn := color.New(color.Bold, color.FgHiWhite).SprintFunc()
		return fn(fmt.Sprintf("%2d | ", num))
	}
	p.Bool = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.Number = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiMagenta),
			Suffix: format(color.Reset),
		}
	}
	p.MapKey = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiCyan),
			Suffix: format(color.Reset),
		}
	}
	p.Anchor = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiYellow),
			Suffix: format(color.Reset),
		}
	}
	p.Alias = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiYellow),
			Suffix: format(color.Reset),
		}
	}
	p.String = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiGreen),
			Suffix: format(color.Reset),
		}
	}
	p.Comment = func() *printer.Property {
		return &printer.Property{
			Prefix: format(color.FgHiBlack),
			Suffix: format(color.Reset),
		}
	}
	writer := colorable.NewColorableStdout()
	_, _ = writer.Write([]byte(p.PrintTokens(tokens)))
}

// Returns a list of IDs.
func rmInteractive(in []ServiceAccount) []string {
	type item struct {
		Name, ID string
	}

	var opts []huh.Option[item]
	for _, sa := range in {
		opts = append(opts, huh.NewOption(fmt.Sprintf("client ID: %s, name: %s", sa.Id, sa.Name), item{
			Name: sa.Name,
			ID:   sa.Id.String(),
		}).Selected(false))
	}

	var selected []item
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[item]().Options(opts...).Value(&selected),
		).Title("Select Service Accounts to remove"),
	)

	if err := form.Run(); err != nil {
		logutil.Errorf("rmInteractive: while running form: %s", err)
		return nil
	}

	var ids []string
	for _, sel := range selected {
		ids = append(ids, sel.ID)
	}
	return ids
}

func looksLikeAnID(s string) bool {
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}

// I don't like Lipgloss's tables because they make it hard to select text in
// the table without also selecting other elements. So I've implemented a
// simple table printer that uses ANSI escape codes to color the output.
//
// All columns are tab-separated, and the headers are printed in bold cyan.
func printTable(headers []string, rows [][]string) {
	// Color the headers in bold cyan, and make them ALL CAPS.
	for i := range headers {
		headers[i] = strings.ToUpper(headers[i])
		headers[i] = boldCyan(headers[i])
	}

	maxWidths := make([]int, len(headers))
	for i, header := range headers {
		maxWidths[i] = len(withoutANSI(header))
	}
	for _, row := range rows {
		for i, col := range row {
			len := len(withoutANSI(col))
			if len > maxWidths[i] {
				maxWidths[i] = len
			}
		}
	}

	for i, header := range headers {
		fmt.Printf("%-*s\t", maxWidths[i]+countANSIChars(header), header)
	}
	fmt.Println()

	for _, row := range rows {
		for i, col := range row {
			fmt.Printf("%-*s\t", maxWidths[i]+countANSIChars(col), col)
		}
		fmt.Println()
	}
}

// Returns an ANSI color escape code that is unique to the given text.
func uniqueColor(text string) string {
	// Don't color if the terminal is not a TTY.
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}

	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", hash(text)%256, text)
}

func hash(s string) int {
	// A simple hash function that returns a number between 0 and 255. This is
	// not cryptographically secure, but it's good enough for our purposes of
	// generating unique colors.
	var h int
	for _, c := range s {
		h = (h*31 + int(c)) % 256
	}
	return h
}

func redBold(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[1;31m%s\x1b[0m", text)
}

func lightGray(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[90m%s\x1b[0m", text)
}

func boldCyan(text string) string {
	if !isatty.IsTerminal(os.Stdout.Fd()) {
		return text
	}
	return fmt.Sprintf("\x1b[1;34m%s\x1b[0m", text)
}

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// Remove ANSI escape codes from the text. Useful for calculating how many chars
// a string has for alignment purposes.
func withoutANSI(s string) string {
	return ansiRegexp.ReplaceAllString(s, "")
}

func countANSIChars(s string) int {
	return len(s) - len(withoutANSI(s))
}

func ptrString(s string) *string {
	return &s
}

func ptrInt(v int) *int {
	return &v
}
