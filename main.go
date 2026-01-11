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
				return fmt.Errorf("sa ls: invalid output format: %s", outputFormat)
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

			updatedSA := existingSA
			updatedSA.PublicKey = ecPub
			p := fullToPatchServiceAccount(updatedSA)
			err = patchServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String(), p)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while patching service account: %w", err)
			}

			if logutil.EnableDebug {
				d := ANSIDiff(fullToPatchServiceAccount(existingSA), fullToPatchServiceAccount(updatedSA))
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
				// Doesn't exist yet, we will be creating it below.
			case err == nil:
				// Exists, we will be updating it.
			default:
				return fmt.Errorf("sa put keypair: while checking if service account exists: %w", err)
			}

			if existingSA.Id.String() == "" {
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
			} else {
				updatedSA := existingSA
				p := fullToPatchServiceAccount(updatedSA)
				err = patchServiceAccount(context.Background(), *apiClient, conf.APIURL, conf.APIKey, existingSA.Id.String(), p)
				if err != nil {
					return fmt.Errorf("sa put keypair: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					d := ANSIDiff(fullToPatchServiceAccount(existingSA), fullToPatchServiceAccount(updatedSA))
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}

				fmt.Println(existingSA.Id.String())
				return nil
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
				// Note: ServiceAccountIds is []uuid.UUID, we can't assign []string to it
				// The display will use saNames for the table output below
			}

			var rows [][]string
			for _, m := range confs {
				rows = append(rows, []string{
					m.Name,
					strings.Join(func() []string {
						result := make([]string, len(m.ServiceAccountIds))
						for i, id := range m.ServiceAccountIds {
							result[i] = id.String()
						}
						return result
					}(), ", "),
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
		return SubCa{}, fmt.Errorf("getSubCaByID: SubCA provider '%s' not found", id)
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
		return fmt.Errorf("removeSubCaProvider: SubCA provider '%s' not found", nameOrID)
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
	config, err := getConfig(ctx, cl, apiURL, apiKey, confName)
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
		return fmt.Errorf("service account '%s' not found (not a valid name or client ID)", saName)
	}

	// Is this SA already in the configuration?
	if slices.Contains(config.ServiceAccountIds, sa.Id) {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.Id.String(), config.Name)
		return nil
	}

	// Add the service account to the configuration.
	config.ServiceAccountIds = append(config.ServiceAccountIds, sa.Id)
	patch := fullToPatchConfig(config)
	err = patchConfig(ctx, cl, apiURL, apiKey, config.Id, patch)
	if err != nil {
		return fmt.Errorf("while patching Workload Identity Manager configuration: %w", err)
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
	err = applyManifests(*apiClient, conf.APIURL, conf.APIKey, manifests, dryRun)
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

			yamlData, err := renderManifests(config)
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
func createConfig(ctx context.Context, cl api.Client, apiURL, apiKey string, config ConfigPatch) (string, error) {
	body, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("createConfig: while marshaling configuration: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL+"/v1/distributedissuers/configurations", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("createConfig: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("createConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", HTTPErrorf(resp, "createConfig: got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		ID string `json:"id"`
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("createConfig: while reading response body: %w", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("createConfig: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result.ID, nil
}

func createFireflyPolicy(ctx context.Context, cl api.Client, apiURL, apiKey string, policy api.PolicyCreateRequest) (string, error) {
	body, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while marshaling policy: %w", err)
	}
	req, err := http.NewRequest("POST", apiURL+"/v1/distributedissuers/policies", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", HTTPErrorf(resp, "createFireflyPolicy: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		ID string `json:"id"`
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while reading response body: %w", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.ID, nil
}

func createSubCaProvider(ctx context.Context, cl api.Client, apiURL, apiKey string, provider SubCaProviderCreateRequest) (string, error) {
	resp, err := cl.SubcaprovidersCreate(ctx, provider)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", HTTPErrorf(resp, "createSubCaProvider: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		ID string `json:"id"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while reading response body: %w", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.ID, nil
}

func patchSubCaProvider(ctx context.Context, cl api.Client, apiURL, apiKey string, id string, patch SubCaProviderUpdateRequest) error {
	resp, err := cl.SubcaprovidersUpdate(ctx, id, patch)
	if err != nil {
		return fmt.Errorf("patchSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// The patch was successful.
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("WIMSubCAProvider: %w", NotFound{NameOrID: id})
	default:
		return HTTPErrorf(resp, "patchSubCaProvider: http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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
		return fmt.Errorf("configuration '%s' not found. Please create it first using 'vcpctl apply config.yaml'", name)
	case err != nil:
		return fmt.Errorf("while getting configuration ID: %w", err)
	}

	populateServiceAccountsInConfig(&config, knownSvcaccts)
	populatePoliciesInConfig(&config, knownPolicies)
	hideMisleadingFields(&config)

	yamlData, err := renderManifests(config)
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
	err = applyManifests(*apiClient, apiURL, apiKey, modified, false)
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
var ErrPINRequired = fmt.Errorf("subCaProvider.pkcs11.pin is required when patching the subCA provider")

// applyManifests walks through the provided manifests in order and applies each
// resource to CyberArk Certificate Manager, SaaS.
func applyManifests(cl api.Client, apiURL, apiKey string, manifests []manifest.Manifest, dryRun bool) error {
	// Sort manifests by dependency order: ServiceAccount → WIMIssuerPolicy → WIMSubCAProvider → WIMConfiguration
	sortedManifests := sortManifestsByDependency(manifests)

	// Pre-flight validation
	if err := validateManifests(sortedManifests); err != nil {
		return fmt.Errorf("pre-flight validation failed: %w", err)
	}

	// Validate references
	if err := validateReferences(cl, apiURL, apiKey, sortedManifests); err != nil {
		return fmt.Errorf("reference validation failed: %w", err)
	}

	if dryRun {
		return applyManifestsDryRun(sortedManifests)
	}

	applyCtx := newManifestApplyContext(context.Background(), cl, apiURL, apiKey)

	var successCount, failureCount int
	var errors []error

	for i, item := range sortedManifests {
		var err error
		switch {
		case item.ServiceAccount != nil:
			err = applyCtx.applyServiceAccount(i, *item.ServiceAccount)
		case item.Policy != nil:
			err = applyCtx.applyPolicy(i, *item.Policy)
		case item.SubCa != nil:
			err = applyCtx.applySubCa(i, *item.SubCa)
		case item.WIMConfiguration != nil:
			err = applyCtx.applyConfig(i, *item.WIMConfiguration)
		default:
			err = fmt.Errorf("manifest #%d: empty or unknown manifest", i+1)
		}

		if err != nil {
			failureCount++
			errors = append(errors, err)
			// Fail-fast: return on first error
			return fmt.Errorf("manifest #%d: %w", i+1, err)
		} else {
			successCount++
		}
	}

	// Print summary
	printApplySummary(successCount, failureCount, len(sortedManifests))

	return nil
}

type manifestApplyContext struct {
	client          api.Client
	apiURL          string
	apiKey          string
	serviceAccounts map[string]ServiceAccount
	policies        map[string]Policy
	subCaProviders  map[string]SubCa
}

func newManifestApplyContext(ctx context.Context, cl api.Client, apiURL, apiKey string) *manifestApplyContext {
	return &manifestApplyContext{
		client:          cl,
		apiURL:          apiURL,
		apiKey:          apiKey,
		serviceAccounts: make(map[string]ServiceAccount),
		policies:        make(map[string]Policy),
		subCaProviders:  make(map[string]SubCa),
	}
}

func (ctx *manifestApplyContext) applyServiceAccount(idx int, in manifest.ServiceAccount) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (ServiceAccount): name must be set", idx+1)
	}

	sa := manifestToAPIServiceAccount(in)
	existing, err := getServiceAccount(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, sa.Name)
	switch {
	case errors.As(err, &NotFound{}):
		resp, err := createServiceAccount(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, sa)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while creating: %w", idx+1, sa.Name, err)
		}
		logutil.Infof("Creating service account '%s' with ID '%s'.", sa.Name, resp.Id.String())
	case err != nil:
		return fmt.Errorf("manifest #%d (ServiceAccount %q): while retrieving existing service account: %w", idx+1, sa.Name, err)
	default:
		if err := patchServiceAccount(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, existing.Id.String(), fullToPatchServiceAccount(sa)); err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while patching: %w", idx+1, sa.Name, err)
		}

		logutil.Infof("Updating service account '%s' (ID '%s').", sa.Name, existing.Id.String())
	}

	fresh, err := ctx.refreshServiceAccount(sa.Name)
	if err != nil {
		return fmt.Errorf("manifest #%d (ServiceAccount %q): while refreshing state: %w", idx+1, sa.Name, err)
	}
	if logutil.EnableDebug {
		d := ANSIDiff(fullToPatchServiceAccount(existing), fullToPatchServiceAccount(fresh))
		logutil.Debugf("Service Account '%s':\n%s", sa.Name, d)
	}
	ctx.serviceAccounts[sa.Name] = fresh
	return nil
}

func (ctx *manifestApplyContext) applyPolicy(idx int, in manifest.Policy) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy): name must be set", idx+1)
	}

	policyCreateReq := manifestToAPIPolicy(in)
	existing, err := getPolicy(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, policyCreateReq.Name)
	switch {
	case errors.As(err, &NotFound{}):
		id, err := createFireflyPolicy(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, policyCreateReq)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while creating: %w", idx+1, policyCreateReq.Name, err)
		}
		logutil.Infof("Creating policy '%s' with ID '%s'.", policyCreateReq.Name, id)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while retrieving existing policy: %w", idx+1, policyCreateReq.Name, err)
	default:
		if err := patchPolicy(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, existing.Id.String(), fullToPatchPolicy(existing)); err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while patching: %w", idx+1, policyCreateReq.Name, err)
		}
		logutil.Infof("Updating policy '%s' (ID '%s').", policyCreateReq.Name, existing.Id.String())
	}

	fresh, err := ctx.refreshPolicy(policyCreateReq.Name)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while refreshing state: %w", idx+1, policyCreateReq.Name, err)
	}
	ctx.policies[policyCreateReq.Name] = fresh
	return nil
}

func (ctx *manifestApplyContext) applySubCa(idx int, in manifest.SubCa) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider): name must be set", idx+1)
	}

	subca := manifestToAPISubCa(in)
	existing, err := getSubCa(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, subca.Name)
	switch {
	case errors.As(err, &NotFound{}):
		// Convert SubCa (SubCaProviderInformation) to SubCaProviderCreateRequest
		createReq := SubCaProviderCreateRequest{
			Name:              subca.Name,
			CaType:            api.SubCaProviderCreateRequestCaType(subca.CaType),
			CaAccountId:       subca.CaAccountId,
			CaProductOptionId: subca.CaProductOptionId,
			ValidityPeriod:    subca.ValidityPeriod,
			CommonName:        subca.CommonName,
			Organization:      subca.Organization,
			Country:           subca.Country,
			Locality:          subca.Locality,
			KeyAlgorithm:      api.SubCaProviderCreateRequestKeyAlgorithm(subca.KeyAlgorithm),
			Pkcs11:            subca.Pkcs11,
		}
		id, err := createSubCaProvider(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, createReq)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while creating: %w", idx+1, subca.Name, err)
		}
		logutil.Infof("Creating WIMSubCAProvider '%s' with ID '%s'.", subca.Name, id)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while retrieving existing SubCA provider: %w", idx+1, subca.Name, err)
	default:
		patch := fullToPatchSubCAProvider(subca)
		if err := patchSubCaProvider(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, existing.Id.String(), patch); err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while patching: %w", idx+1, subca.Name, err)
		}
		logutil.Infof("Updating WIMSubCAProvider '%s' (ID '%s').", subca.Name, existing.Id.String())
	}

	fresh, err := ctx.refreshSubCa(subca.Name)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while refreshing state: %w", idx+1, subca.Name, err)
	}
	ctx.subCaProviders[subca.Name] = fresh
	return nil
}

func (ctx *manifestApplyContext) applyConfig(idx int, in manifest.WIMConfiguration) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMConfiguration): name must be set", idx+1)
	}

	var serviceAccountIDs []openapi_types.UUID
	var policies []api.PolicyInformation
	var policyIDs []openapi_types.UUID

	for _, saName := range in.ServiceAccountNames {
		sa, err := ctx.resolveServiceAccount(saName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving service account %q: %w", idx+1, in.Name, saName, err)
		}
		serviceAccountIDs = append(serviceAccountIDs, sa.Id)
	}

	for _, policyName := range in.PolicyNames {
		policy, err := ctx.resolvePolicy(policyName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving policy %q: %w", idx+1, in.Name, policyName, err)
		}
		policyInfo := api.PolicyInformation{
			Name: policy.Name,
			Id:   policy.Id,
		}
		policyIDs = append(policyIDs, policy.Id)
		policies = append(policies, policyInfo)
	}

	var subCaProvider SubCa
	if in.SubCaProviderName != "" {
		subca, err := ctx.resolveSubCa(in.SubCaProviderName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving subCA provider %q: %w", idx+1, in.Name, in.SubCaProviderName, err)
		}
		subCaProvider = SubCa{
			Name: subca.Name,
			Id:   subca.Id,
		}
	}

	// Build ExtendedConfigurationInformation for comparison and patching
	cfg := api.ExtendedConfigurationInformation{
		Name:              in.Name,
		Policies:          policies,
		PolicyIds:         policyIDs,
		ServiceAccountIds: serviceAccountIDs,
		SubCaProvider:     subCaProvider,
		CloudProviders:    in.CloudProviders,
		AdvancedSettings:  manifestToAPIAdvancedSettings(in.AdvancedSettings),
	}

	if in.MinTLSVersion != "" {
		minTLS := api.ExtendedConfigurationInformationMinTlsVersion(in.MinTLSVersion)
		cfg.MinTlsVersion = minTLS
	}

	existing, err := getConfig(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, in.Name)
	switch {
	case errors.As(err, &NotFound{}):
		_, err := createConfig(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, fullToPatchConfig(cfg))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while creating: %w", idx+1, in.Name, err)
		}
		logutil.Infof("Creating WIM configuration '%s'.", in.Name)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMConfiguration %q): while retrieving existing configuration: %w", idx+1, in.Name, err)
	default:
		if err := patchConfig(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, existing.Id, fullToPatchConfig(cfg)); err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while patching: %w", idx+1, in.Name, err)
		}
		logutil.Infof("Updating WIM configuration '%s' (ID '%s').", in.Name, existing.Id.String())
	}

	return nil
}

func (ctx *manifestApplyContext) resolveServiceAccount(name string) (ServiceAccount, error) {
	if sa, ok := ctx.serviceAccounts[name]; ok {
		return sa, nil
	}
	return ctx.refreshServiceAccount(name)
}

func (ctx *manifestApplyContext) refreshServiceAccount(name string) (ServiceAccount, error) {
	sa, err := getServiceAccount(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, name)
	if err != nil {
		return ServiceAccount{}, err
	}
	ctx.serviceAccounts[name] = sa
	return sa, nil
}

func (ctx *manifestApplyContext) resolvePolicy(name string) (Policy, error) {
	if policy, ok := ctx.policies[name]; ok {
		return policy, nil
	}
	return ctx.refreshPolicy(name)
}

func (ctx *manifestApplyContext) refreshPolicy(name string) (Policy, error) {
	policy, err := getPolicy(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, name)
	if err != nil {
		return Policy{}, err
	}
	ctx.policies[name] = policy
	return policy, nil
}

func (ctx *manifestApplyContext) resolveSubCa(name string) (SubCa, error) {
	if subca, ok := ctx.subCaProviders[name]; ok {
		return subca, nil
	}
	return ctx.refreshSubCa(name)
}

func (ctx *manifestApplyContext) refreshSubCa(name string) (SubCa, error) {
	subca, err := getSubCa(context.Background(), ctx.client, ctx.apiURL, ctx.apiKey, name)
	if err != nil {
		return SubCa{}, err
	}
	ctx.subCaProviders[name] = subca
	return subca, nil
}

// sortManifestsByDependency sorts manifests by kind priority:
// ServiceAccount → WIMIssuerPolicy → WIMSubCAProvider → WIMConfiguration
func sortManifestsByDependency(manifests []manifest.Manifest) []manifest.Manifest {
	kindPriority := map[string]int{
		kindServiceAccount:   1,
		kindIssuerPolicy:     2,
		kindWIMSubCaProvider: 3,
		kindConfiguration:    4,
	}

	sorted := make([]manifest.Manifest, len(manifests))
	copy(sorted, manifests)

	slices.SortFunc(sorted, func(a, b manifest.Manifest) int {
		kindA := getManifestKind(a)
		kindB := getManifestKind(b)
		priorityA := kindPriority[kindA]
		priorityB := kindPriority[kindB]
		return priorityA - priorityB
	})

	return sorted
}

func getManifestKind(m manifest.Manifest) string {
	switch {
	case m.ServiceAccount != nil:
		return kindServiceAccount
	case m.Policy != nil:
		return kindIssuerPolicy
	case m.SubCa != nil:
		return kindWIMSubCaProvider
	case m.WIMConfiguration != nil:
		return kindConfiguration
	default:
		return "unknown"
	}
}

// validateManifests performs pre-flight validation: checks that all required names are set
func validateManifests(manifests []manifest.Manifest) error {
	for i, m := range manifests {
		switch {
		case m.ServiceAccount != nil:
			if m.ServiceAccount.Name == "" {
				return fmt.Errorf("manifest #%d (ServiceAccount): name must be set", i+1)
			}
		case m.Policy != nil:
			if m.Policy.Name == "" {
				return fmt.Errorf("manifest #%d (WIMIssuerPolicy): name must be set", i+1)
			}
		case m.SubCa != nil:
			if m.SubCa.Name == "" {
				return fmt.Errorf("manifest #%d (WIMSubCAProvider): name must be set", i+1)
			}
		case m.WIMConfiguration != nil:
			if m.WIMConfiguration.Name == "" {
				return fmt.Errorf("manifest #%d (WIMConfiguration): name must be set", i+1)
			}
		default:
			return fmt.Errorf("manifest #%d: empty or unknown manifest", i+1)
		}
	}
	return nil
}

// validateReferences checks that all referenced resources exist in manifests or API
func validateReferences(cl api.Client, apiURL, apiKey string, manifests []manifest.Manifest) error {
	// Build sets of names defined in manifests
	serviceAccountNames := make(map[string]bool)
	policyNames := make(map[string]bool)
	subCaNames := make(map[string]bool)

	for _, m := range manifests {
		if m.ServiceAccount != nil && m.ServiceAccount.Name != "" {
			serviceAccountNames[m.ServiceAccount.Name] = true
		}
		if m.Policy != nil && m.Policy.Name != "" {
			policyNames[m.Policy.Name] = true
		}
		if m.SubCa != nil && m.SubCa.Name != "" {
			subCaNames[m.SubCa.Name] = true
		}
	}

	// Validate references in WIMConfiguration manifests
	for i, m := range manifests {
		if m.WIMConfiguration == nil {
			continue
		}

		cfg := m.WIMConfiguration

		// Validate service account references
		for _, saName := range cfg.ServiceAccountNames {
			if !serviceAccountNames[saName] {
				// Check if it exists in API
				_, err := getServiceAccount(context.Background(), cl, apiURL, apiKey, saName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return fmt.Errorf("manifest #%d (WIMConfiguration %q): service account %q not found in manifests or API", i+1, cfg.Name, saName)
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking service account %q: %w", i+1, cfg.Name, saName, err)
				}
			}
		}

		// Validate policy references
		for _, policyName := range cfg.PolicyNames {
			if !policyNames[policyName] {
				// Check if it exists in API
				_, err := getPolicy(context.Background(), cl, apiURL, apiKey, policyName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return fmt.Errorf("manifest #%d (WIMConfiguration %q): policy %q not found in manifests or API", i+1, cfg.Name, policyName)
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking policy %q: %w", i+1, cfg.Name, policyName, err)
				}
			}
		}

		// Validate subCA provider reference
		if cfg.SubCaProviderName != "" {
			if !subCaNames[cfg.SubCaProviderName] {
				// Check if it exists in API
				_, err := getSubCa(context.Background(), cl, apiURL, apiKey, cfg.SubCaProviderName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return fmt.Errorf("manifest #%d (WIMConfiguration %q): subCA provider %q not found in manifests or API", i+1, cfg.Name, cfg.SubCaProviderName)
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking subCA provider %q: %w", i+1, cfg.Name, cfg.SubCaProviderName, err)
				}
			}
		}
	}

	return nil
}

// applyManifestsDryRun shows what would be created/updated without making API calls
func applyManifestsDryRun(manifests []manifest.Manifest) error {
	logutil.Infof("DRY RUN: Would apply %d manifest(s):", len(manifests))
	for i, m := range manifests {
		switch {
		case m.ServiceAccount != nil:
			logutil.Infof("  #%d: ServiceAccount '%s' (would create or update)", i+1, m.ServiceAccount.Name)
		case m.Policy != nil:
			logutil.Infof("  #%d: WIMIssuerPolicy '%s' (would create or update)", i+1, m.Policy.Name)
		case m.SubCa != nil:
			logutil.Infof("  #%d: WIMSubCAProvider '%s' (would create or update)", i+1, m.SubCa.Name)
		case m.WIMConfiguration != nil:
			logutil.Infof("  #%d: WIMConfiguration '%s' (would create or update)", i+1, m.WIMConfiguration.Name)
		}
	}
	return nil
}

// printApplySummary prints a summary of the apply operation
func printApplySummary(successCount, failureCount, totalCount int) {
	if failureCount == 0 {
		logutil.Infof("Successfully applied %d resource(s).", successCount)
	} else {
		logutil.Errorf("Applied %d of %d resource(s) (%d failed).", successCount, totalCount, failureCount)
	}
}

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
		return APIKeyInvalid
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
func patchPolicy(ctx context.Context, cl api.Client, apiURL, apiKey string, id string, patch PolicyPatch) error {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/distributedissuers/policies/%s", apiURL, id), bytes.NewReader(patchJSON))
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("Workload Identity Manager policy: %w", NotFound{NameOrID: id})
	default:
		return HTTPErrorf(resp, "http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

// https://api.venafi.cloud/v1/distributedissuers/configurations/{id}
func patchConfig(ctx context.Context, cl api.Client, apiURL, apiKey string, id openapi_types.UUID, patch ConfigPatch) error {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("patchConfig: while marshaling patch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", cl.Server, id.String()), bytes.NewReader(patchJSON))
	if err != nil {
		return fmt.Errorf("patchConfig: while creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Client.Do(req)
	if err != nil {
		return fmt.Errorf("patchConfig: while sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// The patch was successful.
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("WIM configuration: %w", NotFound{NameOrID: id.String()})
	default:
		return HTTPErrorf(resp, "patchConfig: http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func equalStringSlices(a, b []string) bool {
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
func createServiceAccount(ctx context.Context, cl api.Client, apiURL, apiKey string, sa ServiceAccount) (api.CreateServiceAccountResponseBody, error) {
	// If no owner is specified, let's just use the first team we can find.
	if sa.Owner == (openapi_types.UUID{}) {
		teams, err := getTeams(ctx, cl, apiURL, apiKey)
		if err != nil {
			return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: no teams found, please specify an owner")
		}
		ownerUUID := openapi_types.UUID{}
		_ = ownerUUID.UnmarshalText([]byte(teams[0].ID))
		sa.Owner = ownerUUID
		logutil.Debugf("no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].ID)
	}

	saJSON, err := json.Marshal(sa)
	if err != nil {
		return api.CreateServiceAccountResponseBody{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/serviceaccounts", apiURL), bytes.NewReader(saJSON))
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
	if err := decodeJSON(resp.Body, &result); err != nil {
		return api.CreateServiceAccountResponseBody{}, fmt.Errorf("createServiceAccount: while decoding response: %w", err)
	}
	return result, nil
}

func fullToPatchServiceAccount(sa ServiceAccount) ServiceAccountPatch {
	return ServiceAccountPatch{
		Applications:       sa.Applications,
		Audience:           sa.Audience,
		CredentialLifetime: sa.CredentialLifetime,
		IssuerURL:          sa.IssuerURL,
		JwksURI:            sa.JwksURI,
		Name:               sa.Name,
		Owner:              sa.Owner,
		Scopes:             sa.Scopes,
		Subject:            sa.Subject,
		PublicKey:          sa.PublicKey,
	}
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
