package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/json"
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
	"github.com/maelvls/vcpctl/logutil"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/njayp/ophis"
	"github.com/spf13/cobra"
)

const (
	userAgent     = "vcpctl/v0.0.1"
	defaultAPIURL = "https://api.venafi.cloud"
)

// Replace the old flag-based main() with cobra execution.
func main() {
	var apiURLFlag, apiKeyFlag string
	rootCmd := &cobra.Command{
		Use:   "vcpctl",
		Short: "A CLI tool for CyberArk Certificate Manager configurations",
		Long: undent.Undent(`
			vcpctl is a CLI tool for managing CyberArk Certificate Manager, SaaS (formerly known as Venafi Control Plane and also known as Venafi Cloud) configurations.
			To configure it, set the APIKEY environment variable to your
			CyberArk Certificate Manager, SaaS API key. You can also set the APIURL environment variable
			to override the default API URL.
		`),
		Example: undent.Undent(`
			vcpctl ls
			vcpctl put -f config.yaml
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
	rootCmd.AddCommand(authCmd(), lsCmd(), editCmd(), attachSaCmd(), putCmd(), rmCmd(), getCmd(), saCmd(), subcaCmd(), policyCmd())

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

type ClientAuthentication struct {
	Type     string                       `json:"type" yaml:"type"`
	URLs     []string                     `json:"urls,omitempty" yaml:"urls,omitempty"`
	Audience string                       `json:"audience,omitempty" yaml:"audience,omitempty"`
	BaseURL  string                       `json:"baseUrl,omitempty" yaml:"baseUrl,omitempty"`
	Clients  []ClientAuthenticationClient `json:"clients,omitempty" yaml:"clients,omitempty"`
}

type ClientAuthenticationClient struct {
	Name             string   `json:"name,omitempty" yaml:"name,omitempty"`
	Issuer           string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	JwksURI          string   `json:"jwksURI,omitempty" yaml:"jwksURI,omitempty"`
	Subjects         []string `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	AllowedPolicyIDs []string `json:"allowedPolicyIds,omitempty" yaml:"allowedPolicyIds,omitempty"`
}

type CustomClaimsAliases struct {
	Configuration    string `json:"configuration"`
	AllowAllPolicies string `json:"allowAllPolicies"`
	AllowedPolicies  string `json:"allowedPolicies"`
}

type ClientAuthorization struct {
	CustomClaimsAliases CustomClaimsAliases `json:"customClaimsAliases"`
}

// From https://developer.venafi.com/tlsprotectcloud/reference/configurations_getbyid
type FireflyConfig struct {
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	Policies             []Policy             `json:"policies"`
	SubCaProvider        SubCa                `json:"subCaProvider"`
	AdvancedSettings     AdvancedSettings     `json:"advancedSettings,omitempty"`

	// These fields are returned by the API but are hidden in the 'put', 'get',
	// and 'edit' commands.
	ID                string   `json:"id,omitempty"`
	CreationDate      string   `json:"creationDate,omitempty"`
	ModificationDate  string   `json:"modificationDate,omitempty"`
	ServiceAccountIDs []string `json:"serviceAccountIds,omitempty"`

	// These fields are only used for the 'put', 'get', and 'edit' commands.
	// They are not returned by the API.
	ServiceAccounts []ServiceAccount `json:"serviceAccounts,omitempty"`
}

// Turn `serviceAccountIds` into `serviceAccounts` in the config.
func populateServiceAccountsInConfig(config *FireflyConfig, sa []ServiceAccount) {
	// If the Service Account already exists in the config, update it.
	for _, saItem := range sa {
		for i, saID := range config.ServiceAccountIDs {
			if saItem.ID == saID {
				config.ServiceAccounts = append(config.ServiceAccounts, saItem)
				config.ServiceAccountIDs[i] = saItem.ID
				break
			}
		}
	}
	config.ServiceAccountIDs = nil
}

type Policy struct {
	ID                string       `json:"id,omitempty"`
	Name              string       `json:"name"`
	ValidityPeriod    string       `json:"validityPeriod"`
	Subject           Subject      `json:"subject"`
	SANs              SANs         `json:"sans"`
	KeyUsages         []string     `json:"keyUsages"`
	ExtendedKeyUsages []string     `json:"extendedKeyUsages"`
	KeyAlgorithm      KeyAlgorithm `json:"keyAlgorithm"`
	CreationDate      string       `json:"creationDate,omitempty"`
	ModificationDate  string       `json:"modificationDate,omitempty"`
}

type KeyAlgorithm struct {
	AllowedValues []string `json:"allowedValues"`
	DefaultValue  string   `json:"defaultValue"`
}

type SANs struct {
	DNSNames                   CommonName `json:"dnsNames" yaml:"dnsNames,flow"`
	IPAddresses                CommonName `json:"ipAddresses" yaml:"ipAddresses,flow"`
	RFC822Names                CommonName `json:"rfc822Names" yaml:"rfc822Names,flow"`
	UniformResourceIdentifiers CommonName `json:"uniformResourceIdentifiers" yaml:"uniformResourceIdentifiers,flow"`
}

type CommonName struct {
	Type           string   `json:"type"`
	AllowedValues  []string `json:"allowedValues"`
	DefaultValues  []string `json:"defaultValues"`
	MinOccurrences int      `json:"minOccurrences"`
	MaxOccurrences int      `json:"maxOccurrences"`
}

type SubCa struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name"`
	CaType             string `json:"caType"`
	CaAccountID        string `json:"caAccountId" yaml:"caAccountId,omitempty"`
	CaProductOptionID  string `json:"caProductOptionId" yaml:"caProductOptionId,omitempty"`
	ValidityPeriod     string `json:"validityPeriod"`
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	Country            string `json:"country"`
	Locality           string `json:"locality"`
	OrganizationalUnit string `json:"organizationalUnit"`
	StateOrProvince    string `json:"stateOrProvince"`
	KeyAlgorithm       string `json:"keyAlgorithm"`
	PKCS11             PKCS11 `json:"pkcs11"`
}

type PKCS11 struct {
	AllowedClientLibraries []string `json:"allowedClientLibraries"`
	PartitionLabel         string   `json:"partitionLabel"`
	PartitionSerialNumber  string   `json:"partitionSerialNumber"`
	PIN                    string   `json:"pin"`
	SigningEnabled         bool     `json:"signingEnabled"`
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
		p.PIN == "" &&
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
			List Service Accounts. Service Accounts are used to authenticate
			applications that use Workload Identity Manager configurations.

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
			svcaccts, err := getServiceAccounts(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("sa ls: while listing service accounts: %w", err)
			}

			switch outputFormat {
			case "json":
				b, err := json.MarshalIndent(svcaccts, "", "  ")
				if err != nil {
					return fmt.Errorf("sa ls: while marshaling service accounts to JSON: %w", err)
				}
				fmt.Println(string(b))
				return nil
			case "table":
				var rows [][]string
				for _, sa := range svcaccts {
					rows = append(rows, []string{
						sa.ID,
						uniqueColor(sa.AuthenticationType),
						sa.Name,
					})
				}
				printTable([]string{"Client ID", "Auth Type", "Service Account Name"}, rows)
				return nil
			case "id":
				for _, sa := range svcaccts {
					fmt.Println(sa.ID)
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

			// Does it already exist?
			existingSA, err := getServiceAccount(cl, conf.APIURL, conf.APIKey, saName)
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
			err = patchServiceAccount(cl, conf.APIURL, conf.APIKey, updatedSA.ID, p)
			if err != nil {
				return fmt.Errorf("sa gen keypair: while patching service account: %w", err)
			}

			if logutil.EnableDebug {
				d := ANSIDiff(fullToPatchServiceAccount(existingSA), fullToPatchServiceAccount(updatedSA))
				logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
			}
			logutil.Debugf("Client ID: %s", existingSA.ID)

			switch outputFormat {
			case "pem":
				fmt.Println(ecKey)
			case "json":
				bytes, err := json.MarshalIndent(struct {
					ClientID   string `json:"client_id"`
					PrivateKey string `json:"private_key"`
				}{ClientID: existingSA.ID, PrivateKey: ecKey}, "", "  ")
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
			existingSA, err := getServiceAccount(cl, conf.APIURL, conf.APIKey, saName)
			switch {
			case errors.As(err, &NotFound{}):
				// Doesn't exist yet, we will be creating it below.
			case err == nil:
				// Exists, we will be updating it.
			default:
				return fmt.Errorf("sa put keypair: while checking if service account exists: %w", err)
			}

			if existingSA.ID == "" {
				resp, err := createServiceAccount(cl, conf.APIURL, conf.APIKey, ServiceAccount{
					Name:               saName,
					CredentialLifetime: 365, // days
					Scopes:             scopes,
				})
				if err != nil {
					return fmt.Errorf("sa put keypair: while creating service account: %w", err)
				}
				logutil.Debugf("Service Account '%s' created.\nScopes: %s", saName, strings.Join(scopes, ", "))

				fmt.Println(resp.ID)
				return nil
			} else {
				updatedSA := existingSA
				p := fullToPatchServiceAccount(updatedSA)
				err = patchServiceAccount(cl, conf.APIURL, conf.APIKey, updatedSA.ID, p)
				if err != nil {
					return fmt.Errorf("sa put keypair: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					d := ANSIDiff(fullToPatchServiceAccount(existingSA), fullToPatchServiceAccount(updatedSA))
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}

				fmt.Println(updatedSA.ID)
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

			sa, err := getServiceAccount(cl, conf.APIURL, conf.APIKey, saName)
			if err != nil {
				if errors.As(err, &NotFound{}) {
					return fmt.Errorf("sa get: service account '%s' not found", saName)
				}
				return fmt.Errorf("sa get: while getting service account by name: %w", err)
			}

			if sa.ID == "" {
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
				fmt.Println(sa.ID)
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
				svcaccts, err := getServiceAccounts(cl, conf.APIURL, conf.APIKey)
				if err != nil {
					return fmt.Errorf("sa rm -i: while listing service accounts: %w", err)
				}

				// Use a simple prompt to select the service account to remove.
				selected := rmInteractive(svcaccts)
				for _, saID := range selected {
					err = removeServiceAccount(cl, conf.APIURL, conf.APIKey, saID)
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

			err = removeServiceAccount(cl, conf.APIURL, conf.APIKey, saName)
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
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List Workload Identity Manager configurations in CyberArk Certificate Manager, SaaS",
		Long: undent.Undent(`
			List Workload Identity Manager configurations in CyberArk Certificate Manager, SaaS.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl := http.Client{Transport: Transport}
			// Note: The following functions (GetTokenUsingFileConf and listObjects)
			// should be implemented according to your needs.
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("ls: %w", err)
			}

			confs, err := listConfigs(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("ls: while listing configurations: %w", err)
			}

			// Find service accounts so that we can show the client IDs instead of the
			// IDs.
			knownSvcaccts, err := getServiceAccounts(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("ls: fetching service accounts: %w", err)
			}

			// Replace the service account ID with its name and client ID.
			for i, m := range confs {
				var saNames []string
				for _, saID := range m.ServiceAccountIDs {
					found := false
					for _, sa := range knownSvcaccts {
						if sa.ID == saID {
							saNames = append(saNames, sa.Name+" ("+lightGray(sa.ID)+")")
							found = true
							break
						}
					}
					if !found {
						saNames = append(saNames, saID+redBold(" (deleted)"))
					}
				}
				confs[i].ServiceAccountIDs = saNames
			}

			var rows [][]string
			for _, m := range confs {
				rows = append(rows, []string{
					m.Name,
					strings.Join(m.ServiceAccountIDs, ", "),
				})
			}

			printTable([]string{"Workload Identity Manager Configuration", "Attached Service Accounts"}, rows)
			return nil
		},
	}
	return cmd
}

func subcaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subca",
		Short: "Manage SubCA Providers",
		Long: undent.Undent(`
			Manage SubCA Providers. SubCA Providers are used to issue certificates
			from a SubCA. You can list, create, delete, and set a SubCA Provider
			for a Workload Identity Manager configuration.

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
			providers, err := getSubCas(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("subca ls: while listing subCA providers: %w", err)
			}

			var rows [][]string
			for _, provider := range providers {
				rows = append(rows, []string{
					provider.ID,
					uniqueColor(provider.CaType),
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
			Remove a SubCA Provider. This will delete the SubCA Provider from
			CyberArk Certificate Manager, SaaS. You cannot remove a SubCA Provider that is
			attached to a Workload Identity Manager configuration.
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

			err = removeSubCaProvider(cl, conf.APIURL, conf.APIKey, providerNameOrID)
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
			Manage Policies. Policies are used to define the rules for issuing
			certificates. You can list, create, delete, and set a Policy for a
			Workload Identity Manager configuration.
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
			policies, err := getPolicies(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("policy ls: while listing policies: %w", err)
			}
			var rows [][]string
			for _, policy := range policies {
				rows = append(rows, []string{
					policy.ID,
					policy.Name,
					policy.ValidityPeriod,
					strings.Join(policy.Subject.CommonName.DefaultValues, ", "),
					strings.Join(policy.SANs.DNSNames.DefaultValues, ", "),
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
			Remove a Policy. This will delete the Policy from CyberArk Certificate Manager, SaaS.
			You cannot remove a Policy that is attached to a Workload Identity Manager configuration.
			You must first remove the Policy from the Workload Identity Manager configuration.
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
			err = removePolicy(cl, conf.APIURL, conf.APIKey, policyNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			logutil.Debugf("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}

func removePolicy(cl http.Client, apiURL, apiKey, policyName string) error {
	// Find the policy by name.
	policy, err := getPolicy(cl, apiURL, apiKey, policyName)
	if err != nil {
		return fmt.Errorf("removePolicy: while getting policy by name %q: %w", policyName, err)
	}

	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/policies/"+policy.ID, nil)
	if err != nil {
		return fmt.Errorf("removePolicy: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("removePolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func getSubCas(cl http.Client, apiURL, apiKey string) ([]SubCa, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return nil, fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

func getSubCaByID(cl http.Client, apiURL, apiKey, id string) (SubCa, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders/"+id, nil)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
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
		return SubCa{}, fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result SubCa
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while reading response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SubCa{}, fmt.Errorf("getSubCaByID: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	if result.ID == "" {
		return SubCa{}, fmt.Errorf("getSubCaByID: SubCA provider '%s' not found", id)
	}
	return result, nil
}

func removeSubCaProvider(cl http.Client, apiURL, apiKey, nameOrID string) error {
	if looksLikeAnID(nameOrID) {
		return removeSubCaProviderByID(cl, apiURL, apiKey, nameOrID)
	}

	subCA, err := getSubCa(cl, apiURL, apiKey, nameOrID)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while getting SubCA provider by name '%s': %w", nameOrID, err)
	}
	if subCA.ID == "" {
		return fmt.Errorf("removeSubCaProvider: SubCA provider '%s' not found", nameOrID)
	}
	return removeSubCaProviderByID(cl, apiURL, apiKey, subCA.ID)
}

func removeSubCaProviderByID(cl http.Client, apiURL, apiKey, id string) error {
	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/subcaproviders/"+id, nil)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func attachSaCmd() *cobra.Command {
	var saName string
	cmd := &cobra.Command{
		Use:   "attach-sa <config-name> --sa <sa-name>",
		Short: "Attach a Service Account to a Workload Identity Manager configuration",
		Long: undent.Undent(`
			Attach the given Service Account to the Workload Identity Manager configuration.
		`),
		Example: undent.Undent(`
			vcpctl attach-sa "config-name" --sa "sa-name"
			vcpctl attach-sa "config-name" --sa "03931ba6-3fc5-11f0-85b8-9ee29ab248f0"
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("attach-sa: expected a single argument (the Workload Identity Manager configuration name), got %s", args)
			}
			confName := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}

			err = attachSAToConf(cl, conf.APIURL, conf.APIKey, confName, saName)
			if err != nil {
				return fmt.Errorf("attach-sa: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&saName, "sa", "s", "", "Service Account name or client ID to attach to the Workload Identity Manager configuration")
	_ = cmd.MarkFlagRequired("sa")
	return cmd
}

func attachSAToConf(cl http.Client, apiURL, apiKey, confName, saName string) error {
	// Get configuration name by ID.
	config, err := getConfig(cl, apiURL, apiKey, confName)
	if err != nil {
		return fmt.Errorf("while fetching the ID of the Workload Identity Manager configuration '%s': %w", confName, err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	var sa *ServiceAccount
	// First, check if saName is actually a client ID (direct match with ID).
	for _, knownSa := range knownSvcaccts {
		if knownSa.ID == saName {
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
	if slices.Contains(config.ServiceAccountIDs, sa.ID) {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.ID, config.Name)
		return nil
	}

	// Add the service account to the configuration.
	config.ServiceAccountIDs = append(config.ServiceAccountIDs, sa.ID)
	patch := fullToPatchConfig(config)
	err = patchConfig(cl, apiURL, apiKey, config.ID, patch)
	if err != nil {
		return fmt.Errorf("while patching Workload Identity Manager configuration: %w", err)
	}

	return nil
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit a Workload Identity Manager configuration",
		Long: undent.Undent(`
			Edit a Workload Identity Manager configuration.
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("edit: expected a single argument (the Workload Identity Manager configuration name), got %s", args)
			}

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			err = editConfig(cl, conf.APIURL, conf.APIKey, args[0])
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			return nil
		},
	}
}

func putCmd() *cobra.Command {
	var filePath string
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Create or update a Workload Identity Manager configuration",
		Long: undent.Undent(`
			Create or update a Workload Identity Manager configuration in CyberArk Certificate Manager, SaaS.
			The name in the config's 'name' field is used to identify the
			configuration.
		`),
		Example: undent.Undent(`
			vcpctl put -f config.yaml
			vcpctl put -f - < config.yaml
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var file *os.File
			switch filePath {
			case "":
				return fmt.Errorf("put: no file specified, use --file or -f to specify a file path")
			case "-":
				filePath = "/dev/stdin"
				file = os.Stdin
			default:
				var err error
				file, err = os.Open(filePath)
				if err != nil {
					return fmt.Errorf("put: opening file '%s': %w", filePath, err)
				}
				defer file.Close()
			}

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("put: %w", err)
			}

			bytes, err := io.ReadAll(file)
			if err != nil {
				return fmt.Errorf("put: while reading Workload Identity Manager configuration from '%s': %w", filePath, err)
			}

			// Get service accounts.
			svcaccts, err := getServiceAccounts(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("put: while getting service accounts: %w", err)
			}

			// Read the Workload Identity Manager configuration.
			var updatedConfig FireflyConfig
			if err := yaml.UnmarshalWithOptions(bytes, &updatedConfig, yaml.Strict()); err != nil {
				return fmt.Errorf("put: while decoding Workload Identity Manager configuration from '%s': %w", filePath, err)
			}
			hideMisleadingFields(&updatedConfig)
			populateServiceAccountsInConfig(&updatedConfig, svcaccts)

			if err := validateFireflyConfig(updatedConfig); err != nil {
				return fmt.Errorf("put: Workload Identity Manager configuration validation failed: %w", err)
			}

			if updatedConfig.Name == "" {
				return fmt.Errorf("put: Workload Identity Manager configuration must have a 'name' field set")
			}

			// Patch the original configuration with the new values.
			err = createOrUpdateConfigAndDeps(cl, conf.APIURL, conf.APIKey, svcaccts, updatedConfig)
			if err != nil {
				return fmt.Errorf("put: while creating or updating the Workload Identity Manager configuration, Sub CA, or Policies: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "Path to the Workload Identity Manager configuration file (YAML). Use '-' to read from stdin.")
	return cmd
}

func rmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <config-name>",
		Short: "Remove a Workload Identity Manager configuration",
		Long: undent.Undent(`
			Remove a Workload Identity Manager configuration. This will delete the configuration
			from CyberArk Certificate Manager, SaaS.
		`),
		Example: undent.Undent(`
			vcpctl rm my-config
			vcpctl rm 03931ba6-3fc5-11f0-85b8-9ee29ab248f0
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected a single argument (the Workload Identity Manager configuration name or ID), got %s", args)
			}
			nameOrID := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			// Get the configuration by name or ID.
			c, err := getConfig(cl, conf.APIURL, conf.APIKey, nameOrID)
			if err != nil {
				if errors.As(err, &NotFound{}) {
					return fmt.Errorf("rm: Workload Identity Manager configuration '%s' not found", nameOrID)
				}
				return fmt.Errorf("rm: while getting Workload Identity Manager configuration by name or ID '%s': %w", nameOrID, err)
			}
			// Remove the configuration.
			err = removeConfig(cl, conf.APIURL, conf.APIKey, c.ID)
			if err != nil {
				return fmt.Errorf("rm: while removing Workload Identity Manager configuration '%s': %w", nameOrID, err)
			}
			logutil.Debugf("Workload Identity Manager configuration '%s' removed successfully.", nameOrID)
			return nil
		},
	}
	return cmd
}

func getPolicy(cl http.Client, apiURL, apiKey, nameOrID string) (Policy, error) {
	if looksLikeAnID(nameOrID) {
		return getPolicyByID(cl, apiURL, apiKey, nameOrID)
	}

	policies, err := getPolicies(cl, apiURL, apiKey)
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
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", cur.Name, cur.ID, cur.CreationDate))
		}
		return Policy{}, fmt.Errorf(undent.Undent(`
			getPolicy: duplicate policies found with name '%s':
			%s
			Please use an ID instead, or try to remove one of the service accounts
			first with:
			    vcpctl sa rm %s
			`), nameOrID, b.String(), found[0].ID)
	}

	return found[0], nil
}

func getPolicyByID(cl http.Client, apiURL, apiKey, id string) (Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies/"+id, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByID: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return Policy{}, fmt.Errorf("getPolicyByID: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

func getSubCa(cl http.Client, apiURL, apiKey, name string) (SubCa, error) {
	if looksLikeAnID(name) {
		return getSubCaByID(cl, apiURL, apiKey, name)
	}

	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCa: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return SubCa{}, fmt.Errorf("getSubCa: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return SubCa{}, fmt.Errorf("getSubCa: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCa `json:"subCaProviders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s)\n", cur.Name, cur.ID))
		}
		return SubCa{}, fmt.Errorf(undent.Undent(`
			getSubCa: duplicate sub CAs found with name '%s':
			%s
			Either use the subCA ID instead of the name, or remove one of the
			subCAs first with:
			    vcpctl subca rm %s
		`), name, b.String(), found[0].ID)
	}

	return found[0], nil
}

func getConfig(cl http.Client, apiURL, apiKey, nameOrID string) (FireflyConfig, error) {
	if looksLikeAnID(nameOrID) {
		return getConfigByID(cl, apiURL, apiKey, nameOrID)
	}

	confs, err := getConfigs(cl, apiURL, apiKey)
	if err != nil {
		return FireflyConfig{}, fmt.Errorf("getConfigByName:urations: %w", err)
	}

	// We need to error out if duplicate names are found.
	var found []FireflyConfig
	for _, cur := range confs {
		if cur.Name == nameOrID || cur.ID == nameOrID {
			found = append(found, cur)
		}
	}
	if len(found) == 0 {
		return FireflyConfig{}, NotFound{NameOrID: nameOrID}
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, f := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", f.Name, f.ID, f.CreationDate))
		}
		return FireflyConfig{}, fmt.Errorf(undent.Undent(`
			getConfigByName: duplicate Workload Identity Manager configurations found with name '%s':
			%s
			Either use the Workload Identity Manager configuration ID instead of the name, or try
			removing the duplicates first with:
			    vcpctl rm %s
		`), nameOrID, b.String(), found[0].ID)
	}

	return found[0], nil
}

func getConfigs(cl http.Client, apiURL, apiKey string) ([]FireflyConfig, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, fmt.Errorf("getConfigs: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
	var result struct {
		Configurations []FireflyConfig `json:"configurations"`
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

func removeConfig(cl http.Client, apiURL, apiKey, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		config, err := getConfig(cl, apiURL, apiKey, nameOrID)
		if err != nil {
			return fmt.Errorf("removeConfig:uration by name %q: %w", nameOrID, err)
		}
		id = config.ID
	}

	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/configurations/"+id, nil)
	if err != nil {
		return fmt.Errorf("removeConfig: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
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
		return fmt.Errorf("removeConfig: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func getPolicies(cl http.Client, apiURL, apiKey string) ([]Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Policies []Policy `json:"policies"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("getPolicies: while decoding response: %w", err)
		}
		return result.Policies, nil
	default:
		return nil, parseJSONErrorOrDumpBody(resp)
	}
}

//go:embed genschema/schema.json
var jsonSchema []byte

func getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Export a Workload Identity Manager configuration",
		Long: undent.Undent(`
			Get a Workload Identity Manager configuration from CyberArk Certificate Manager, SaaS. The configuration
			is written to stdout in YAML format.
		`),
		Example: undent.Undent(`
			vcpctl get <config-name>
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("get: expected a single argument (the Workload Identity Manager configuration name), got %s", args)
			}
			idOrName := args[0]

			cl := http.Client{Transport: Transport}
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("get: %w", err)
			}

			knownSvcaccts, err := getServiceAccounts(cl, conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("get: while fetching service accounts: %w", err)
			}

			config, err := getConfig(cl, conf.APIURL, conf.APIKey, idOrName)
			if err != nil {
				return fmt.Errorf("get: while getting original Workload Identity Manager configuration: %w", err)
			}
			populateServiceAccountsInConfig(&config, knownSvcaccts)
			hideMisleadingFields(&config)

			yamlData, err := yaml.MarshalWithOptions(
				config,
				yaml.WithComment(svcAcctsComments(config, knownSvcaccts)),
				yaml.Indent(4),
			)
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
func hideMisleadingFields(c *FireflyConfig) {
	// Zero out all IDs in the configuration, so that we can use it to create
	// a new configuration without any IDs.
	c.ID = ""
	c.CreationDate = ""
	c.ModificationDate = ""
	c.SubCaProvider.ID = ""
	c.SubCaProvider.CaAccountID = ""
	c.SubCaProvider.CaProductOptionID = ""

	for i := range c.Policies {
		c.Policies[i].ID = ""
		c.Policies[i].CreationDate = ""
		c.Policies[i].ModificationDate = ""
	}

	for i := range c.ServiceAccounts {
		c.ServiceAccounts[i].ID = ""
		c.ServiceAccounts[i].Owner = ""
	}
}

// createConfig creates a new Workload Identity Manager configuration or updates an
// existing one. Also deals with creating the subCA policies.
func createConfig(cl http.Client, apiURL, apiKey string, config FireflyConfigPatch) (string, error) {
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
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("createConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", fmt.Errorf("createConfig: got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

func createFireflyPolicy(cl http.Client, apiURL, apiKey string, policy Policy) (string, error) {
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
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("createFireflyPolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", fmt.Errorf("createFireflyPolicy: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

func createSubCaProvider(cl http.Client, apiURL, apiKey string, provider SubCa) (string, error) {
	body, err := json.Marshal(provider)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while marshaling provider: %w", err)
	}
	req, err := http.NewRequest("POST", apiURL+"/v1/distributedissuers/subcaproviders", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return "", fmt.Errorf("createSubCaProvider: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		ID string `json:"id"`
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while reading response body: %w", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("createSubCaProvider: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.ID, nil
}

type Config struct {
	Name              string
	ServiceAccountIDs []string
}

func listConfigs(cl http.Client, apiURL, apiKey string) ([]Config, error) {
	if apiURL == "" {
		return nil, fmt.Errorf("listConfigs: apiURL is empty")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("listConfigs: apiKey is empty")
	}

	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while reading response: %w", err)
	}

	var result struct {
		Configurations []struct {
			Name              string   `json:"name"`
			ServiceAccountIDs []string `json:"serviceAccountIds"`
		} `json:"configurations"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	var confs []Config
	for _, conf := range result.Configurations {
		confs = append(confs, Config{
			Name:              conf.Name,
			ServiceAccountIDs: conf.ServiceAccountIDs,
		})
	}
	return confs, nil
}

type NotFound struct {
	NameOrID string `json:"id"`
}

func (e NotFound) Error() string {
	return fmt.Sprintf("'%s' not found", e.NameOrID)
}

func getConfigByID(cl http.Client, apiURL, apiKey, id string) (FireflyConfig, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", apiURL, id), nil)
	if err != nil {
		return FireflyConfig{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return FireflyConfig{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return FireflyConfig{}, fmt.Errorf("getConfig: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var fireflyConfig FireflyConfig
	if err := json.NewDecoder(resp.Body).Decode(&fireflyConfig); err != nil {
		return FireflyConfig{}, err
	}

	return fireflyConfig, nil
}

type AdvancedSettings struct {
	EnableIssuanceAuditLog       bool `json:"enableIssuanceAuditLog"`
	IncludeRawCertDataInAuditLog bool `json:"includeRawCertDataInAuditLog"`
	RequireFIPSCompliantBuild    bool `json:"requireFIPSCompliantBuild"`
}

// The PATCH request body only allows for a subset of the fields in the full
// configuration. Here is the subset that can be modified, as per
// https://developer.venafi.com/tlsprotectcloud/reference/configurations_update.
//
//	name: ...
//	clientAuthentication: ...
//	clientAuthorization: ...
//	cloudProviders: ...
//	minTlsVersion: ...
//	serviceAccountIds: ...
//	policyIds: ...
//	subCaProviderId: ...
//	advancedSettings: ...
type FireflyConfigPatch struct {
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	ServiceAccountIDs    []string             `json:"serviceAccountIds"`
	PolicyIDs            []string             `json:"policyIds"`
	SubCaProviderID      string               `json:"subCaProviderId"`
	// The advancedSettings field is not supported yet with the PATCH verb, so
	// it is not included. Please add it as soon as it appears in the API:
	// https://developer.venafi.com/tlsprotectcloud/reference/configurations_update
	AdvancedSettings AdvancedSettings `json:"advancedSettings,omitempty"`
}

func fullToPatchConfig(full FireflyConfig) FireflyConfigPatch {
	policyIDs := make([]string, len(full.Policies))
	for i, p := range full.Policies {
		policyIDs[i] = p.ID
	}

	return FireflyConfigPatch{
		Name:                 full.Name,
		ClientAuthentication: full.ClientAuthentication,
		ClientAuthorization:  full.ClientAuthorization,
		CloudProviders:       full.CloudProviders,
		MinTLSVersion:        full.MinTLSVersion,
		ServiceAccountIDs:    full.ServiceAccountIDs,
		PolicyIDs:            policyIDs,
		SubCaProviderID:      full.SubCaProvider.ID,
		AdvancedSettings:     full.AdvancedSettings,
	}
}

func editConfig(cl http.Client, apiURL, apiKey, name string) error {
	knownSvcaccts, err := getServiceAccounts(cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	config, err := getConfig(cl, apiURL, apiKey, name)
	if err != nil {
		if errors.Is(err, NotFound{}) {
			return fmt.Errorf("configuration '%s' not found. Please create it first using 'vcpctl put config.yaml'", name)
		}
		return fmt.Errorf("while getting configuration ID: %w", err)
	}
	populateServiceAccountsInConfig(&config, knownSvcaccts)
	hideMisleadingFields(&config)

	yamlData, err := yaml.MarshalWithOptions(
		config,
		yaml.WithComment(svcAcctsComments(config, knownSvcaccts)),
	)
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

	var modified FireflyConfig
	if err := yaml.UnmarshalWithOptions(modifiedRaw, &modified, yaml.Strict()); err != nil {
		logutil.Debugf("the configuration you have modified is not valid:\n%s", err)
		notice := "# NOTICE: Errors were found, please edit the configuration.\n" +
			"# NOTICE: You can abort editing by emptying this file.\n" +
			"# NOTICE:\n" +
			"# NOTICE: " + strings.ReplaceAll(err.Error(), "\n", "\n# NOTICE: ") + "\n\n"
		err = os.WriteFile(tmpfile.Name(), append([]byte(notice), modifiedRaw...), 0644)
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		info, _ := os.Stat(tmpfile.Name())
		lastSaved = info.ModTime()
		goto edit
	}

	err = validateFireflyConfig(modified)
	if err != nil {
		logutil.Debugf("the configuration you have modified is not valid:\n%s", err)

		modifiedRaw := removeNoticeFromYAML(string(modifiedRaw))
		notice := "# NOTICE: Errors were found, please edit the configuration.\n" +
			"# NOTICE: You can abort editing by emptying this file.\n" +
			"# NOTICE:\n" +
			"# NOTICE: " + strings.ReplaceAll(err.Error(), "\n", "\n# NOTICE: ") + "\n\n"
		err = os.WriteFile(tmpfile.Name(), append([]byte(notice), modifiedRaw...), 0644)
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		info, _ := os.Stat(tmpfile.Name())
		lastSaved = info.ModTime()
		goto edit
	}

	err = createOrUpdateConfigAndDeps(cl, apiURL, apiKey, knownSvcaccts, modified)
	if errors.Is(err, ErrPINRequired) {
		logutil.Errorf("ERROR: The subCaProvider.pkcs11.pin field is required.")

		// If the PIN is required, we need to ask the user to fill it in.
		modifiedRaw := removeNoticeFromYAML(string(modifiedRaw))
		notice := "# NOTICE: Since you have changed the subCaProvider, you need fill in the subCaProvider.pkcs11.pin\n" +
			"# NOTICE: You can abort by emptying this file and closing it. Please re-edit the configuration to fill in the PKCS11 pin.\n\n"
		err = os.WriteFile(tmpfile.Name(), append([]byte(notice), modifiedRaw...), 0644)
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		goto edit
	}
	if err != nil {
		return fmt.Errorf("while merging and patching Workload Identity Manager configuration: %w", err)
	}

	return nil
}

var re = regexp.MustCompile(`(?m)^# NOTICE:.*\n`)

// Remove the NOTICE lines from the YAML data.
func removeNoticeFromYAML(yamlData string) string {
	return re.ReplaceAllString(yamlData, "")
}

func svcAcctsComments(config FireflyConfig, allSvcAccts []ServiceAccount) map[string][]*yaml.Comment {
	var comments = make(map[string][]*yaml.Comment)

	for i, sa := range config.ServiceAccountIDs {
		found := false
		for _, knownSa := range allSvcAccts {
			if knownSa.ID == sa {
				found = true
				comments[fmt.Sprintf("$.serviceAccountIds[%d]", i)] = []*yaml.Comment{
					yaml.LineComment(" " + knownSa.Name),
				}
				break
			}
		}
		if !found {
			comments[fmt.Sprintf("$.serviceAccountIds[%d]", i)] = []*yaml.Comment{
				yaml.LineComment(" unknown service account"),
			}
		}
	}

	return comments
}

var ErrPINRequired = fmt.Errorf("subCaProvider.pkcs11.pin is required when patching the subCA provider")

// Also patches the nested SubCA provider and Workload Identity Manager policies. Use
// errors.Is(err, errPINRequired) to check if the error is due to the missing
// PIN.
func createOrUpdateConfigAndDeps(cl http.Client, apiURL, apiKey string, existingSvcAccts []ServiceAccount, updatedConfig FireflyConfig) error {
	// Start with creating or updating the Service Accounts.
	for i := range updatedConfig.ServiceAccounts {
		var id string
		existingSa, err := findServiceAccount(updatedConfig.ServiceAccounts[i].Name, existingSvcAccts)
		switch {
		case errors.As(err, &NotFound{}):
			// The service account does not exist. We will be creating below.
		case err != nil:
			return fmt.Errorf("while getting service account '%s': %w", updatedConfig.ServiceAccounts[i].Name, err)
		default:
			// The service account exists, we need to patch it below.
		}
		if existingSa.ID == "" {
			// The service account does not have an ID, we need to create it.
			resp, err := createServiceAccount(cl, apiURL, apiKey, updatedConfig.ServiceAccounts[i])
			if err != nil {
				return fmt.Errorf("while creating service account '%s': %w", updatedConfig.ServiceAccounts[i].Name, err)
			}
			id = resp.ID
			logutil.Debugf("Service account '%s' created with ID '%s'.", updatedConfig.ServiceAccounts[i].Name, resp.ID)
		} else {
			// The service account exists, we may need to patch it.
			id = existingSa.ID

			// Un-hide the owner field.
			updatedConfig.ServiceAccounts[i].Owner = existingSa.Owner
			d := ANSIDiff(fullToPatchServiceAccount(existingSa), fullToPatchServiceAccount(updatedConfig.ServiceAccounts[i]))
			if d != "" {
				err = patchServiceAccount(cl, apiURL, apiKey, id, fullToPatchServiceAccount(updatedConfig.ServiceAccounts[i]))
				if err != nil {
					return fmt.Errorf("while patching service account '%s': %w", updatedConfig.ServiceAccounts[i].Name, err)
				}

				logutil.Debugf("Service account '%s' patched:\n'%s'", updatedConfig.ServiceAccounts[i].Name, d)
			} else {
				logutil.Debugf("Service account '%s' is unchanged, skipping update.", updatedConfig.ServiceAccounts[i].Name)
			}
		}
		updatedConfig.ServiceAccounts[i].ID = id
		updatedConfig.ServiceAccountIDs = append(updatedConfig.ServiceAccountIDs, id)
	}

	knownSvcaccts, err := getServiceAccounts(cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}
	for _, saID := range updatedConfig.ServiceAccountIDs {
		found := false
		for _, knownSa := range knownSvcaccts {
			if knownSa.ID == saID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("service account ID '%s' not found.\nTo list all existing service accounts, run:\n    vcpctl ls", saID)
		}
	}

	templates, err := getIssuingTemplates(cl, apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while getting issuing templates: %w", err)
	}
	// Find the built-in issuing template.
	var builtin CertificateIssuingTemplate
	for _, template := range templates {
		if template.CertificateAuthority == "BUILTIN" {
			builtin = template
			break
		}
	}
	if builtin.ID == "" {
		return fmt.Errorf("built-in issuing template not found, please check your CyberArk Certificate Manager, SaaS configuration")
	}

	// Before dealing with patching the configuration, let's patch the policies
	// and the SubCA provider, if needed.
	for i := range updatedConfig.Policies {
		// Get the original policy to check if it exists.
		existingPolicy, err := getPolicy(cl, apiURL, apiKey, updatedConfig.Policies[i].Name)
		switch {
		case errors.As(err, &NotFound{}):
			// We will create it below.
		case err == nil:
			// Policy exists and might need to be patched. Continue below.
		default:
			return fmt.Errorf("while getting the existing Workload Identity Manager policy '%s': %w", updatedConfig.Policies[i].Name, err)
		}

		if existingPolicy.ID == "" {
			// The policy does not exist, we need to create it.
			id, err := createFireflyPolicy(cl, apiURL, apiKey, updatedConfig.Policies[i])
			if err != nil {
				return fmt.Errorf("while creating Workload Identity Manager policy: %w", err)
			}
			updatedConfig.Policies[i].ID = id
			logutil.Debugf("Policy '%s' created with ID '%s'.", updatedConfig.Policies[i].Name, id)
		} else {
			updatedConfig.Policies[i].ID = existingPolicy.ID

			// If the policy is not equal to the original one, we need to update it.
			d := ANSIDiff(fullToPatchPolicy(existingPolicy), fullToPatchPolicy(updatedConfig.Policies[i]))
			if d == "" {
				logutil.Debugf("Policy '%s' is unchanged, skipping update.", updatedConfig.Policies[i].Name)
				continue
			}

			// If the policy is different, we need to update it.
			logutil.Debugf("Policy '%s' was changed:\n%s\n", updatedConfig.Policies[i].Name, d)

			// Patch the policy.
			err = patchPolicy(cl, apiURL, apiKey, existingPolicy.ID, fullToPatchPolicy(updatedConfig.Policies[i]))
			if err != nil {
				return fmt.Errorf("while patching Workload Identity Manager policy #%d '%s': %w", i, updatedConfig.Policies[i].Name, err)
			}
		}
	}

	// Now, let's take care of the SubCA provider.
	existingSubCa, err := getSubCa(cl, apiURL, apiKey, updatedConfig.SubCaProvider.Name)
	switch {
	case errors.As(err, &NotFound{}):
		// We will create the SubCA provider just below.
	case err != nil:
		return fmt.Errorf("while getting original SubCA provider '%s': %w", updatedConfig.SubCaProvider.Name, err)
	default:
		// SubCA provider exists and might need to be patched. Continue below.
	}

	// Replace the sub CA's issuing template with the built-in one. Fail if
	// caType != BUILTIN.
	if updatedConfig.SubCaProvider.CaType != "BUILTIN" {
		return fmt.Errorf("subCA provider '%s' has caType '%s', but only BUILTIN is supported for now", updatedConfig.SubCaProvider.Name, updatedConfig.SubCaProvider.CaType)
	}
	updatedConfig.SubCaProvider.CaAccountID = builtin.CertificateAuthorityAccountID
	updatedConfig.SubCaProvider.CaProductOptionID = builtin.CertificateAuthorityProductOptionID

	if existingSubCa.ID == "" {
		// The SubCA provider does not exist, we need to create it.
		id, err := createSubCaProvider(cl, apiURL, apiKey, updatedConfig.SubCaProvider)
		if err != nil {
			return fmt.Errorf("while creating SubCA provider: %w", err)
		}
		updatedConfig.SubCaProvider.ID = id
		logutil.Debugf("SubCA provider '%s' created with ID '%s'.", updatedConfig.SubCaProvider.Name, id)
	} else {
		updatedConfig.SubCaProvider.ID = existingSubCa.ID

		// If the SubCA provider is not equal to the original one, we need to update it.
		diff := ANSIDiff(fullToPatchSubCAProvider(existingSubCa), fullToPatchSubCAProvider(updatedConfig.SubCaProvider))
		if diff == "" {
			logutil.Debugf("SubCA provider '%s' is unchanged, skipping update.", updatedConfig.SubCaProvider.Name)
		} else {
			// The `subCaProvider.pkcs11.pin` field is never returned by the API, so
			// we need to check if the user has changed it and patch it separately.
			// If the user still wants to patch the subCAProvider, we need to ask
			// them to re-edit the manifest to fill in the pin.
			//
			// First off, let's check if the user has changed something under the
			// `subCaProvider`.

			if !isZeroPKCS11(updatedConfig.SubCaProvider.PKCS11) && updatedConfig.SubCaProvider.PKCS11.PIN == "" {
				return fmt.Errorf("while patching Workload Identity Manager configuration's subCAProvider: %w", ErrPINRequired)
			}

			// If the SubCA provider is different, we need to update it.
			logutil.Debugf("SubCA provider '%s' was changed:\n%s\n", updatedConfig.SubCaProvider.Name, diff)

			// Patch the SubCA provider.
			err = patchSubCaProvider(cl, apiURL, apiKey, existingSubCa.ID, fullToPatchSubCAProvider(updatedConfig.SubCaProvider))
			if err != nil {
				return fmt.Errorf("while patching Workload Identity Manager SubCA provider '%s': %w", updatedConfig.SubCaProvider.Name, err)
			}
		}
	}

	// If we reach this point, we have successfully dealt with service accounts,
	// the sub CA, and policies. Let's see if the Workload Identity Manager configuration needs to
	// be created or updated.
	existingConfig, err := getConfig(cl, apiURL, apiKey, updatedConfig.Name)
	switch {
	case errors.As(err, &NotFound{}):
		// Continue below since the nested sub CA and policies may not already
		// exist, so the Workload Identity Manager configuration may need to be patched.
	case err != nil:
		return fmt.Errorf("while getting configuration ID: %w", err)
	}
	if existingConfig.ID == "" {
		// The configuration does not exist, we need to create it.
		confID, err := createConfig(cl, apiURL, apiKey, fullToPatchConfig(updatedConfig))
		if err != nil {
			return fmt.Errorf("while creating Workload Identity Manager configuration: %w", err)
		}

		logutil.Debugf("Configuration '%s' created with ID '%s'.", updatedConfig.Name, confID)
	} else {
		// The configuration exists, we need to patch it.
		d := ANSIDiff(fullToPatchConfig(existingConfig), fullToPatchConfig(updatedConfig))
		if d == "" {
			logutil.Debugf("Configuration '%s' is unchanged, skipping update.", updatedConfig.Name)
			return nil
		} else {
			logutil.Debugf("Configuration '%s' was changed:\n%s\n", updatedConfig.Name, d)

			patch := fullToPatchConfig(updatedConfig)
			err = patchConfig(cl, apiURL, apiKey, existingConfig.ID, patch)
			if err != nil {
				return fmt.Errorf("while patching Workload Identity Manager configuration: %w", err)
			}
		}
	}

	return nil
}

func patchConfig(cl http.Client, apiURL, apiKey, id string, patch FireflyConfigPatch) error {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", apiURL, id), bytes.NewReader(patchJSON))
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		return nil
	default:
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

// From: https://developer.venafi.com/tlsprotectcloud/reference/subcaproviders_update
type SubCaProviderPatch struct {
	CaProductOptionID  string `json:"caProductOptionId"`
	CommonName         string `json:"commonName"`
	Country            string `json:"country"`
	KeyAlgorithm       string `json:"keyAlgorithm"`
	Locality           string `json:"locality"`
	Name               string `json:"name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	PKCS11             PKCS11 `json:"pkcs11,omitempty"`
	StateOrProvince    string `json:"stateOrProvince"`
	ValidityPeriod     string `json:"validityPeriod"`
}

func patchSubCaProvider(cl http.Client, apiURL, apiKey, id string, patch SubCaProviderPatch) error {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/distributedissuers/subcaproviders/%s", apiURL, id), bytes.NewReader(patchJSON))
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		return nil
	default:
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
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

func fullToPatchSubCAProvider(full SubCa) SubCaProviderPatch {
	return SubCaProviderPatch{
		CaProductOptionID:  full.CaProductOptionID,
		CommonName:         full.CommonName,
		Country:            full.Country,
		KeyAlgorithm:       full.KeyAlgorithm,
		Locality:           full.Locality,
		Name:               full.Name,
		Organization:       full.Organization,
		OrganizationalUnit: full.OrganizationalUnit,
		PKCS11:             full.PKCS11,
		StateOrProvince:    full.StateOrProvince,
		ValidityPeriod:     full.ValidityPeriod,
	}
}

// From https://developer.venafi.com/tlsprotectcloud/reference/policies_update
type PolicyPatch struct {
	Name              string       `json:"name"`
	KeyAlgorithm      KeyAlgorithm `json:"keyAlgorithm"`
	KeyUsages         []string     `json:"keyUsages"`
	ExtendedKeyUsages []string     `json:"extendedKeyUsages"`
	SANs              SANs         `json:"sans"`
	Subject           Subject      `json:"subject"`
	ValidityPeriod    string       `json:"validityPeriod"` // ISO8601 Period Format, e.g. "P90D"
}

type Subject struct {
	CommonName         CommonName `json:"commonName" yaml:"commonName,flow"`
	Country            CommonName `json:"country" yaml:"country,flow"`
	Locality           CommonName `json:"locality" yaml:"locality,flow"`
	Organization       CommonName `json:"organization" yaml:"organization,flow"`
	OrganizationalUnit CommonName `json:"organizationalUnit" yaml:"organizationalUnit,flow"`
	StateOrProvince    CommonName `json:"stateOrProvince" yaml:"stateOrProvince,flow"`
}

func fullToPatchPolicy(full Policy) PolicyPatch {
	return PolicyPatch{
		Name:              full.Name,
		KeyAlgorithm:      full.KeyAlgorithm,
		KeyUsages:         full.KeyUsages,
		ExtendedKeyUsages: full.ExtendedKeyUsages,
		SANs:              full.SANs,
		Subject:           full.Subject,
		ValidityPeriod:    full.ValidityPeriod,
	}
}

// https://api.venafi.cloud/v1/distributedissuers/policies/{id}
func patchPolicy(cl http.Client, apiURL, apiKey, id string, patch PolicyPatch) error {
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

	resp, err := cl.Do(req)
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
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

type ServiceAccount struct {
	AuthenticationType string   `json:"authenticationType,omitempty"`
	CredentialLifetime int      `json:"credentialLifetime,omitempty"`
	Enabled            bool     `json:"enabled,omitempty"`
	ID                 string   `json:"id,omitempty"`
	Name               string   `json:"name,omitempty"`
	Owner              string   `json:"owner,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	Applications       []string `json:"applications,omitempty"`
	Audience           string   `json:"audience,omitempty"`
	IssuerURL          string   `json:"issuerURL,omitempty"`
	JwksURI            string   `json:"jwksURI,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty"`
}

func (sa ServiceAccount) Equal(other ServiceAccount) bool {
	return sa.ID == other.ID &&
		sa.Name == other.Name &&
		sa.AuthenticationType == other.AuthenticationType &&
		sa.CredentialLifetime == other.CredentialLifetime &&
		sa.Enabled == other.Enabled &&
		sa.Owner == other.Owner &&
		equalStringSlices(sa.Scopes, other.Scopes) &&
		equalStringSlices(sa.Applications, other.Applications) &&
		sa.Audience == other.Audience &&
		sa.IssuerURL == other.IssuerURL &&
		sa.JwksURI == other.JwksURI &&
		sa.Subject == other.Subject &&
		sa.PublicKey == other.PublicKey
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

func getServiceAccounts(cl http.Client, apiURL, apiKey string) ([]ServiceAccount, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/serviceaccounts", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return nil, fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

func removeServiceAccount(cl http.Client, apiURL, apiKey, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		sa, err := getServiceAccount(cl, apiURL, apiKey, nameOrID)
		if err != nil {
			if errors.Is(err, NotFound{}) {
				return fmt.Errorf("service account '%s' not found", nameOrID)
			}
			return fmt.Errorf("while getting service account by name '%s': %w", nameOrID, err)
		}
		id = sa.ID
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
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
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func findServiceAccount(nameOrID string, allSAs []ServiceAccount) (ServiceAccount, error) {
	if looksLikeAnID(nameOrID) {
		for _, sa := range allSAs {
			if sa.ID == nameOrID {
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

func getServiceAccount(cl http.Client, apiURL, apiKey, nameOrID string) (ServiceAccount, error) {
	if looksLikeAnID(nameOrID) {
		return getServiceAccountByID(cl, apiURL, apiKey, nameOrID)
	}

	sas, err := getServiceAccounts(cl, apiURL, apiKey)
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
		_, _ = b.WriteString(fmt.Sprintf("  - %s (%s)\n", sa.Name, sa.ID))
	}
	return ServiceAccount{}, fmt.Errorf(undent.Undent(`
		getServiceAccount: duplicate service account name '%s' found.
		The conflicting service accounts are:
		%s
		Please use a client ID (that's the same as the service account ID), or
		remove the duplicates using:
		    vcpctl sa rm %s
	`), nameOrID, b.String(), found[0].ID)
}

func getServiceAccountByID(cl http.Client, apiURL, apiKey, id string) (ServiceAccount, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), nil)
	if err != nil {
		return ServiceAccount{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return ServiceAccount{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return ServiceAccount{}, fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result ServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ServiceAccount{}, fmt.Errorf("getServiceAccountByID: while decoding response: %w", err)
	}
	return result, nil
}

type SACreateResp struct {
	ID         string `json:"id"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
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
func createServiceAccount(cl http.Client, apiURL, apiKey string, sa ServiceAccount) (SACreateResp, error) {
	// If no owner is specified, let's just use the first team we can find.
	if sa.Owner == "" {
		teams, err := getTeams(cl, apiURL, apiKey)
		if err != nil {
			return SACreateResp{}, fmt.Errorf("createServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return SACreateResp{}, fmt.Errorf("createServiceAccount: no teams found, please specify an owner")
		}
		sa.Owner = teams[0].ID
		logutil.Debugf("no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].ID)
	}

	saJSON, err := json.Marshal(sa)
	if err != nil {
		return SACreateResp{}, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/serviceaccounts", apiURL), bytes.NewReader(saJSON))
	if err != nil {
		return SACreateResp{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return SACreateResp{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// The creation was successful. Continue below to decode the response.
	case http.StatusConflict:
		return SACreateResp{}, fmt.Errorf("service account with the same name already exists, please choose a different name")
	default:
		return SACreateResp{}, fmt.Errorf("http %s: please check the Status account fields: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result SACreateResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return SACreateResp{}, fmt.Errorf("createServiceAccount: while decoding response: %w", err)
	}
	return result, nil
}

type ServiceAccountPatch struct {
	Applications       []string `json:"applications,omitempty"`
	Audience           string   `json:"audience,omitempty"`
	CredentialLifetime int      `json:"credentialLifetime,omitempty"`
	IssuerURL          string   `json:"issuerURL,omitempty"`
	JwksURI            string   `json:"jwksURI,omitempty"`
	Name               string   `json:"name,omitempty"`
	Owner              string   `json:"owner,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty"`
	Enabled            bool     `json:"enabled,omitempty"`
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
		Enabled:            sa.Enabled,
		PublicKey:          sa.PublicKey,
	}
}

func patchServiceAccount(cl http.Client, apiURL, apiKey, id string, patch ServiceAccountPatch) error {
	// If no owner is specified, let's just use the first team we can find.
	if patch.Owner == "" {
		teams, err := getTeams(cl, apiURL, apiKey)
		if err != nil {
			return fmt.Errorf("patchServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return fmt.Errorf("patchServiceAccount: no teams found, please specify an owner")
		}
		patch.Owner = teams[0].ID
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

	resp, err := cl.Do(req)
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
		return fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
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

type CertificateIssuingTemplate struct {
	ID                                  string `json:"id"`
	CompanyID                           string `json:"companyId"`
	CertificateAuthority                string `json:"certificateAuthority"`
	Name                                string `json:"name"`
	CertificateAuthorityAccountID       string `json:"certificateAuthorityAccountId"`
	CertificateAuthorityProductOptionID string `json:"certificateAuthorityProductOptionId"`
	Product                             struct {
		CertificateAuthority string   `json:"certificateAuthority"`
		ProductName          string   `json:"productName"`
		ProductTypes         []string `json:"productTypes"`
		ValidityPeriod       string   `json:"validityPeriod"`
	} `json:"product"`
	Priority                  int       `json:"priority,omitempty"`
	SystemGenerated           bool      `json:"systemGenerated"`
	CreationDate              time.Time `json:"creationDate"`
	ModificationDate          time.Time `json:"modificationDate"`
	Status                    string    `json:"status"`
	Reason                    string    `json:"reason"`
	ReferencingApplicationIds []any     `json:"referencingApplicationIds"`
	SubjectCNRegexes          []string  `json:"subjectCNRegexes"`
	SubjectORegexes           []string  `json:"subjectORegexes"`
	SubjectOURegexes          []string  `json:"subjectOURegexes"`
	SubjectSTRegexes          []string  `json:"subjectSTRegexes"`
	SubjectLRegexes           []string  `json:"subjectLRegexes"`
	SubjectCValues            []string  `json:"subjectCValues"`
	SanRegexes                []string  `json:"sanRegexes"`
	SanDNSNameRegexes         []string  `json:"sanDnsNameRegexes"`
	KeyTypes                  []struct {
		KeyType    string `json:"keyType"`
		KeyLengths []int  `json:"keyLengths"`
	} `json:"keyTypes"`
	KeyReuse                    bool  `json:"keyReuse"`
	ExtendedKeyUsageValues      []any `json:"extendedKeyUsageValues"`
	CsrUploadAllowed            bool  `json:"csrUploadAllowed"`
	KeyGeneratedByVenafiAllowed bool  `json:"keyGeneratedByVenafiAllowed"`
	ResourceConsumerUserIds     []any `json:"resourceConsumerUserIds"`
	ResourceConsumerTeamIds     []any `json:"resourceConsumerTeamIds"`
	EveryoneIsConsumer          bool  `json:"everyoneIsConsumer"`
}

func getIssuingTemplates(cl http.Client, apiURL, apiKey string) ([]CertificateIssuingTemplate, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/certificateissuingtemplates", nil)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, fmt.Errorf("got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		CertificateIssuingTemplates []CertificateIssuingTemplate `json:"certificateIssuingTemplates"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while reading response body: %w", err)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&result)
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

func checkAPIKey(cl http.Client, apiURL, apiKey string) (CheckResp, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/useraccounts", apiURL), nil)
	if err != nil {
		return CheckResp{}, fmt.Errorf("while creating request for GET /v1/useraccounts: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := cl.Do(req)
	if err != nil {
		return CheckResp{}, fmt.Errorf("while making request to GET /v1/useraccounts: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	// The request was successful, the token is valid. Continue below.
	case http.StatusUnauthorized:
		return CheckResp{}, fmt.Errorf("unauthorized: please check your API key")
	case http.StatusForbidden:
		return CheckResp{}, fmt.Errorf("forbidden: please check your API key and permissions")
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
func getTeams(cl http.Client, apiURL, apiKey string) ([]Team, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/teams?includeSystemGenerated=true", nil)
	if err != nil {
		return nil, fmt.Errorf("getTeams: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getTeams: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, fmt.Errorf("getTeams: got http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		Teams []Team `json:"teams"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
		opts = append(opts, huh.NewOption(fmt.Sprintf("client ID: %s, name: %s", sa.ID, sa.Name), item{
			Name: sa.Name,
			ID:   sa.ID,
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
