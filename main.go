package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss/v2"
	"github.com/charmbracelet/lipgloss/v2/table"
	"github.com/fatih/color"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/lexer"
	"github.com/goccy/go-yaml/printer"
	"github.com/google/go-cmp/cmp"
	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const (
	userAgent     = "vcpctl/v0.0.1"
	defaultAPIURL = "https://api.venafi.cloud"
)

// Replace the old flag-based main() with cobra execution.
func main() {
	var apiURLFlag string
	rootCmd := &cobra.Command{
		Use:   "vcpctl",
		Short: "A CLI tool for Venafi configurations",
		Long: undent.Undent(`
			vcpctl is a CLI tool for managing Venafi Control Plane configurations.
			To configure it, set the APIKEY environment variable to your
			Venafi Control Plane API key. You can also set the APIURL environment variable
			to override the default API URL.
		`),
		Example: undent.Undent(`
			vcpctl ls
			vcpctl push config.yaml
			vcpctl edit <config-name>
			vcpctl pull <config-name> > config.yaml
			vcpctl set-service-account <config-name> <service-account-name>
			vcpctl sa ls
			vcpctl sa rm
			vcpctl sa keygen
			vcpctl subca ls
			vcpctl subca rm
			vcpctl policy ls
			vcpctl policy rm
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	rootCmd.PersistentFlags().StringVar(&apiURLFlag, "api-url", "", "Override the Venafi API URL (default: https://api.venafi.cloud, can also set APIURL env var; flag takes precedence)")
	rootCmd.PersistentFlags().BoolVar(&logutil.EnableDebug, "debug", false, "Enable debug logging (set to 'true' to enable)")
	rootCmd.AddCommand(lsCmd(), editCmd(), setServiceAccountCmd(), pushCmd(), pullCmd(), saCmd(), subcaCmd(), policyCmd())

	ctx := context.Background()
	err := fang.Execute(ctx, rootCmd)
	if err != nil {
		os.Exit(1)
	}
}

type ClientAuthentication struct {
	Type string   `json:"type"`
	URLs []string `json:"urls"`
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
	ID                   string               `json:"id,omitempty"`
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	ServiceAccountIDs    []string             `json:"serviceAccountIds"`
	Policies             []Policy             `json:"policies"`
	SubCaProvider        SubCaProvider        `json:"subCaProvider"`
	AdvancedSettings     AdvancedSettings     `json:"advancedSettings,omitempty"`
	CreationDate         string               `json:"creationDate,omitempty"`
	ModificationDate     string               `json:"modificationDate,omitempty"`
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

type SubCaProvider struct {
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

func getToolConfig(cmd *cobra.Command) (ToolConf, error) {
	token := os.Getenv("APIKEY")
	if token == "" {
		return ToolConf{}, fmt.Errorf("APIKEY environment variable not set")
	}

	// Priority: --api-url flag > APIURL env var > https://api.venafi.cloud.
	apiURLFlag, err := cmd.Flags().GetString("api-url")
	if err != nil {
		return ToolConf{}, fmt.Errorf("failed to get api-url flag: %w", err)
	}
	apiURL := defaultAPIURL
	if apiURLFlag != "" {
		apiURL = apiURLFlag
	} else if envURL := os.Getenv("APIURL"); envURL != "" {
		apiURL = envURL
	}

	return ToolConf{
		APIURL: apiURL,
		APIKey: token,
	}, nil
}

func saLsCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List Service Accounts",
		Long: undent.Undent(`
			List Service Accounts. Service Accounts are used to authenticate
			applications that use the Firefly Configurations.
		`),
		Example: undent.Undent(`
			vcpctl sa ls
			vcpctl sa ls -ojson
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa ls: while getting config %w", err)
			}
			svcaccts, err := getServiceAccounts(conf.APIURL, conf.APIKey)
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
						sa.Name,
						sa.ID,
						sa.AuthenticationType,
					})
				}
				t := table.New().
					Headers("Service Account", "Client ID", "Authentication Type").
					StyleFunc(func(row, col int) lipgloss.Style { return lipgloss.NewStyle().Padding(0, 1) }).
					Rows(rows...)
				fmt.Println(t.String())
				return nil
			default:
				return fmt.Errorf("sa ls: invalid output format: %s", outputFormat)
			}
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (json, table)")
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
			vcpctl sa ls -ojson
			vcpctl sa rm <sa-name>
			vcpctl sa keygen <sa-name>
			vcpctl set-service-account <config-name> <sa-name>
		`),
	}
	cmd.AddCommand(
		saLsCmd(),
		saRmCmd(),
		saKeygenCmd(),
		saGetClientIDCmd(),
		&cobra.Command{Use: "gen-rsa", Deprecated: "the 'gen-rsa' command is deprecated, please use 'keygen' instead.", RunE: saKeygenCmd().RunE},
	)
	return cmd
}

func saKeygenCmd() *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "keygen <sa-name>",
		Short: "Generates an EC private key and registers it to the given Service Account, or create it if it doesn't exist",
		Long: undent.Undent(`
			Generates an EC private key and registers it to the given Service
			Account in Venafi Control Plane. The Service Account is created
			if it doesn't exist. The private key is printed to stdout in PEM,
			you can use it to create a Kubernetes secret, for example:

			  vcpctl sa keygen my-sa | \
			    kubectl create secret generic venafi-credentials \
			    --from-file=svc-acct.key=/dev/stdin

			Once that's done, you can grab the client ID with:

			  vcpctl sa get-client-id <my-sa>

			You can use '-ojson' to get the client ID and the private key in
			JSON format in a venctl-compatible format that looks like this:

			  {
					"client_id": "123e4567-e89b-12d3-a456-426614174000",
					"private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
			  }
		`),
		Example: undent.Undent(`
			vcpctl sa keygen <sa-name>
			vcpctl sa keygen <sa-name> -ojson
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa keygen: while getting config %w", err)
			}

			saName := args[0]

			// Does it already exist?
			existingSA, err := getServiceAccountByName(conf.APIURL, conf.APIKey, saName)
			switch {
			case errors.As(err, &NotFound{}):
				// Doesn't exist yet, we will be creating it below.
			case err == nil:
				// Exists, we will be updating it.
			default:
				return fmt.Errorf("sa keygen: while checking if service account exists: %w", err)
			}

			ecKey, ecPub, err := genECKeyPair()
			if err != nil {
				return fmt.Errorf("sa keygen: while generating EC key pair: %w", err)
			}

			var resp SACreateResp
			if existingSA.ID == "" {
				resp, err = createServiceAccount(conf.APIURL, conf.APIKey, ServiceAccount{
					Name:               saName,
					CredentialLifetime: 365, // days
					Scopes:             []string{"distributed-issuance"},
					// PublicKey:          ecPub,
				})
				if err != nil {
					return fmt.Errorf("sa keygen: while creating service account: %w", err)
				}
				logutil.Infof("Service Account '%s' created.\nClient ID: %s", saName, resp.ID)
			} else {
				updatedSA := existingSA
				updatedSA.PublicKey = ecPub
				p := fullToPatchServiceAccount(updatedSA)
				err = patchServiceAccount(conf.APIURL, conf.APIKey, updatedSA.ID, p)
				if err != nil {
					return fmt.Errorf("sa keygen: while patching service account: %w", err)
				}

				if logutil.EnableDebug {
					d := ANSIDiff(fullToPatchServiceAccount(existingSA), fullToPatchServiceAccount(updatedSA))
					logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
				}
				logutil.Debugf("Client ID: %s", existingSA.ID)
			}

			switch outputFormat {
			case "pem":
				fmt.Println(ecKey)
			case "json":
				bytes, err := json.MarshalIndent(struct {
					ClientID   string `json:"client_id"`
					PrivateKey string `json:"private_key"`
				}{ClientID: existingSA.ID, PrivateKey: ecKey}, "", "  ")
				if err != nil {
					return fmt.Errorf("sa keygen: while marshaling JSON: %w", err)
				}
				fmt.Println(string(bytes))
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "pem", "Output format (pem, json)")
	return cmd
}

func saGetClientIDCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get-client-id <sa-name>",
		Short: "Get the client ID of a Service Account",
		Long: undent.Undent(`
			Get the client ID of a Service Account. The client ID is used to
			authenticate with the Firefly Configurations.
			You can use this client ID to set the Service Account for a Firefly
			Configuration.
		`),
		Example: undent.Undent(`
			vcpctl sa get-client-id <sa-name>
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa get-client-id: while getting config %w", err)
			}
			saName := args[0]
			sa, err := getServiceAccountByName(conf.APIURL, conf.APIKey, saName)
			if err != nil {
				if errors.As(err, &NotFound{}) {
					return fmt.Errorf("sa get-client-id: service account '%s' not found", saName)
				}
				return fmt.Errorf("sa get-client-id: while getting service account by name: %w", err)
			}

			if sa.ID == "" {
				return fmt.Errorf("sa get-client-id: service account '%s' has no client ID", saName)
			}

			fmt.Println(sa.ID)
			return nil
		},
	}

	return cmd
}

func saRmCmd() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{
		Use:   "rm [<sa-name> | -i]",
		Short: "Remove a Service Account",
		Long: undent.Undent(`
			Remove a Service Account. This will delete the Service Account from
			Venafi Control Plane.
		`),
		Example: undent.Undent(`
			vcpctl sa rm <sa-name>
			vcpctl sa rm -i
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if interactive {
				if len(args) > 0 {
					return fmt.Errorf("sa rm -i: expected no arguments when using --interactive, got %d", len(args))
				}
				// In interactive mode, we will list the service accounts and let the user
				// select one to remove.
				conf, err := getToolConfig(cmd)
				if err != nil {
					return fmt.Errorf("sa rm -i: while getting config %w", err)
				}
				svcaccts, err := getServiceAccounts(conf.APIURL, conf.APIKey)
				if err != nil {
					return fmt.Errorf("sa rm -i: while listing service accounts: %w", err)
				}

				// Use a simple prompt to select the service account to remove.
				selected := rmInteractive(svcaccts)
				for _, saID := range selected {
					err = removeServiceAccount(conf.APIURL, conf.APIKey, saID)
					if err != nil {
						return fmt.Errorf("sa rm -i: while removing service account '%s': %w", saID, err)
					}
				}

				logutil.Infof("Service Account(s) removed successfully:\n%s", strings.Join(selected, "\n"))
				return nil
			}

			if len(args) != 1 {
				return fmt.Errorf("sa rm: expected 1 argument, got %d", len(args))
			}
			saName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("sa rm: while getting config %w", err)
			}

			err = removeServiceAccount(conf.APIURL, conf.APIKey, saName)
			if err != nil {
				return fmt.Errorf("sa rm: %w", err)
			}

			return nil
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactively select the service account to remove.")
	return cmd
}

// List Firefly configurations.
func lsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the Firefly Configurations present in Venafi Control Plane",
		Long: undent.Undent(`
			List the Firefly Configurations present in Venafi Control Plane.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Note: The following functions (GetTokenUsingFileConf and listObjects)
			// should be implemented according to your needs.
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("ls: while getting config %w", err)
			}

			confs, err := listConfigs(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("ls: while listing configurations: %w", err)
			}

			// Find service accounts so that we can show the client IDs instead of the
			// IDs.
			knownSvcaccts, err := getServiceAccounts(conf.APIURL, conf.APIKey)
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
							saNames = append(saNames, sa.ID+" ("+sa.Name+")")
							found = true
							break
						}
					}
					if !found {
						saNames = append(saNames, saID+" (deleted)")
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

			t := table.New().
				Headers("Firefly Configuration", "Attached Service Accounts' Client IDs").
				StyleFunc(func(row, col int) lipgloss.Style { return lipgloss.NewStyle().Padding(0, 1) }).
				Rows(rows...)

			fmt.Println(t.String())

			rows = nil
			for _, m := range knownSvcaccts {
				rows = append(rows, []string{m.Name, m.ID})
			}

			t = table.New().
				Headers("Service Account", "Client ID").
				StyleFunc(func(row, col int) lipgloss.Style { return lipgloss.NewStyle().Padding(0, 1) }).
				Rows(rows...)

			fmt.Println(t.String())
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
			for a Firefly Configuration.

			Example:
			  vcpctl subca ls
			  vcpctl subca create --name foo
			  vcpctl subca rm foo
			  vcpctl subca pull foo
		`),
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
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("subca ls: while getting config %w", err)
			}
			providers, err := getSubCaProviders(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("subca ls: while listing subCA providers: %w", err)
			}

			var rows [][]string
			for _, provider := range providers {
				rows = append(rows, []string{
					provider.Name,
					provider.ID,
					provider.CaType,
					provider.CaAccountID,
					provider.CaProductOptionID,
				})
			}
			t := table.New().
				Headers("SubCA Provider", "ID", "CA Type", "CA Account ID", "CA Product Option ID").
				StyleFunc(func(row, col int) lipgloss.Style { return lipgloss.NewStyle().Padding(0, 1) }).
				Rows(rows...)

			fmt.Println(t.String())

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
			Venafi Control Plane. You cannot remove a SubCA Provider that is
			attached to a Firefly Configuration.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected 1 argument, got %d", len(args))
			}
			providerNameOrID := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: while getting config %w", err)
			}

			err = removeSubCaProvider(conf.APIURL, conf.APIKey, providerNameOrID)
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
			Firefly Configuration.
		`),
		Example: undent.Undent(`
			vcpctl policy ls
			vcpctl policy rm <policy-name>
		`),
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
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("policy ls: while getting config %w", err)
			}
			policies, err := getPolicies(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("policy ls: while listing policies: %w", err)
			}
			var rows [][]string
			for _, policy := range policies {
				rows = append(rows, []string{
					policy.Name,
					policy.ID,
					policy.ValidityPeriod,
					strings.Join(policy.Subject.CommonName.DefaultValues, ", "),
					strings.Join(policy.SANs.DNSNames.DefaultValues, ", "),
				})
			}

			t := table.New().
				Headers("Policy", "ID", "Validity Period", "Common Name", "DNS Names").
				StyleFunc(func(row, col int) lipgloss.Style { return lipgloss.NewStyle().Padding(0, 1) }).
				Rows(rows...)

			fmt.Println(t.String())

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
			Remove a Policy. This will delete the Policy from Venafi Control Plane.
			You cannot remove a Policy that is attached to a Firefly Configuration.
			You must first remove the Policy from the Firefly Configuration.
		`),
		Example: undent.Undent(`
			vcpctl policy rm <policy-name>
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rm: expected 1 argument, got %d", len(args))
			}
			policyNameOrID := args[0]
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("rm: while getting config %w", err)
			}
			err = removePolicy(conf.APIURL, conf.APIKey, policyNameOrID)
			if err != nil {
				return fmt.Errorf("rm: %w", err)
			}
			logutil.Infof("Policy '%s' deleted successfully.", policyNameOrID)
			return nil
		},
	}
	return cmd
}

func removePolicy(apiURL, apiKey, policyName string) error {
	// Find the policy by name.
	policy, err := getPolicyByName(apiURL, apiKey, policyName)
	if err != nil {
		return fmt.Errorf("removePolicy: while getting policy by name %q: %w", policyName, err)
	}

	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/policies/"+policy.ID, nil)
	if err != nil {
		return fmt.Errorf("removePolicy: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
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

func getSubCaProviders(apiURL, apiKey string) ([]SubCaProvider, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return nil, fmt.Errorf("getSubCaProviders: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getSubCaProviders: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return nil, fmt.Errorf("http %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCaProvider `json:"subCaProviders"`
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getSubCaProviders: while reading response body: %w", err)
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, fmt.Errorf("getSubCaProviders: while decoding %s response: %w, body was: %s", resp.Status, err, string(bytes))
	}

	return result.SubCaProviders, nil
}

func removeSubCaProvider(apiURL, apiKey, providerNameOrID string) error {
	req, err := http.NewRequest("DELETE", apiURL+"/v1/distributedissuers/subcaproviders/"+providerNameOrID, nil)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
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

func setServiceAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-service-account",
		Short: "Set a Service Account for a given Firefly Configuration",
		Long: undent.Undent(`
			Set a Service Account for a given Firefly Configuration.
		`),
		Example: undent.Undent(`
			vcpctl set-service-account "config-name" "sa-name"
			vcpctl set-service-account "config-name" "03931ba6-3fc5-11f0-85b8-9ee29ab248f0"
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("set-service-account: expected 2 arguments, got %d", len(args))
			}
			confName := args[0]
			saName := args[1]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("set-service-account: while getting config %w", err)
			}

			err = setServiceAccount(conf.APIURL, conf.APIKey, confName, saName)
			if err != nil {
				return fmt.Errorf("set-service-account: %w", err)
			}

			return nil
		},
	}
}

func setServiceAccount(apiURL, apiKey, confName, saName string) error {
	// Get configuration name by ID.
	config, err := getConfigByName(apiURL, apiKey, confName)
	if err != nil {
		return fmt.Errorf("while fetching Firefly configuration ID for the configuration '%s': %w", confName, err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(apiURL, apiKey)
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
		logutil.Infof("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.ID, config.Name)
		return nil
	}

	// Add the service account to the configuration.
	config.ServiceAccountIDs = append(config.ServiceAccountIDs, sa.ID)
	patch := fullToPatchConfig(config)
	err = patchConfig(apiURL, apiKey, config.ID, patch)
	if err != nil {
		return fmt.Errorf("while patching Firefly configuration: %w", err)
	}

	return nil
}

func editCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Edit a Firefly Configuration",
		Long: undent.Undent(`
			Edit a Firefly Configuration.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("edit: expected 1 argument, got %d", len(args))
			}

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("edit: while getting config %w", err)
			}

			err = editConfig(conf.APIURL, conf.APIKey, args[0])
			if err != nil {
				return fmt.Errorf("edit: %w", err)
			}

			return nil
		},
	}
}

func pushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push",
		Short: "Push a Firefly Configuration to Venafi Control Plane",
		Long: undent.Undent(`
			Push a Firefly Configuration to Venafi Control Plane. The config may
			already exist, in which case it will be updated. The name in the
			config's 'name' field is used to identify the configuration.
		`),
		Example: undent.Undent(`
			vcpctl push config.yaml
			vcpctl push - < config.yaml
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("push: expected 1 argument, got %d", len(args))
			}

			var file *os.File
			var path string
			switch args[0] {
			case "-":
				path = "/dev/stdin"
				file = os.Stdin
			default:
				path = args[0]
				var err error
				file, err = os.Open(path)
				if err != nil {
					return fmt.Errorf("push: opening file ''%s'': %w", path, err)
				}
				defer file.Close()
			}

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("push: while getting config %w", err)
			}

			bytes, err := io.ReadAll(file)
			if err != nil {
				return fmt.Errorf("push: while reading Firefly configuration from '%s': %w", path, err)
			}

			if err := validateYAMLFireflyConfig(bytes); err != nil {
				return fmt.Errorf("push: Firefly configuration validation failed: %w", err)
			}

			// Read the Firefly configuration.
			var updatedConfig FireflyConfig
			if err := yaml.UnmarshalWithOptions(bytes, &updatedConfig, yaml.Strict()); err != nil {
				return fmt.Errorf("push: while decoding Firefly configuration from '%s': %w", path, err)
			}
			updatedConfig = hideMisleadingFields(updatedConfig)

			if updatedConfig.Name == "" {
				return fmt.Errorf("push: Firefly configuration must have a 'name' field set")
			}

			// Patch the original configuration with the new values.
			err = createOrUpdateConfigAndDeps(conf.APIURL, conf.APIKey, updatedConfig)
			if err != nil {
				return fmt.Errorf("push: while patching Firefly configuration: %w", err)
			}

			return nil
		},
	}
}

func getSubCaProvider(apiURL, apiKey, id string) (SubCaProvider, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders/"+id, nil)
	if err != nil {
		return SubCaProvider{}, fmt.Errorf("getSubCaProvider: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SubCaProvider{}, fmt.Errorf("getSubCaProvider: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var result SubCaProvider
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			body, _ := io.ReadAll(resp.Body)
			return SubCaProvider{}, fmt.Errorf("getSubCaProvider: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
		}
		return result, nil
	case http.StatusNotFound:
		return SubCaProvider{}, NotFound{NameOrID: id}
	default:
		return SubCaProvider{}, fmt.Errorf("getSubCaProvider: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func getPolicyByName(apiURL, apiKey, nameOrID string) (Policy, error) {
	policies, err := getPolicies(apiURL, apiKey)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicyByName: while getting policies: %w", err)
	}

	// Find the policy by name. Error out if duplicate names are found.
	var found Policy
	for _, cur := range policies {
		if cur.Name == nameOrID {
			if found.ID != "" {
				return Policy{}, fmt.Errorf("getPolicyByName: duplicate policies found with name '%s':\n"+
					"- %s (%s) created on %s\n"+
					"- %s (%s) created on %s\n"+
					"Please remove one of the service accounts first. You can run:\n"+
					"    vcpctl sa rm %s", nameOrID, cur.Name, cur.ID, cur.CreationDate, found.Name, found.ID, found.CreationDate, found.ID)
			}
			found = cur
		}
	}
	if found.ID == "" {
		return Policy{}, fmt.Errorf("getPolicyByName: policy with name '%s' not found", nameOrID)
	}

	// Now we can get the policy by ID.
	return found, nil
}

func getSubCaProviderByName(apiURL, apiKey, name string) (SubCaProvider, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/subcaproviders", nil)
	if err != nil {
		return SubCaProvider{}, fmt.Errorf("getSubCaProviderByName: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SubCaProvider{}, fmt.Errorf("getSubCaProviderByName: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return SubCaProvider{}, fmt.Errorf("getSubCaProviderByName: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCaProvider `json:"subCaProviders"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return SubCaProvider{}, fmt.Errorf("getSubCaProviderByName: while decoding response: %w", err)
	}

	// Error out if a duplicate name is found.
	var found SubCaProvider
	for _, provider := range result.SubCaProviders {
		if provider.Name == name {
			if found.ID != "" {
				return SubCaProvider{}, fmt.Errorf("getSubCaProviderByName: duplicate subCA providers found with name '%s':\n"+
					"- %s (%s)\n"+
					"- %s (%s)\n"+
					"Please remove one of the subCA providers first. You can run:\n"+
					"    vcpctl subca rm %s", name, provider.Name, provider.ID, found.Name, found.ID, found.ID)
			}
			found = provider
		}
	}
	if found.ID == "" {
		return SubCaProvider{}, fmt.Errorf("subCA provider: %w", NotFound{NameOrID: name})
	}

	// Now we can get the subCA provider by ID.
	return found, nil
}

func getConfigByName(apiURL, apiKey, nameOrID string) (FireflyConfig, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return FireflyConfig{}, fmt.Errorf("getConfigByName: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return FireflyConfig{}, fmt.Errorf("getConfigByName: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return FireflyConfig{}, fmt.Errorf("getConfigByName: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
	var result struct {
		Configurations []FireflyConfig `json:"configurations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return FireflyConfig{}, fmt.Errorf("getConfigByName: while decoding response: %w", err)
	}
	// Find the configuration by name or ID. Error out if duplicate names are found.
	var found FireflyConfig
	for _, cur := range result.Configurations {
		if cur.Name == nameOrID || cur.ID == nameOrID {
			if found.ID != "" {
				return FireflyConfig{}, fmt.Errorf("getConfigByName: duplicate configurations found with name '%s':\n"+
					"- %s (%s) created on %s\n"+
					"- %s (%s) created on %s\n"+
					"Please remove one of the configurations first. You can run:\n"+
					"    vcpctl rm %s", nameOrID, cur.Name, cur.ID, cur.CreationDate, found.Name, found.ID, found.CreationDate, found.ID)
			}
			found = cur
		}
	}
	if found.ID == "" {
		return FireflyConfig{}, fmt.Errorf("getConfigByName: configuration with name '%s' not found", nameOrID)
	}

	// Now we can get the configuration by ID.
	return found, nil
}

func getPolicies(apiURL, apiKey string) ([]Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
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

func getPolicy(apiURL, apiKey, id string) (Policy, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/policies/"+id, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicy: while creating request: %w", err)
	}

	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Policy{}, fmt.Errorf("getPolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var result Policy
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return Policy{}, fmt.Errorf("getPolicy: while decoding %s response: %w", resp.Status, err)
		}
		return result, nil
	case http.StatusNotFound:
		return Policy{}, &NotFound{NameOrID: id}
	default:
		return Policy{}, fmt.Errorf("getPolicy: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}
}

func pullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "Pull a Firefly Configuration from Venafi Control Plane",
		Long: undent.Undent(`
			Pull a Firefly Configuration from Venafi Control Plane. The config
			will be written to stdout in YAML format.
		`),
		Example: undent.Undent(`
			vcpctl pull <config-name>
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("pull: expected 1 argument, got %d", len(args))
			}
			idOrName := args[0]

			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("pull: while getting config %w", err)
			}

			// Get the original configuration.
			originalConfig, err := getConfigByName(conf.APIURL, conf.APIKey, idOrName)
			if err != nil {
				return fmt.Errorf("pull: while getting original Firefly configuration: %w", err)
			}

			// Find service accounts.
			knownSvcaccts, err := getServiceAccounts(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("pull: while fetching service accounts: %w", err)
			}

			yamlData, err := yaml.MarshalWithOptions(
				hideMisleadingFields(originalConfig),
				yaml.WithComment(svcAcctsComments(originalConfig, knownSvcaccts)),
				yaml.Indent(4),
			)
			if err != nil {
				return err
			}
			yamlData = appendSchemaComment(yamlData)

			coloredYAMLPrintf(string(yamlData))

			return nil
		},
	}
}

// Zero out the config ID, subCA provider ID, and policy IDs in the
// configuration. Service account IDs are kept. Useful for removing misleading
// fields before marshalling to YAML.
func hideMisleadingFields(config FireflyConfig) FireflyConfig {
	c := config

	var policies []Policy
	for i := range config.Policies {
		policies = append(policies, config.Policies[i])
	}
	c.Policies = policies

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

	return c
}

// createConfig creates a new Firefly configuration or updates an
// existing one. Also deals with creating the subCA policies.
func createConfig(apiURL, apiKey string, config FireflyConfig) (string, error) {
	reqBody := struct {
		Name              string   `json:"name"`
		SubCaProviderID   string   `json:"subCaProviderId"`
		PolicyIDs         []string `json:"policyIds"`
		ServiceAccountIDs []string `json:"serviceAccountIds"`
		MinTLSVersion     string   `json:"minTlsVersion"`
		AdvancedSettings  struct {
			EnableIssuanceAuditLog       bool `json:"enableIssuanceAuditLog"`
			IncludeRawCertDataInAuditLog bool `json:"includeRawCertDataInAuditLog"`
			RequireFIPSCompliantBuild    bool `json:"requireFIPSCompliantBuild"`
		} `json:"advancedSettings"`
		ClientAuthentication ClientAuthentication `json:"clientAuthentication"`
		CloudProviders       map[string]any       `json:"cloudProviders"`
	}{
		Name:              config.Name,
		SubCaProviderID:   config.SubCaProvider.ID,
		PolicyIDs:         make([]string, len(config.Policies)),
		ServiceAccountIDs: config.ServiceAccountIDs,
		MinTLSVersion:     config.MinTLSVersion,
		AdvancedSettings: struct {
			EnableIssuanceAuditLog       bool `json:"enableIssuanceAuditLog"`
			IncludeRawCertDataInAuditLog bool `json:"includeRawCertDataInAuditLog"`
			RequireFIPSCompliantBuild    bool `json:"requireFIPSCompliantBuild"`
		}{
			EnableIssuanceAuditLog:       config.AdvancedSettings.EnableIssuanceAuditLog,
			IncludeRawCertDataInAuditLog: config.AdvancedSettings.IncludeRawCertDataInAuditLog,
			RequireFIPSCompliantBuild:    config.AdvancedSettings.RequireFIPSCompliantBuild,
		},
		ClientAuthentication: config.ClientAuthentication,
		CloudProviders:       config.CloudProviders,
	}

	body, err := json.Marshal(reqBody)
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
	resp, err := http.DefaultClient.Do(req)
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

func createFireflyPolicy(apiURL, apiKey string, policy Policy) (string, error) {
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
	resp, err := http.DefaultClient.Do(req)
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

func createSubCaProvider(apiURL, apiKey string, provider SubCaProvider) (string, error) {
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
	resp, err := http.DefaultClient.Do(req)
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

func listConfigs(apiURL, apiKey string) ([]Config, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while making request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Configurations []struct {
			Name              string   `json:"name"`
			ServiceAccountIDs []string `json:"serviceAccountIds"`
		} `json:"configurations"`
	}

	b := new(bytes.Buffer)
	_, err = io.Copy(b, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: returned status code %s: %w", resp.Status, parseJSONErrorOrDumpBody(resp))
	}

	if err := json.NewDecoder(b).Decode(&result); err != nil {
		if b.Len() > 1000 {
			// Only show the first 1000 characters of the body in the error
			// message.
			b.Truncate(1000)
		}
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while decoding response: %w, body: %s", err, b.String())
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

func getConfig(apiURL, apiKey, id string) (FireflyConfig, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", apiURL, id), nil)
	if err != nil {
		return FireflyConfig{}, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
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

func editConfig(apiURL, apiKey, name string) error {
	config, err := getConfigByName(apiURL, apiKey, name)
	if err != nil {
		if errors.Is(err, NotFound{}) {
			return fmt.Errorf("configuration '%s' not found. Please create it first using 'vcpctl push config.yaml'", name)
		}
		return fmt.Errorf("while getting configuration ID: %w", err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	yamlData, err := yaml.MarshalWithOptions(
		hideMisleadingFields(config),
		yaml.WithComment(svcAcctsComments(config, knownSvcaccts)),
	)
	if err != nil {
		return err
	}
	yamlData = appendSchemaComment(yamlData)
	tmpfile, err := os.CreateTemp("", "vcp-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(yamlData); err != nil {
		return err
	}
	defer tmpfile.Close()

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

	err = validateYAMLFireflyConfig(modifiedRaw)
	if err != nil {
		notice := "# NOTICE: The configuration you have modified is not valid.\n" +
			"# NOTICE: Please fix the errors and re-edit the configuration.\n" +
			"# NOTICE: The errors are:\n" + err.Error() + "\n"

		// Prepend the notice to the modified YAML.
		tmpfile.Seek(0, 0)
		_, err = tmpfile.Write(append([]byte(notice), modifiedRaw...))
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		goto edit
	}

	var modified FireflyConfig
	if err := yaml.UnmarshalWithOptions(modifiedRaw, &modified, yaml.Strict()); err != nil {
		notice := "# NOTICE: The configuration you have modified is not valid.\n" +
			"# NOTICE: Please fix the errors and re-edit the configuration.\n" +
			"# NOTICE: The errors are:\n" + err.Error() + "\n"

		// Prepend the notice to the modified YAML.
		tmpfile.Seek(0, 0)
		_, err = tmpfile.Write(append([]byte(notice), modifiedRaw...))
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		goto edit
	}

	err = createOrUpdateConfigAndDeps(apiURL, apiKey, modified)
	if errors.Is(err, errPINRequired) {
		// If the PIN is required, we need to ask the user to fill it in.
		logutil.Errorf("ERROR: The subCaProvider.pkcs11.pin field is required.")
		logutil.Errorf("Reopening the editor so that you can fill it in.")

		// Add the notice to the top of the file.
		notice := "# NOTICE: Since you have changed the subCaProvider, you need fill in the subCaProvider.pkcs11.pin\n" +
			"# NOTICE: field. has been modified. Please re-edit the configuration to fill in the PKCS11 pin.\n"

		// Prepend the notice to the modified YAML.
		tmpfile.Seek(0, 0)
		_, err = tmpfile.Write(append([]byte(notice), modifiedRaw...))
		if err != nil {
			return fmt.Errorf("while writing notice to file: %w", err)
		}
		goto edit
	}
	if err != nil {
		return fmt.Errorf("while merging and patching Firefly configuration: %w", err)
	}

	return nil
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

var errPINRequired = fmt.Errorf("subCaProvider.pkcs11.pin is required when patching the subCA provider")

// Also patches the nested SubCA provider and Firefly Policies. Use
// errors.Is(err, errPINRequired) to check if the error is due to the missing
// PIN.
func createOrUpdateConfigAndDeps(apiURL, apiKey string, updatedConfig FireflyConfig) error {
	// Check that the service account IDs exist.
	knownSvcaccts, err := getServiceAccounts(apiURL, apiKey)
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

	templates, err := getIssuingTemplates(apiURL, apiKey)
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
		return fmt.Errorf("built-in issuing template not found, please check your Venafi Control Plane configuration")
	}

	existingConfig, err := getConfigByName(apiURL, apiKey, updatedConfig.Name)
	switch {
	case errors.As(err, &NotFound{}):
		// Continue below since the nested sub CA and policies may not already
		// exist, so the Firefly configuration may need to be patched.
	case err != nil:
		return fmt.Errorf("while getting configuration ID: %w", err)
	}

	// Before dealing with patching the configuration, let's patch the policies
	// and the SubCA provider, if needed.
	for i := range updatedConfig.Policies {
		// Get the original policy to check if it exists.
		existingPolicy, err := getPolicyByName(apiURL, apiKey, updatedConfig.Policies[i].Name)
		switch {
		case errors.As(err, &NotFound{}):
			// We will create it below.
		case err != nil:
			return fmt.Errorf("while getting the existing Firefly policy '%s': %w", updatedConfig.Policies[i].Name, err)
		default:
			// Policy exists and might need to be patched. Continue below.
		}

		if existingPolicy.ID == "" {
			// The policy does not exist, we need to create it.
			id, err := createFireflyPolicy(apiURL, apiKey, updatedConfig.Policies[i])
			if err != nil {
				return fmt.Errorf("while creating Firefly policy: %w", err)
			}
			updatedConfig.Policies[i].ID = id
			logutil.Infof("Policy '%s' created with ID '%s'.", updatedConfig.Policies[i].Name, id)
		} else {
			updatedConfig.Policies[i].ID = existingPolicy.ID

			// If the policy is not equal to the original one, we need to update it.
			d := ANSIDiff(fullToPatchPolicy(existingPolicy), fullToPatchPolicy(updatedConfig.Policies[i]))
			if d == "" {
				logutil.Infof("Policy '%s' is unchanged, skipping update.", updatedConfig.Policies[i].Name)
				continue
			}

			// If the policy is different, we need to update it.
			logutil.Infof("Policy '%s' was changed:\n%s\n", updatedConfig.Policies[i].Name, d)

			// Patch the policy.
			err = patchPolicy(apiURL, apiKey, existingPolicy.ID, fullToPatchPolicy(updatedConfig.Policies[i]))
			if err != nil {
				return fmt.Errorf("while patching Firefly policy #%d '%s': %w", i, updatedConfig.Policies[i].Name, err)
			}
		}
	}

	// Now, let's take care of the SubCA provider.
	existingSubCa, err := getSubCaProviderByName(apiURL, apiKey, updatedConfig.SubCaProvider.Name)
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
		id, err := createSubCaProvider(apiURL, apiKey, updatedConfig.SubCaProvider)
		if err != nil {
			return fmt.Errorf("while creating SubCA provider: %w", err)
		}
		updatedConfig.SubCaProvider.ID = id
		logutil.Infof("SubCA provider '%s' created with ID '%s'.", updatedConfig.SubCaProvider.Name, id)
	} else {
		updatedConfig.SubCaProvider.ID = existingSubCa.ID

		// If the SubCA provider is not equal to the original one, we need to update it.
		diff := ANSIDiff(fullToPatchSubCAProvider(existingSubCa), fullToPatchSubCAProvider(updatedConfig.SubCaProvider))
		if diff == "" {
			logutil.Infof("SubCA provider '%s' is unchanged, skipping update.", updatedConfig.SubCaProvider.Name)
		} else {
			// The `subCaProvider.pkcs11.pin` field is never returned by the API, so
			// we need to check if the user has changed it and patch it separately.
			// If the user still wants to patch the subCAProvider, we need to ask
			// them to re-edit the manifest to fill in the pin.
			//
			// First off, let's check if the user has changed something under the
			// `subCaProvider`.

			if !isZeroPKCS11(updatedConfig.SubCaProvider.PKCS11) && updatedConfig.SubCaProvider.PKCS11.PIN == "" {
				return fmt.Errorf("while patching Firefly configuration's subCAProvider: %w", errPINRequired)
			}

			// If the SubCA provider is different, we need to update it.
			logutil.Infof("SubCA provider '%s' was changed:\n%s\n", updatedConfig.SubCaProvider.Name, diff)

			// Patch the SubCA provider.
			err = patchSubCaProvider(apiURL, apiKey, existingSubCa.ID, fullToPatchSubCAProvider(updatedConfig.SubCaProvider))
			if err != nil {
				return fmt.Errorf("while patching Firefly SubCA provider '%s': %w", updatedConfig.SubCaProvider.Name, err)
			}
		}
	}

	// If we reach this point, we have successfully patched the configuration,
	// subCA provider, and policies. Let's see if the Firefly configuration
	// needs to be created or updated.
	if existingConfig.ID == "" {
		// The configuration does not exist, we need to create it.
		confID, err := createConfig(apiURL, apiKey, updatedConfig)
		if err != nil {
			return fmt.Errorf("while creating Firefly configuration: %w", err)
		}

		logutil.Infof("Configuration '%s' created with ID '%s'.", updatedConfig.Name, confID)
	} else {
		// The configuration exists, we need to patch it.
		d := ANSIDiff(fullToPatchConfig(existingConfig), fullToPatchConfig(updatedConfig))
		if d == "" {
			logutil.Infof("Configuration '%s' is unchanged, skipping update.", updatedConfig.Name)
			return nil
		} else {
			logutil.Infof("Configuration '%s' was changed:\n%s\n", updatedConfig.Name, d)

			patch := fullToPatchConfig(updatedConfig)
			err = patchConfig(apiURL, apiKey, existingConfig.ID, patch)
			if err != nil {
				return fmt.Errorf("while patching Firefly configuration: %w", err)
			}
			logutil.Infof("Configuration '%s' updated successfully.", updatedConfig.Name)
		}
	}

	return nil
}

func patchConfig(apiURL, apiKey, id string, patch FireflyConfigPatch) error {
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

	resp, err := http.DefaultClient.Do(req)
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

func patchSubCaProvider(apiURL, apiKey, id string, patch SubCaProviderPatch) error {
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

	resp, err := http.DefaultClient.Do(req)
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

func parseJSONErrorOrDumpBody(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var venafiErr VenafiError
	if err := json.Unmarshal(body, &venafiErr); err != nil {
		logutil.Debugf("parseJSONErrorOrDumpBody: while decoding JSON error response: %s", err)
		return fmt.Errorf("unexpected error: %s", string(body))
	}

	return venafiErr
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

func fullToPatchSubCAProvider(full SubCaProvider) SubCaProviderPatch {
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
func patchPolicy(apiURL, apiKey, id string, patch PolicyPatch) error {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("Firefly policy: %w", NotFound{NameOrID: id})
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

func getServiceAccounts(apiURL, apiKey string) ([]ServiceAccount, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/serviceaccounts", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
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

func removeServiceAccount(apiURL, apiKey, nameOrID string) error {
	var id string
	if len(nameOrID) == 36 && strings.Count(nameOrID, "-") == 4 {
		// It looks like a UUID, so we can use it directly.
		id = nameOrID
	} else {
		// It looks like a name, so we need to find the ID first.
		sa, err := getServiceAccountByName(apiURL, apiKey, nameOrID)
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

	resp, err := http.DefaultClient.Do(req)
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

func getServiceAccountByName(apiURL, apiKey, name string) (ServiceAccount, error) {
	sas, err := getServiceAccounts(apiURL, apiKey)
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("getServiceAccountByName: while getting service accounts: %w", err)
	}

	// Error out if a duplicate service account name is found.
	var found []ServiceAccount
	for _, sa := range sas {
		if sa.Name == name {
			found = append(found, sa)
		}
	}

	if len(found) == 0 {
		return ServiceAccount{}, NotFound{NameOrID: name}
	}
	if len(found) == 1 {
		return found[0], nil
	}

	// If we have multiple service accounts with the same name, let the user
	// know about the duplicates.
	var lst strings.Builder
	for _, sa := range found {
		lst.WriteString(fmt.Sprintf("  - %s (%s)\n", sa.Name, sa.ID))
	}
	return ServiceAccount{}, fmt.Errorf("getServiceAccountByName: duplicate service account name '%s' found.\n"+
		"The conflicting service accounts are:\n"+
		lst.String()+
		"Please remove one with the command:\n"+
		"  vcpctl sa rm %s\n",
		name,
		found[0].ID)

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
func createServiceAccount(apiURL, apiKey string, sa ServiceAccount) (SACreateResp, error) {
	// If no owner is specified, let's just use the first team we can find.
	if sa.Owner == "" {
		teams, err := getTeams(apiURL, apiKey)
		if err != nil {
			return SACreateResp{}, fmt.Errorf("createServiceAccount: while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return SACreateResp{}, fmt.Errorf("createServiceAccount: no teams found, please specify an owner")
		}
		sa.Owner = teams[0].ID
		logutil.Infof("no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].ID)
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
	resp, err := http.DefaultClient.Do(req)
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
		return SACreateResp{}, fmt.Errorf("http %s: please check the Status account fields: %w", resp.StatusCode, parseJSONErrorOrDumpBody(resp))
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

func patchServiceAccount(apiURL, apiKey, id string, patch ServiceAccountPatch) error {
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

	resp, err := http.DefaultClient.Do(req)
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

func getIssuingTemplates(apiURL, apiKey string) ([]CertificateIssuingTemplate, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/certificateissuingtemplates", nil)
	if err != nil {
		return nil, fmt.Errorf("getIssuingTemplates: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
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
func getTeams(apiURL, apiKey string) ([]Team, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/teams?includeSystemGenerated=true", nil)
	if err != nil {
		return nil, fmt.Errorf("getTeams: while creating request: %w", err)
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
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

// For anyone who uses the Red Hat YAML LSP server.
func appendSchemaComment(b []byte) []byte {
	return appendLines(b,
		"# yaml-language-server: $schema=https://raw.githubusercontent.com/maelvls/vcpctl/refs/heads/main/schema.json",
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

func coloredYAMLPrintf(yamlBytes string) {
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
