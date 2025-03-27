package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/google/go-cmp/cmp"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

const (
	userAgent = "vcpctl/v0.0.1"
)

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
	ID                   string               `json:"id"`
	CompanyID            string               `json:"companyId"`
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	ServiceAccountIDs    []string             `json:"serviceAccountIds"`
	Policies             []Policy             `json:"policies"`
	SubCaProvider        SubCaProvider        `json:"subCaProvider"`
}

type Policy struct {
	ID                string       `json:"id"`
	CompanyID         string       `json:"companyId"`
	Name              string       `json:"name"`
	ValidityPeriod    string       `json:"validityPeriod"`
	Subject           Subject      `json:"subject"`
	SANs              SANs         `json:"sans"`
	KeyUsages         []string     `json:"keyUsages"`
	ExtendedKeyUsages []string     `json:"extendedKeyUsages"`
	KeyAlgorithm      KeyAlgorithm `json:"keyAlgorithm"`
	CreationDate      string       `json:"creationDate"`
	ModificationDate  string       `json:"modificationDate"`
}

type KeyAlgorithm struct {
	AllowedValues []string `json:"allowedValues"`
	DefaultValue  string   `json:"defaultValue"`
}

type SANs struct {
	DNSNames                   CommonName `json:"dnsNames"`
	IPAddresses                CommonName `json:"ipAddresses"`
	RFC822Names                CommonName `json:"rfc822Names"`
	UniformResourceIdentifiers CommonName `json:"uniformResourceIdentifiers"`
}

type CommonName struct {
	Type           string   `json:"type"`
	AllowedValues  []string `json:"allowedValues"`
	DefaultValues  []string `json:"defaultValues"`
	MinOccurrences int      `json:"minOccurrences"`
	MaxOccurrences int      `json:"maxOccurrences"`
}

type SubCaProvider struct {
	ID                 string `json:"id"`
	CompanyID          string `json:"companyId"`
	Name               string `json:"name"`
	CaType             string `json:"caType"`
	CaAccountID        string `json:"caAccountId"`
	CaProductOptionID  string `json:"caProductOptionId"`
	ValidityPeriod     string `json:"validityPeriod"`
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	Country            string `json:"country"`
	Locality           string `json:"locality"`
	OrganizationalUnit string `json:"organizationalUnit"`
	StateOrProvince    string `json:"stateOrProvince"`
	KeyAlgorithm       string `json:"keyAlgorithm"`
	PKCS11             PKCS11 `json:"pkcs11"`
	CreationDate       string `json:"creationDate"`
	ModificationDate   string `json:"modificationDate"`
}

type PKCS11 struct {
	AllowedClientLibraries []string `json:"allowedClientLibraries"`
	PartitionLabel         string   `json:"partitionLabel"`
	PartitionSerialNumber  string   `json:"partitionSerialNumber"`
	PIN                    string   `json:"pin"`
	SigningEnabled         bool     `json:"signingEnabled"`
}

// For now we aren't yet using ~/.config/vcpctl.yml.
type ToolConf struct {
	APIURL string `json:"apiURL"`
	APIKey string `json:"apiKey"`
}

func getToolConfig() (ToolConf, error) {
	token := os.Getenv("APIKEY")
	if token == "" {
		return ToolConf{}, fmt.Errorf("APIKEY environment variable not set")
	}

	return ToolConf{
		APIURL: "https://api.venafi.cloud",
		APIKey: token,
	}, nil
}

// New cobra command for ls
func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List the Firefly Configurations present in Venafi Control Plane.",
		Long: undent.Undent(`
			List the Firefly Configurations present in Venafi Control Plane.
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Note: The following functions (GetTokenUsingFileConf and listObjects)
			// should be implemented according to your needs.
			conf, err := getToolConfig()
			if err != nil {
				return fmt.Errorf("ls: while getting config %w", err)
			}

			names, err := listConfigs(conf.APIURL, conf.APIKey)
			if err != nil {
				return fmt.Errorf("ls: while listing configurations: %w", err)
			}

			for _, name := range names {
				fmt.Println(name)
			}

			return nil
		},
	}
}

func setServiceAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set-service-account",
		Short: "Set a Service Account for a given Firefly Configuration.",
		Long: undent.Undent(`
			Set a Service Account for a given Firefly Configuration.
			Example:
			  vcpctl set-service-account my-config "Service Account Name"
		`),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("set-service-account: expected 2 arguments, got %d", len(args))
			}
			confName := args[0]
			saName := args[1]

			conf, err := getToolConfig()
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
	confID, err := getConfigID(apiURL, apiKey, confName)
	if err != nil {
		return fmt.Errorf("while fetching Firefly configuration ID for the configuration '%s': %w", confName, err)
	}

	config, err := getConfig(apiURL, apiKey, confID)
	if err != nil {
		return fmt.Errorf("while fetching Firefly configuration '%s': %w", confName, err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	var sa *ServiceAccount
	for _, knownSa := range knownSvcaccts {
		if knownSa.Name == saName {
			if sa != nil {
				return fmt.Errorf("service account %q is ambiguous, please use a UID instead", saName)
			}
			sa = &knownSa
		}
	}
	if sa == nil {
		return fmt.Errorf("service account %q not found", saName)
	}

	// Is this SA already in the configuration?
	if slices.Contains(config.ServiceAccountIDs, sa.ID) {
		fmt.Fprintf(os.Stderr, "Service account '%s' is already in the configuration '%s', doing nothing.\n", sa.Name, config.Name)
		return nil
	}

	// Add the service account to the configuration.
	config.ServiceAccountIDs = append(config.ServiceAccountIDs, sa.ID)
	patch := fullToPatch(config)
	err = patchConfig(apiURL, apiKey, confID, *patch)
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
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("edit: expected 1 argument, got %d", len(args))
			}

			conf, err := getToolConfig()
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

// Replace the old flag-based main() with cobra execution.
func main() {
	rootCmd := &cobra.Command{
		Use:           "vcpctl",
		Short:         "A CLI tool for Venafi configurations",
		SilenceErrors: true,
		SilenceUsage:  true,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	rootCmd.AddCommand(lsCmd(), editCmd(), setServiceAccountCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listConfigs(apiURL, apiKey string) ([]string, error) {
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
			Name string `json:"name"`
		} `json:"configurations"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("/v1/distributedissuers/configurations: while decoding response: %w", err)
	}

	var names []string
	for _, conf := range result.Configurations {
		names = append(names, conf.Name)
	}
	return names, nil
}

func getConfigID(apiURL, apiKey, name string) (string, error) {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("tppl-api-key", apiKey)
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Configurations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"configurations"`
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return "", fmt.Errorf("while reading configurations: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("returned status code %s, body: %s", resp.Status, body.String())
	}

	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		return "", fmt.Errorf("while decoding configurations: %w, body: %s", err, body.String())
	}

	for _, conf := range result.Configurations {
		if conf.Name == name {
			return conf.ID, nil
		}
	}

	return "", fmt.Errorf("configuration %q not found", name)
}

func getConfig(apiURL, apiKey, id string) (*FireflyConfig, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/distributedissuers/configurations/%s", apiURL, id), nil)
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

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("returned status code %s, body: %s", resp.Status, body)
	}

	var fireflyConfig FireflyConfig
	if err := json.NewDecoder(resp.Body).Decode(&fireflyConfig); err != nil {
		return nil, err
	}

	return &fireflyConfig, nil
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
type FireflyConfigPatch struct {
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	ServiceAccountIDs    []string             `json:"serviceAccountIds"`
	PolicyIDs            []string             `json:"policyIds"`
	SubCaProviderID      string               `json:"subCaProviderId"`
}

func fullToPatch(full *FireflyConfig) *FireflyConfigPatch {
	policyIDs := make([]string, len(full.Policies))
	for i, p := range full.Policies {
		policyIDs[i] = p.ID
	}

	return &FireflyConfigPatch{
		Name:                 full.Name,
		ClientAuthentication: full.ClientAuthentication,
		ClientAuthorization:  full.ClientAuthorization,
		CloudProviders:       full.CloudProviders,
		MinTLSVersion:        full.MinTLSVersion,
		ServiceAccountIDs:    full.ServiceAccountIDs,
		PolicyIDs:            policyIDs,
		SubCaProviderID:      full.SubCaProvider.ID,
	}
}

func editConfig(apiURL, apiKey, name string) error {
	// Get configuration ID by name.
	id, err := getConfigID(apiURL, apiKey, name)
	if err != nil {
		return fmt.Errorf("while fetching Firefly configuration ID for the configuration '%s': %w", name, err)
	}

	// Get full configuration
	config, err := getConfig(apiURL, apiKey, id)
	if err != nil {
		return fmt.Errorf("while fetching Firefly configuration '%s': %w", name, err)
	}

	// Find service accounts.
	knownSvcaccts, err := getServiceAccounts(apiURL, apiKey)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	var comments = make(map[string][]*yaml.Comment)
	for i, sa := range config.ServiceAccountIDs {
		found := false
		for _, knownSa := range knownSvcaccts {
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

	// Convert to YAML so that it is easier to edit.
	yamlData, err := yaml.MarshalWithOptions(config, yaml.WithComment(comments))
	if err != nil {
		return err
	}
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
	var modified FireflyConfig
	if err := yaml.Unmarshal(modifiedRaw, &modified); err != nil {
		return err
	}

	patch := fullToPatch(&modified)
	err = patchConfig(apiURL, apiKey, id, *patch)
	if err != nil {
		return fmt.Errorf("while patching Firefly configuration: %w", err)
	}

	// The `subCaProvider.pkcs11.pin` field is never returned by the API, so we
	// need to check if the user has changed it and patch it separately. If the
	// user still wants to patch the subCAProvider, we need to ask them to
	// re-edit the manifest to fill in the pin.
	//
	// First off, let's check if the user has changed something under the
	// `subCaProvider`.
	d := cmp.Diff(config.SubCaProvider, modified.SubCaProvider)
	if d != "" {
		if modified.SubCaProvider.PKCS11.PIN == "" {
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
		var patchSub *SubCaProviderPatch
		if modified.SubCaProvider.ID != "" {
			patchSub = fullToPatchCAProvider(&modified.SubCaProvider)
			err = patchSubCaProvider(apiURL, apiKey, modified.SubCaProvider.ID, *patchSub)
			if err != nil {
				return fmt.Errorf("while patching Firefly configuration's subCAProvider %q: %w", modified.SubCaProvider.Name, err)
			}
		}
	}

	for _, p := range modified.Policies {
		patch := fullToPatchPolicy(&p)
		err = patchPolicy(apiURL, apiKey, p.ID, *patch)
		if err != nil {
			return fmt.Errorf("while patching Firefly configuration's policy %q: %w", p.Name, err)
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s: %s", resp.Status, body)
	}
	return nil
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
	PKCS11             PKCS11 `json:"pkcs11"`
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s: %s", resp.Status, body)
	}
	return nil
}

func fullToPatchCAProvider(full *SubCaProvider) *SubCaProviderPatch {
	return &SubCaProviderPatch{
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
	CommonName         CommonName `json:"commonName"`
	Country            CommonName `json:"country"`
	Locality           CommonName `json:"locality"`
	Organization       CommonName `json:"organization"`
	OrganizationalUnit CommonName `json:"organizationalUnit"`
	StateOrProvince    CommonName `json:"stateOrProvince"`
}

func fullToPatchPolicy(full *Policy) *PolicyPatch {
	return &PolicyPatch{
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s: %s", resp.Status, body)
	}

	return nil
}

type ServiceAccount struct {
	AuthenticationType    string    `json:"authenticationType"`
	CompanyID             string    `json:"companyId"`
	CredentialLifetime    int       `json:"credentialLifetime"`
	CredentialsExpiringOn time.Time `json:"credentialsExpiringOn"`
	Enabled               bool      `json:"enabled"`
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Owner                 string    `json:"owner"`
	Scopes                []string  `json:"scopes"`
	UpdatedBy             string    `json:"updatedBy"`
	UpdatedOn             time.Time `json:"updatedOn"`
	Applications          []string  `json:"applications"`
	Audience              string    `json:"audience"`
	IssuerURL             string    `json:"issuerURL"`
	JwksURI               string    `json:"jwksURI"`
	Subject               string    `json:"subject"`
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

	if resp.StatusCode != http.StatusOK {
		// Dump body.
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("returned status code %s, body: %s", resp.Status, body)
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("while reading service accounts: %w", err)
	}

	var result []ServiceAccount
	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("while decoding service accounts: %w\n\nBody: %s", err, body.String())
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

func fullServiceAccountToPatch(sa *ServiceAccount) *ServiceAccountPatch {
	return &ServiceAccountPatch{
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
	}
}

func patchServiceAccount(apiURL, apiKey, id string, patch ServiceAccountPatch) error {
	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v1/serviceaccounts/%s", apiURL, id), bytes.NewReader(patchJSON))
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

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update failed: %s: %s", resp.Status, body)
	}

	return nil
}
