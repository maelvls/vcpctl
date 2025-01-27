package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
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
	ID                   string                 `json:"id"`
	CompanyID            string                 `json:"companyId"`
	Name                 string                 `json:"name"`
	ClientAuthentication ClientAuthentication   `json:"clientAuthentication"`
	ClientAuthorization  ClientAuthorization    `json:"clientAuthorization"`
	CloudProviders       map[string]interface{} `json:"cloudProviders"`
	MinTLSVersion        string                 `json:"minTlsVersion"`
	ServiceAccountIDs    []string               `json:"serviceAccountIds"`
	Policies             []Policy               `json:"policies"`
	SubCaProvider        SubCaProvider          `json:"subCaProvider"`
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

func main() {
	apiURL := os.Getenv("APIURL")
	if apiURL == "" {
		apiURL = "https://api.venafi.cloud"
	}

	apiKey := os.Getenv("APIKEY")
	if apiKey == "" {
		fmt.Println("APIKEY needs to be set in the environment")
		os.Exit(1)
	}

	lsCmd := flag.NewFlagSet("ls", flag.ExitOnError)
	editCmd := flag.NewFlagSet("edit", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("Expected 'ls' or 'edit' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "ls":
		lsCmd.Parse(os.Args[2:])
		if err := listConfigs(apiURL, apiKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "edit":
		editCmd.Parse(os.Args[2:])
		if editCmd.NArg() < 1 {
			fmt.Println("Expected configuration name")
			os.Exit(1)
		}
		if err := editConfig(apiURL, apiKey, editCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func listConfigs(apiURL, apiKey string) error {
	req, err := http.NewRequest("GET", apiURL+"/v1/distributedissuers/configurations", nil)
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

	var result struct {
		Configurations []struct {
			Name string `json:"name"`
		} `json:"configurations"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	for _, conf := range result.Configurations {
		fmt.Println(conf.Name)
	}
	return nil
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

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
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

	var config FireflyConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
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
	Name                 string                 `json:"name"`
	ClientAuthentication ClientAuthentication   `json:"clientAuthentication"`
	ClientAuthorization  ClientAuthorization    `json:"clientAuthorization"`
	CloudProviders       map[string]interface{} `json:"cloudProviders"`
	MinTLSVersion        string                 `json:"minTlsVersion"`
	ServiceAccountIDs    []string               `json:"serviceAccountIds"`
	PolicyIDs            []string               `json:"policyIds"`
	SubCaProviderID      string                 `json:"subCaProviderId"`
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
	// Get configuration ID by name
	id, err := getConfigID(apiURL, apiKey, name)
	if err != nil {
		return err
	}

	// Get full configuration
	config, err := getConfig(apiURL, apiKey, id)
	if err != nil {
		return err
	}

	// Convert to YAML so that it is easier to edit.
	yamlData, err := yaml.Marshal(config)
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
	modifiedYAML, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		return err
	}
	var modified FireflyConfig
	if err := yaml.Unmarshal(modifiedYAML, &modified); err != nil {
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
			_, err = tmpfile.Write(append([]byte(notice), modifiedYAML...))
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
