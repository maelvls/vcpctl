package manifest

import "github.com/maelvls/vcpctl/api"

type Manifest struct {
	*WIMConfiguration
	*ServiceAccount
	*Policy
	*SubCa
}

type WIMConfiguration struct {
	Name                 string                        `yaml:"name"`
	ClientAuthentication ClientAuthentication          `yaml:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization           `yaml:"clientAuthorization,omitempty"`
	CloudProviders       api.CloudProvidersInformation `yaml:"cloudProviders"`
	MinTLSVersion        string                        `yaml:"minTlsVersion"`
	AdvancedSettings     AdvancedSettings              `yaml:"advancedSettings,omitempty"`

	PolicyNames         []string `yaml:"policyNames,omitempty"` // Doesn't existing in the API.
	SubCaProviderName   string   `yaml:"subCaProviderName"`     // Doesn't existing in the API.
	ServiceAccountNames []string `yaml:"serviceAccountNames"`   // Doesn't existing in the API.
}

type ClientAuthentication struct {
	Type     string                       `yaml:"type"`
	URLs     []string                     `yaml:"urls,omitempty"`
	Audience string                       `yaml:"audience,omitempty"`
	BaseURL  string                       `yaml:"baseUrl,omitempty"`
	Clients  []ClientAuthenticationClient `yaml:"clients,omitempty"`
}

type ClientAuthenticationClient struct {
	Name            string   `yaml:"name,omitempty"`
	Issuer          string   `yaml:"issuer,omitempty"`
	JwksURI         string   `yaml:"jwksURI,omitempty"`
	Subjects        []string `yaml:"subjects,omitempty"`
	AllowedPolicies []string `yaml:"allowedPolicies,omitempty"`
}

type CustomClaimsAliases struct {
	Configuration    string `yaml:"configuration"`
	AllowAllPolicies string `yaml:"allowAllPolicies"`
	AllowedPolicies  string `yaml:"allowedPolicies"`
}

type ClientAuthorization struct {
	CustomClaimsAliases CustomClaimsAliases `yaml:"customClaimsAliases"`
}

type Policy struct {
	Name              string       `yaml:"name"`
	ValidityPeriod    string       `yaml:"validityPeriod"`
	Subject           Subject      `yaml:"subject"`
	SANs              SANs         `yaml:"sans"`
	KeyUsages         []string     `yaml:"keyUsages"`
	ExtendedKeyUsages []string     `yaml:"extendedKeyUsages"`
	KeyAlgorithm      KeyAlgorithm `yaml:"keyAlgorithm"`
}

type KeyAlgorithm struct {
	AllowedValues []string `yaml:"allowedValues"`
	DefaultValue  string   `yaml:"defaultValue"`
}

type SANs struct {
	DNSNames                   CommonName `yaml:"dnsNames,flow"`
	IPAddresses                CommonName `yaml:"ipAddresses,flow"`
	RFC822Names                CommonName `yaml:"rfc822Names,flow"`
	UniformResourceIdentifiers CommonName `yaml:"uniformResourceIdentifiers,flow"`
}

type CommonName struct {
	Type           string   `yaml:"type"`
	AllowedValues  []string `yaml:"allowedValues"`
	DefaultValues  []string `yaml:"defaultValues"`
	MinOccurrences int32    `yaml:"minOccurrences"`
	MaxOccurrences int32    `yaml:"maxOccurrences"`
}

type Subject struct {
	CommonName         CommonName `yaml:"commonName,flow"`
	Country            CommonName `yaml:"country,flow"`
	Locality           CommonName `yaml:"locality,flow"`
	Organization       CommonName `yaml:"organization,flow"`
	OrganizationalUnit CommonName `yaml:"organizationalUnit,flow"`
	StateOrProvince    CommonName `yaml:"stateOrProvince,flow"`
}

type SubCa struct {
	Name                string `yaml:"name"`
	IssuingTemplateName string `yaml:"issuingTemplateName,omitempty"`

	ValidityPeriod     string `yaml:"validityPeriod"`
	CommonName         string `yaml:"commonName"`
	Organization       string `yaml:"organization"`
	Country            string `yaml:"country"`
	Locality           string `yaml:"locality"`
	OrganizationalUnit string `yaml:"organizationalUnit"`
	StateOrProvince    string `yaml:"stateOrProvince"`
	KeyAlgorithm       string `yaml:"keyAlgorithm"`
	PKCS11             PKCS11 `yaml:"pkcs11"`
}

type PKCS11 struct {
	AllowedClientLibraries []string `yaml:"allowedClientLibraries"`
	PartitionLabel         string   `yaml:"partitionLabel"`
	PartitionSerialNumber  string   `yaml:"partitionSerialNumber"`
	PIN                    string   `yaml:"pin"`
	SigningEnabled         *bool    `yaml:"signingEnabled"`
}

// Since "false" is a valid value and there needs to be a way to tell between
// "false" and "not set" in order to update the API object, we use pointers.
// Otherwise, it would be impossible to disable these settings once they have
// been enabled.
type AdvancedSettings struct {
	EnableIssuanceAuditLog       *bool `yaml:"enableIssuanceAuditLog"`
	IncludeRawCertDataInAuditLog *bool `yaml:"includeRawCertDataInAuditLog"`
	RequireFIPSCompliantBuild    *bool `yaml:"requireFIPSCompliantBuild"`
}

type ServiceAccount struct {
	Name               string   `yaml:"name,omitempty"`
	AuthenticationType string   `yaml:"authenticationType,omitempty"`
	CredentialLifetime int      `yaml:"credentialLifetime,omitempty"`
	Enabled            *bool    `yaml:"enabled,omitempty"`
	Owner              string   `yaml:"owner,omitempty"`
	Scopes             []string `yaml:"scopes,omitempty"`
	Applications       []string `yaml:"applications,omitempty"`
	Audience           string   `yaml:"audience,omitempty"`
	IssuerURL          string   `yaml:"issuerURL,omitempty"`
	JwksURI            string   `yaml:"jwksURI,omitempty"`
	Subject            string   `yaml:"subject,omitempty"`
	PublicKey          string   `yaml:"publicKey,omitempty"`
}
