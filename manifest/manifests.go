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
	DNSNames                   Property `yaml:"dnsNames,flow"`
	IPAddresses                Property `yaml:"ipAddresses,flow"`
	RFC822Names                Property `yaml:"rfc822Names,flow"`
	UniformResourceIdentifiers Property `yaml:"uniformResourceIdentifiers,flow"`
}

// Since the zero value for the `PropertyInformation` struct in the generated
// code is not a valid value (`type` must be set), we can keep `minOccurrences`
// and `maxOccurrences` marked as omitzero since they are optional. When
// missing, they are treated as 0 by the API as far I could tell (POST and PATCH
// equally).
type Property struct {
	Type           string   `yaml:"type"`
	AllowedValues  []string `yaml:"allowedValues"`
	DefaultValues  []string `yaml:"defaultValues"`
	MinOccurrences int32    `yaml:"minOccurrences"`
	MaxOccurrences int32    `yaml:"maxOccurrences"`
}

type Subject struct {
	CommonName         Property `yaml:"commonName,flow"`
	Country            Property `yaml:"country,flow"`
	Locality           Property `yaml:"locality,flow"`
	Organization       Property `yaml:"organization,flow"`
	OrganizationalUnit Property `yaml:"organizationalUnit,flow"`
	StateOrProvince    Property `yaml:"stateOrProvince,flow"`
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

	// No need for a pointer here, see the AdvancedSettings explanation.
	SigningEnabled bool `yaml:"signingEnabled"`
}

// For PATCH operations, these booleans must not be omitted when explicitly
// setting them to false, and the only way to do that is to use a pointer.
// Otherwise, it would be impossible to change them from true to false.
//
// In the following diagram, "API object" refers to the generated Go struct
// `PropertyInformation`:
//
//	                   conversion
//	Read YAML Manifest  -------->   API object (desired)
//	Read API            -------->   API object (existing)
//	                                    |
//	                                    | diffToPatch
//	                                    v
//	                                API object
//	                                 (patch)
//
// These three API objects use the same Go struct; the only one of them that
// needs to contain the pointer is the patch one... but since one of them needs
// the pointer, we are forced to have that pointer for the "desired" and
// "existing" objects as well.
//
// You can see that the YAML manifest doesn't actually need the pointer since
// "desired" doesn't need to know whether the value was omitted or explicitly
// set to false; the intention of the user is guessed in diffToPatch.
type AdvancedSettings struct {
	EnableIssuanceAuditLog       bool `yaml:"enableIssuanceAuditLog"`
	IncludeRawCertDataInAuditLog bool `yaml:"includeRawCertDataInAuditLog"`
	RequireFIPSCompliantBuild    bool `yaml:"requireFIPSCompliantBuild"`
}

type ServiceAccount struct {
	Name               string `yaml:"name,omitempty"`
	AuthenticationType string `yaml:"authenticationType,omitempty"`
	CredentialLifetime int    `yaml:"credentialLifetime,omitempty"`

	// No need for a pointer here, see the AdvancedSettings explanation.
	Enabled      bool     `yaml:"enabled,omitempty"`
	Owner        string   `yaml:"owner,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
	Applications []string `yaml:"applications,omitempty"`
	Audience     string   `yaml:"audience,omitempty"`
	IssuerURL    string   `yaml:"issuerURL,omitempty"`
	JwksURI      string   `yaml:"jwksURI,omitempty"`
	Subject      string   `yaml:"subject,omitempty"`
	PublicKey    string   `yaml:"publicKey,omitempty"`
}
