package manifest

type Config struct {
	Name                 string               `json:"name" yaml:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty" yaml:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty" yaml:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders" yaml:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion" yaml:"minTlsVersion"`
	Policies             []Policy             `json:"policies,omitempty" yaml:"policies,omitempty"`
	SubCaProviderName    string               `json:"subCaProvider" yaml:"subCaProvider"`
	AdvancedSettings     AdvancedSettings     `json:"advancedSettings,omitempty" yaml:"advancedSettings,omitempty"`
	ServiceAccounts      []ServiceAccount     `json:"serviceAccounts,omitempty" yaml:"serviceAccounts,omitempty"`

	// SubCaProvider holds the manifest referenced by SubCaProviderName
	// after manifests have been parsed. It is not serialized back to YAML.
	SubCaProvider SubCa `json:"-" yaml:"-"`
}

type ClientAuthentication struct {
	Type     string                       `json:"type" yaml:"type"`
	URLs     []string                     `json:"urls,omitempty" yaml:"urls,omitempty"`
	Audience string                       `json:"audience,omitempty" yaml:"audience,omitempty"`
	BaseURL  string                       `json:"baseUrl,omitempty" yaml:"baseUrl,omitempty"`
	Clients  []ClientAuthenticationClient `json:"clients,omitempty" yaml:"clients,omitempty"`
}

type ClientAuthenticationClient struct {
	Name            string   `json:"name,omitempty" yaml:"name,omitempty"`
	Issuer          string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	JwksURI         string   `json:"jwksURI,omitempty" yaml:"jwksURI,omitempty"`
	Subjects        []string `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	AllowedPolicies []string `json:"allowedPolicies,omitempty" yaml:"allowedPolicies,omitempty"`
}

type CustomClaimsAliases struct {
	Configuration    string `json:"configuration" yaml:"configuration"`
	AllowAllPolicies string `json:"allowAllPolicies" yaml:"allowAllPolicies"`
	AllowedPolicies  string `json:"allowedPolicies" yaml:"allowedPolicies"`
}

type ClientAuthorization struct {
	CustomClaimsAliases CustomClaimsAliases `json:"customClaimsAliases" yaml:"customClaimsAliases"`
}

type Policy struct {
	Name              string       `json:"name" yaml:"name"`
	ValidityPeriod    string       `json:"validityPeriod" yaml:"validityPeriod"`
	Subject           Subject      `json:"subject" yaml:"subject"`
	SANs              SANs         `json:"sans" yaml:"sans"`
	KeyUsages         []string     `json:"keyUsages" yaml:"keyUsages"`
	ExtendedKeyUsages []string     `json:"extendedKeyUsages" yaml:"extendedKeyUsages"`
	KeyAlgorithm      KeyAlgorithm `json:"keyAlgorithm" yaml:"keyAlgorithm"`
}

type KeyAlgorithm struct {
	AllowedValues []string `json:"allowedValues" yaml:"allowedValues"`
	DefaultValue  string   `json:"defaultValue" yaml:"defaultValue"`
}

type SANs struct {
	DNSNames                   CommonName `json:"dnsNames" yaml:"dnsNames,flow"`
	IPAddresses                CommonName `json:"ipAddresses" yaml:"ipAddresses,flow"`
	RFC822Names                CommonName `json:"rfc822Names" yaml:"rfc822Names,flow"`
	UniformResourceIdentifiers CommonName `json:"uniformResourceIdentifiers" yaml:"uniformResourceIdentifiers,flow"`
}

type CommonName struct {
	Type           string   `json:"type" yaml:"type"`
	AllowedValues  []string `json:"allowedValues" yaml:"allowedValues"`
	DefaultValues  []string `json:"defaultValues" yaml:"defaultValues"`
	MinOccurrences int      `json:"minOccurrences" yaml:"minOccurrences"`
	MaxOccurrences int      `json:"maxOccurrences" yaml:"maxOccurrences"`
}

type Subject struct {
	CommonName         CommonName `json:"commonName" yaml:"commonName,flow"`
	Country            CommonName `json:"country" yaml:"country,flow"`
	Locality           CommonName `json:"locality" yaml:"locality,flow"`
	Organization       CommonName `json:"organization" yaml:"organization,flow"`
	OrganizationalUnit CommonName `json:"organizationalUnit" yaml:"organizationalUnit,flow"`
	StateOrProvince    CommonName `json:"stateOrProvince" yaml:"stateOrProvince,flow"`
}

type SubCa struct {
	Name               string `json:"name" yaml:"name"`
	CaType             string `json:"caType" yaml:"caType"`
	CaAccountID        string `json:"caAccountId" yaml:"caAccountId,omitempty"`
	CaProductOptionID  string `json:"caProductOptionId" yaml:"caProductOptionId,omitempty"`
	ValidityPeriod     string `json:"validityPeriod" yaml:"validityPeriod"`
	CommonName         string `json:"commonName" yaml:"commonName"`
	Organization       string `json:"organization" yaml:"organization"`
	Country            string `json:"country" yaml:"country"`
	Locality           string `json:"locality" yaml:"locality"`
	OrganizationalUnit string `json:"organizationalUnit" yaml:"organizationalUnit"`
	StateOrProvince    string `json:"stateOrProvince" yaml:"stateOrProvince"`
	KeyAlgorithm       string `json:"keyAlgorithm" yaml:"keyAlgorithm"`
	PKCS11             PKCS11 `json:"pkcs11" yaml:"pkcs11"`
}

type PKCS11 struct {
	AllowedClientLibraries []string `json:"allowedClientLibraries" yaml:"allowedClientLibraries"`
	PartitionLabel         string   `json:"partitionLabel" yaml:"partitionLabel"`
	PartitionSerialNumber  string   `json:"partitionSerialNumber" yaml:"partitionSerialNumber"`
	PIN                    string   `json:"pin" yaml:"pin"`
	SigningEnabled         bool     `json:"signingEnabled" yaml:"signingEnabled"`
}

type AdvancedSettings struct {
	EnableIssuanceAuditLog       bool `json:"enableIssuanceAuditLog" yaml:"enableIssuanceAuditLog"`
	IncludeRawCertDataInAuditLog bool `json:"includeRawCertDataInAuditLog" yaml:"includeRawCertDataInAuditLog"`
	RequireFIPSCompliantBuild    bool `json:"requireFIPSCompliantBuild" yaml:"requireFIPSCompliantBuild"`
}

type ServiceAccount struct {
	AuthenticationType string   `json:"authenticationType,omitempty" yaml:"authenticationType,omitempty"`
	CredentialLifetime int      `json:"credentialLifetime,omitempty" yaml:"credentialLifetime,omitempty"`
	Enabled            bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Name               string   `json:"name,omitempty" yaml:"name,omitempty"`
	Owner              string   `json:"owner,omitempty" yaml:"owner,omitempty"`
	Scopes             []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Applications       []string `json:"applications,omitempty" yaml:"applications,omitempty"`
	Audience           string   `json:"audience,omitempty" yaml:"audience,omitempty"`
	IssuerURL          string   `json:"issuerURL,omitempty" yaml:"issuerURL,omitempty"`
	JwksURI            string   `json:"jwksURI,omitempty" yaml:"jwksURI,omitempty"`
	Subject            string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	PublicKey          string   `json:"publicKey,omitempty" yaml:"publicKey,omitempty"`
}
