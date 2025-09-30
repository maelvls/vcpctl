package api

// Types representing the CyberArk Certificate Manager (Venafi Cloud) REST API
// payloads. These mirror the structures returned by the API and may include
// fields (such as IDs and timestamps) that should not leak into the user-facing
// manifest layer.

type ClientAuthentication struct {
	Type     string                       `json:"type"`
	URLs     []string                     `json:"urls,omitempty"`
	Audience string                       `json:"audience,omitempty"`
	BaseURL  string                       `json:"baseUrl,omitempty"`
	Clients  []ClientAuthenticationClient `json:"clients,omitempty"`
}

type ClientAuthenticationClient struct {
	Name     string   `json:"name,omitempty"`
	Issuer   string   `json:"issuer,omitempty"`
	JwksURI  string   `json:"jwksURI,omitempty"`
	Subjects []string `json:"subjects,omitempty"`

	// Returned by the API but hidden in manifests in favour of AllowedPolicies.
	AllowedPolicyIDs []string `json:"allowedPolicyIds,omitempty"`

	// Used only by higher layers to provide policy names.
	AllowedPolicies []string `json:"allowedPolicies,omitempty"`
}

type CustomClaimsAliases struct {
	Configuration    string `json:"configuration"`
	AllowAllPolicies string `json:"allowAllPolicies"`
	AllowedPolicies  string `json:"allowedPolicies"`
}

type ClientAuthorization struct {
	CustomClaimsAliases CustomClaimsAliases `json:"customClaimsAliases"`
}

type Config struct {
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	Policies             []Policy             `json:"policies"`
	SubCaProvider        SubCa                `json:"subCaProvider"`
	AdvancedSettings     AdvancedSettings     `json:"advancedSettings,omitempty"`

	ID                string   `json:"id,omitempty"`
	CreationDate      string   `json:"creationDate,omitempty"`
	ModificationDate  string   `json:"modificationDate,omitempty"`
	ServiceAccountIDs []string `json:"serviceAccountIds,omitempty"`

	ServiceAccounts []ServiceAccount `json:"serviceAccounts,omitempty"`
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

type SubCa struct {
	ID                 string `json:"id,omitempty"`
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
}

type PKCS11 struct {
	AllowedClientLibraries []string `json:"allowedClientLibraries"`
	PartitionLabel         string   `json:"partitionLabel"`
	PartitionSerialNumber  string   `json:"partitionSerialNumber"`
	PIN                    string   `json:"pin"`
	SigningEnabled         bool     `json:"signingEnabled"`
}

type AdvancedSettings struct {
	EnableIssuanceAuditLog       bool `json:"enableIssuanceAuditLog"`
	IncludeRawCertDataInAuditLog bool `json:"includeRawCertDataInAuditLog"`
	RequireFIPSCompliantBuild    bool `json:"requireFIPSCompliantBuild"`
}

type ConfigPatch struct {
	Name                 string               `json:"name"`
	ClientAuthentication ClientAuthentication `json:"clientAuthentication,omitempty"`
	ClientAuthorization  ClientAuthorization  `json:"clientAuthorization,omitempty"`
	CloudProviders       map[string]any       `json:"cloudProviders"`
	MinTLSVersion        string               `json:"minTlsVersion"`
	ServiceAccountIDs    []string             `json:"serviceAccountIds"`
	PolicyIDs            []string             `json:"policyIds"`
	SubCaProviderID      string               `json:"subCaProviderId"`
	AdvancedSettings     AdvancedSettings     `json:"advancedSettings,omitempty"`
}

type PolicyPatch struct {
	Name              string       `json:"name"`
	KeyAlgorithm      KeyAlgorithm `json:"keyAlgorithm"`
	KeyUsages         []string     `json:"keyUsages"`
	ExtendedKeyUsages []string     `json:"extendedKeyUsages"`
	SANs              SANs         `json:"sans"`
	Subject           Subject      `json:"subject"`
	ValidityPeriod    string       `json:"validityPeriod"`
}

type Subject struct {
	CommonName         CommonName `json:"commonName"`
	Country            CommonName `json:"country"`
	Locality           CommonName `json:"locality"`
	Organization       CommonName `json:"organization"`
	OrganizationalUnit CommonName `json:"organizationalUnit"`
	StateOrProvince    CommonName `json:"stateOrProvince"`
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

type SACreateResp struct {
	ID         string `json:"id"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

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

type CertificateIssuingTemplate struct {
	ID                                   string   `json:"id"`
	Name                                 string   `json:"name"`
	Description                          string   `json:"description"`
	CreationDate                         string   `json:"creationDate"`
	ModificationDate                     string   `json:"modificationDate"`
	Builtin                              bool     `json:"builtin"`
	CertificateAuthority                 string   `json:"certificateAuthority"`
	CertificateAuthorityAccountID        string   `json:"certificateAuthorityAccountId"`
	CertificateAuthorityProductOptionID  string   `json:"certificateAuthorityProductOptionId"`
	CertificateIssuingTemplateWorkflowID string   `json:"certificateIssuingTemplateWorkflowId"`
	CertificateIssuingTemplateResultID   string   `json:"certificateIssuingTemplateResultId"`
	CertificateIssuingTemplateStatus     string   `json:"certificateIssuingTemplateStatus"`
	EnrollmentLoose                      bool     `json:"enrollmentLoose"`
	GeneratedCSR                         bool     `json:"generatedCsr"`
	PolicyID                             string   `json:"policyId"`
	SystemGenerated                      bool     `json:"systemGenerated"`
	Tags                                 []string `json:"tags"`
}
