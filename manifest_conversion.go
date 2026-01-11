package main

import (
	api "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

func namesFrom[T any](items []T, nameFunc func(T) string) []string {
	if len(items) == 0 {
		return nil
	}
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = nameFunc(item)
	}
	return result
}

// manifestToAPIClientAuthentication converts manifest ClientAuthentication to API union type.
// ClientAuthenticationInformation is a union type, so we use JSON marshaling to handle it.
func manifestToAPIClientAuthentication(in manifest.ClientAuthentication) api.ClientAuthenticationInformation {
	// ClientAuthenticationInformation is a union type with only Type and union json.RawMessage.
	// For now, we create a minimal structure. The actual union handling would require
	// JSON marshaling/unmarshaling based on the Type field.
	// TODO: Implement proper union type handling if ClientAuthentication is actually used.
	return api.ClientAuthenticationInformation{
		Type: in.Type,
		// union field is json.RawMessage and cannot be set directly
	}
}

// apiToManifestClientAuthentication converts API union type to manifest ClientAuthentication.
// ClientAuthenticationInformation is a union type, so we use JSON unmarshaling to handle it.
func apiToManifestClientAuthentication(in api.ClientAuthenticationInformation) manifest.ClientAuthentication {
	// ClientAuthenticationInformation is a union type with only Type and union json.RawMessage.
	// For now, we return a minimal structure. The actual union handling would require
	// JSON marshaling/unmarshaling based on the Type field.
	// TODO: Implement proper union type handling if ClientAuthentication is actually used.
	return manifest.ClientAuthentication{
		Type: in.Type,
		// Other fields cannot be extracted from union type without JSON unmarshaling
	}
}

// manifestToAPIClientAuthenticationClient is not used since ClientAuthenticationClient doesn't exist.
// This function is kept for compatibility but returns an empty union type.
func manifestToAPIClientAuthenticationClient(in manifest.ClientAuthenticationClient) api.ClientAuthenticationInformation {
	// ClientAuthenticationClient doesn't exist as a separate type in the API.
	// This is a placeholder that returns a minimal union type.
	return api.ClientAuthenticationInformation{
		Type: "", // Type would need to be determined from the client structure
	}
}

// apiToManifestClientAuthenticationClient is not used since ClientAuthenticationClient doesn't exist.
// This function is kept for compatibility but returns an empty structure.
func apiToManifestClientAuthenticationClient(in api.ClientAuthenticationInformation) manifest.ClientAuthenticationClient {
	// ClientAuthenticationClient doesn't exist as a separate type in the API.
	// This is a placeholder that returns an empty structure.
	return manifest.ClientAuthenticationClient{}
}

func manifestToAPIClientAuthorization(in manifest.ClientAuthorization) api.ClientAuthorizationInformation {
	return api.ClientAuthorizationInformation{
		CustomClaimsAliases: manifestToAPICustomClaimsAliases(in.CustomClaimsAliases),
	}
}

func apiToManifestClientAuthorization(in api.ClientAuthorizationInformation) manifest.ClientAuthorization {
	return manifest.ClientAuthorization{
		CustomClaimsAliases: apiToManifestCustomClaimsAliases(in.CustomClaimsAliases),
	}
}

func manifestToAPICustomClaimsAliases(in manifest.CustomClaimsAliases) api.CustomClaimsAliasesInformation {
	return api.CustomClaimsAliasesInformation{
		Configuration:    in.Configuration,
		AllowAllPolicies: in.AllowAllPolicies,
		AllowedPolicies:  in.AllowedPolicies,
	}
}

func apiToManifestCustomClaimsAliases(in api.CustomClaimsAliasesInformation) manifest.CustomClaimsAliases {
	return manifest.CustomClaimsAliases{
		Configuration:    in.Configuration,
		AllowAllPolicies: in.AllowAllPolicies,
		AllowedPolicies:  in.AllowedPolicies,
	}
}

func manifestPoliciesToAPI(policyNameToUUID func(string) (string, error), items []manifest.Policy) []api.PolicyCreateRequest {
	if len(items) == 0 {
		return nil
	}
	result := make([]api.PolicyCreateRequest, len(items))
	for i, item := range items {
		result[i] = manifestToAPIPolicy(item)
	}
	return result
}

func apiPoliciesToManifest(items []Policy) []manifest.Policy {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.Policy, len(items))
	for i, item := range items {
		result[i] = apiToManifestPolicy(item)
	}
	return result
}

func manifestToAPIPolicy(in manifest.Policy) api.PolicyCreateRequest {
	return api.PolicyCreateRequest{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           manifestToAPISubject(in.Subject),
		Sans:              manifestToAPISANs(in.SANs),
		KeyUsages:         manifestToAPIKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: manifestToAPIExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      manifestToAPIKeyAlgorithm(in.KeyAlgorithm),
	}
}

func apiToManifestPolicy(in Policy) manifest.Policy {
	return manifest.Policy{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           apiToManifestSubject(in.Subject),
		SANs:              apiToManifestSANs(in.Sans),
		KeyUsages:         apiToManifestKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: apiToManifestExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      apiToManifestKeyAlgorithm(in.KeyAlgorithm),
	}
}

func manifestToAPIKeyUsages(in []string) []api.PolicyCreateRequestKeyUsages {
	result := make([]api.PolicyCreateRequestKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.PolicyCreateRequestKeyUsages(v)
	}
	return result
}

func apiToManifestKeyUsages(in []api.ExtendedPolicyInformationKeyUsages) []string {
	result := make([]string, len(in))
	for i, v := range in {
		result[i] = string(v)
	}
	return result
}

func manifestToAPIExtendedKeyUsages(in []string) []api.PolicyCreateRequestExtendedKeyUsages {
	result := make([]api.PolicyCreateRequestExtendedKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.PolicyCreateRequestExtendedKeyUsages(v)
	}
	return result
}

func apiToManifestExtendedKeyUsages(in []api.ExtendedPolicyInformationExtendedKeyUsages) []string {
	result := make([]string, len(in))
	for i, v := range in {
		result[i] = string(v)
	}
	return result
}

func manifestToAPISubject(in manifest.Subject) api.SubjectAttributesInformation {
	return api.SubjectAttributesInformation{
		CommonName:         manifestToAPICommonName(in.CommonName),
		Country:            manifestToAPICommonName(in.Country),
		Locality:           manifestToAPICommonName(in.Locality),
		Organization:       manifestToAPICommonName(in.Organization),
		OrganizationalUnit: manifestToAPICommonName(in.OrganizationalUnit),
		StateOrProvince:    manifestToAPICommonName(in.StateOrProvince),
	}
}

func apiToManifestSubject(in api.SubjectAttributesInformation) manifest.Subject {
	return manifest.Subject{
		CommonName:         apiToManifestCommonName(in.CommonName),
		Country:            apiToManifestCommonName(in.Country),
		Locality:           apiToManifestCommonName(in.Locality),
		Organization:       apiToManifestCommonName(in.Organization),
		OrganizationalUnit: apiToManifestCommonName(in.OrganizationalUnit),
		StateOrProvince:    apiToManifestCommonName(in.StateOrProvince),
	}
}

func manifestToAPISANs(in manifest.SANs) api.SansInformation {
	return api.SansInformation{
		DnsNames:                   manifestToAPICommonName(in.DNSNames),
		IpAddresses:                manifestToAPICommonName(in.IPAddresses),
		Rfc822Names:                manifestToAPICommonName(in.RFC822Names),
		UniformResourceIdentifiers: manifestToAPICommonName(in.UniformResourceIdentifiers),
	}
}

func apiToManifestSANs(in api.SansInformation) manifest.SANs {
	return manifest.SANs{
		DNSNames:                   apiToManifestCommonName(in.DnsNames),
		IPAddresses:                apiToManifestCommonName(in.IpAddresses),
		RFC822Names:                apiToManifestCommonName(in.Rfc822Names),
		UniformResourceIdentifiers: apiToManifestCommonName(in.UniformResourceIdentifiers),
	}
}

func manifestToAPIKeyAlgorithm(in manifest.KeyAlgorithm) api.KeyAlgorithmInformation {
	allowedValues := make([]api.KeyAlgorithmInformationAllowedValues, len(in.AllowedValues))
	for i, v := range in.AllowedValues {
		allowedValues[i] = api.KeyAlgorithmInformationAllowedValues(v)
	}
	return api.KeyAlgorithmInformation{
		AllowedValues: allowedValues,
		DefaultValue:  api.KeyAlgorithmInformationDefaultValue(in.DefaultValue),
	}
}

func apiToManifestKeyAlgorithm(in api.KeyAlgorithmInformation) manifest.KeyAlgorithm {
	allowedValues := make([]string, len(in.AllowedValues))
	for i, v := range in.AllowedValues {
		allowedValues[i] = string(v)
	}
	return manifest.KeyAlgorithm{
		AllowedValues: allowedValues,
		DefaultValue:  string(in.DefaultValue),
	}
}

func manifestToAPICommonName(in manifest.CommonName) api.PropertyInformation {
	return api.PropertyInformation{
		Type:           api.PropertyInformationType(in.Type),
		AllowedValues:  append([]string(nil), in.AllowedValues...),
		DefaultValues:  append([]string(nil), in.DefaultValues...),
		MinOccurrences: int32(in.MinOccurrences),
		MaxOccurrences: int32(in.MaxOccurrences),
	}
}

func apiToManifestCommonName(in api.PropertyInformation) manifest.CommonName {
	return manifest.CommonName{
		Type:           string(in.Type),
		AllowedValues:  append([]string(nil), in.AllowedValues...),
		DefaultValues:  append([]string(nil), in.DefaultValues...),
		MinOccurrences: int(in.MinOccurrences),
		MaxOccurrences: int(in.MaxOccurrences),
	}
}

func manifestServiceAccountsToAPI(items []manifest.ServiceAccount) []ServiceAccount {
	if len(items) == 0 {
		return nil
	}
	result := make([]ServiceAccount, len(items))
	for i, item := range items {
		result[i] = manifestToAPIServiceAccount(item)
	}
	return result
}

func apiServiceAccountsToManifest(items []ServiceAccount) []manifest.ServiceAccount {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.ServiceAccount, len(items))
	for i, item := range items {
		result[i] = apiToManifestServiceAccount(item)
	}
	return result
}

func manifestToAPIServiceAccount(in manifest.ServiceAccount) ServiceAccount {
	ownerUUID := openapi_types.UUID{}
	_ = ownerUUID.UnmarshalText([]byte(in.Owner))

	applications := make([]api.Application, len(in.Applications))
	for i, app := range in.Applications {
		appUUID := openapi_types.UUID{}
		_ = appUUID.UnmarshalText([]byte(app))
		applications[i] = appUUID
	}

	return ServiceAccount{
		AuthenticationType: in.AuthenticationType,
		CredentialLifetime: in.CredentialLifetime,
		Enabled:            in.Enabled,
		Name:               in.Name,
		Owner:              ownerUUID,
		Scopes:             append([]string(nil), in.Scopes...),
		Applications:       applications,
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		JwksURI:            in.JwksURI,
		Subject:            in.Subject,
		PublicKey:          in.PublicKey,
	}
}

func apiToManifestServiceAccount(in ServiceAccount) manifest.ServiceAccount {
	applications := make([]string, len(in.Applications))
	for i, app := range in.Applications {
		applications[i] = app.String()
	}

	return manifest.ServiceAccount{
		AuthenticationType: in.AuthenticationType,
		CredentialLifetime: in.CredentialLifetime,
		Enabled:            in.Enabled,
		Name:               in.Name,
		Owner:              in.Owner.String(),
		Scopes:             append([]string(nil), in.Scopes...),
		Applications:       applications,
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		JwksURI:            in.JwksURI,
		Subject:            in.Subject,
		PublicKey:          in.PublicKey,
	}
}

func manifestToAPISubCa(in manifest.SubCa) SubCa {
	caAccountUUID := openapi_types.UUID{}
	_ = caAccountUUID.UnmarshalText([]byte(in.CaAccountID))
	caProductOptionUUID := openapi_types.UUID{}
	_ = caProductOptionUUID.UnmarshalText([]byte(in.CaProductOptionID))

	return SubCa{
		Name:               in.Name,
		CaType:             api.SubCaProviderInformationCaType(in.CaType),
		CaAccountId:        caAccountUUID,
		CaProductOptionId:  caProductOptionUUID,
		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       api.SubCaProviderInformationKeyAlgorithm(in.KeyAlgorithm),
		Pkcs11:             manifestToAPIPKCS11(in.PKCS11),
	}
}

func apiToManifestSubCa(in SubCa) manifest.SubCa {
	return manifest.SubCa{
		Name:               in.Name,
		CaType:             string(in.CaType),
		CaAccountID:        in.CaAccountId.String(),
		CaProductOptionID:  in.CaProductOptionId.String(),
		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       string(in.KeyAlgorithm),
		PKCS11:             apiToManifestPKCS11(in.Pkcs11),
	}
}

func manifestToAPIPKCS11(in manifest.PKCS11) PKCS11 {
	return PKCS11{
		AllowedClientLibraries: append([]string(nil), in.AllowedClientLibraries...),
		PartitionLabel:         in.PartitionLabel,
		PartitionSerialNumber:  in.PartitionSerialNumber,
		Pin:                    in.PIN,
		SigningEnabled:         in.SigningEnabled,
	}
}

func apiToManifestPKCS11(in PKCS11) manifest.PKCS11 {
	return manifest.PKCS11{
		AllowedClientLibraries: append([]string(nil), in.AllowedClientLibraries...),
		PartitionLabel:         in.PartitionLabel,
		PartitionSerialNumber:  in.PartitionSerialNumber,
		PIN:                    in.Pin,
		SigningEnabled:         in.SigningEnabled,
	}
}

func manifestToAPIAdvancedSettings(in manifest.AdvancedSettings) api.AdvancedSettingsInformation {
	return api.AdvancedSettingsInformation{
		EnableIssuanceAuditLog:       in.EnableIssuanceAuditLog,
		IncludeRawCertDataInAuditLog: in.IncludeRawCertDataInAuditLog,
		RequireFIPSCompliantBuild:    in.RequireFIPSCompliantBuild,
	}
}

func apiToManifestAdvancedSettings(in api.AdvancedSettingsInformation) manifest.AdvancedSettings {
	return manifest.AdvancedSettings{
		EnableIssuanceAuditLog:       in.EnableIssuanceAuditLog,
		IncludeRawCertDataInAuditLog: in.IncludeRawCertDataInAuditLog,
		RequireFIPSCompliantBuild:    in.RequireFIPSCompliantBuild,
	}
}

func copyStringAnyMap(in api.CloudProvidersInformation) api.CloudProvidersInformation {
	// For now, just return as-is since CloudProvidersInformation is already the correct type
	return in
}

func copyStringAnyMapFromMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}
