package main

import (
	"fmt"

	api "github.com/maelvls/vcpctl/api"
	manifest "github.com/maelvls/vcpctl/manifest"

	openapi_types "github.com/oapi-codegen/runtime/types"
)

func resolve[T any, V any](items []T, nameFunc func(T) (V, error)) ([]V, error) {
	if len(items) == 0 {
		return nil, nil
	}
	result := make([]V, len(items))
	for i, item := range items {
		var err error
		result[i], err = nameFunc(item)
		if err != nil {
			return nil, fmt.Errorf("namesFrom: while getting name for #%d: %w", i+1, err)
		}
	}
	return result, nil
}

// IMPORTANT: the 'policies', 'serviceAccounts' and 'subCaProvider' fields are
// not entirely set. Do not expect them to be there. Only the IDs are set:
//   - policyIds
//   - serviceAccountIds
//   - subCaProvider.Id
func manifestToAPIExtendedConfigurationInformation(
	resolvePolicy func(string) (api.ExtendedPolicyInformation, error),
	resolveSA func(string) (api.ServiceAccountDetails, error),
	resolveSubCaProvider func(string) (api.SubCaProviderInformation, error),
	in manifest.WIMConfiguration,
) (api.ExtendedConfigurationInformation, error) {
	policyIDs, err := resolve(in.PolicyNames, func(name string) (openapi_types.UUID, error) {
		policy, err := resolvePolicy(name)
		if err != nil {
			return openapi_types.UUID{}, err
		}
		return policy.Id, nil
	})
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("manifestToAPIExtendedConfigurationInformation: while resolving PolicyNames to PolicyIds: %w", err)
	}
	serviceAccountIDs, err := resolve(in.ServiceAccountNames, func(name string) (openapi_types.UUID, error) {
		sa, err := resolveSA(name)
		if err != nil {
			return openapi_types.UUID{}, err
		}
		return sa.Id, nil
	})
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("manifestToAPIExtendedConfigurationInformation: while resolving ServiceAccountNames to ServiceAccountIds: %w", err)
	}
	subCaProvider, err := resolveSubCaProvider(in.SubCaProviderName)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("manifestToAPIExtendedConfigurationInformation: while resolving SubCaProviderName to api.SubCaProviderInformation: %w", err)
	}

	clientAuthentication, err := manifestToAPIClientAuthentication(resolvePolicy, in.ClientAuthentication)
	if err != nil {
		return api.ExtendedConfigurationInformation{}, fmt.Errorf("manifestToAPIExtendedConfigurationInformation: while converting ClientAuthentication: %w", err)
	}

	return api.ExtendedConfigurationInformation{
		Name:                 in.Name,
		ClientAuthentication: clientAuthentication,
		ClientAuthorization:  manifestToAPIClientAuthorization(in.ClientAuthorization),
		CloudProviders:       copyStringAnyMap(in.CloudProviders),
		MinTlsVersion:        api.ExtendedConfigurationInformationMinTlsVersion(in.MinTLSVersion),
		PolicyIds:            policyIDs,
		ServiceAccountIds:    serviceAccountIDs,
		SubCaProvider:        api.SubCaProviderInformation{Id: subCaProvider.Id},
		AdvancedSettings:     manifestToAPIAdvancedSettings(in.AdvancedSettings),

		Id:                         openapi_types.UUID{}, // Not set.
		CompanyId:                  openapi_types.UUID{}, // Not set.
		Policies:                   nil,                  // Not set.
		PolicyDefinitions:          nil,                  // Not set.
		ControllerAllowedPolicyIds: nil,                  // Not set.
		UnixSocketAllowedPolicyIds: nil,                  // Not set.
		CreationDate:               "",                   // Not set.
		ModificationDate:           "",                   // Not set.
		LongLivedCertCount:         0,                    // Not set.
		ShortLivedCertCount:        0,
		UltraShortLivedCertCount:   0, // Not set.
	}, nil
}

func apiToManifestWIMConfiguration(resolveSA func(openapi_types.UUID) (api.ServiceAccountDetails, error), cfg api.ExtendedConfigurationInformation) (manifest.WIMConfiguration, error) {
	clientAuthentication, err := apiToManifestClientAuthentication(cfg.ClientAuthentication)
	if err != nil {
		return manifest.WIMConfiguration{}, fmt.Errorf("apiToManifestWIMConfiguration: while converting ClientAuthentication: %w", err)
	}

	serviceAccounts, err := resolve(cfg.ServiceAccountIds, resolveSA)
	if err != nil {
		return manifest.WIMConfiguration{}, fmt.Errorf("apiToManifestWIMConfiguration: while resolving ServiceAccounts from ServiceAccountIds: %w", err)
	}
	serviceAccountNames, err := resolve(serviceAccounts, func(sa api.ServiceAccountDetails) (string, error) {
		return sa.Name, nil
	})
	if err != nil {
		return manifest.WIMConfiguration{}, fmt.Errorf("apiToManifestWIMConfiguration: while resolving names from ServiceAccounts: %w", err)
	}

	policyNames, err := resolve(cfg.Policies, func(p api.PolicyInformation) (string, error) {
		return p.Name, nil
	})
	if err != nil {
		return manifest.WIMConfiguration{}, fmt.Errorf("apiToManifestWIMConfiguration: while getting policy names: %w", err)
	}

	return manifest.WIMConfiguration{
		Name:                 cfg.Name,
		ClientAuthentication: clientAuthentication,
		ClientAuthorization:  apiToManifestClientAuthorization(cfg.ClientAuthorization),
		CloudProviders:       cfg.CloudProviders,
		MinTLSVersion:        string(cfg.MinTlsVersion),
		PolicyNames:          policyNames,
		SubCaProviderName:    cfg.SubCaProvider.Name,
		AdvancedSettings:     apiToManifestAdvancedSettings(cfg.AdvancedSettings),
		ServiceAccountNames:  serviceAccountNames,
	}, nil
}

func apiToManifestClientAuthentication(in api.ClientAuthenticationInformation) (manifest.ClientAuthentication, error) {
	v, err := in.ValueByDiscriminator()
	if err != nil {
		return manifest.ClientAuthentication{}, fmt.Errorf("could not figure out what type the 'clientAuthentication' field is: %w", err)
	}
	switch val := v.(type) {
	case api.JwtJwksAuthenticationInformation:
		return manifest.ClientAuthentication{
			Type: "JWT_JWKS",
			URLs: val.Urls,
		}, nil
	case api.JwtStandardClaimsAuthenticationInformation:
		clients, err := apiToManifestJwtClientInformation(val.Clients)
		if err != nil {
			return manifest.ClientAuthentication{}, fmt.Errorf("while looking at 'clientAuthentication' of type=JWT_STANDARD_CLAIMS: %w", err)
		}
		return manifest.ClientAuthentication{
			Type:     "JWT_STANDARD_CLAIMS",
			Audience: val.Audience,
			Clients:  clients,
		}, nil
	case api.JwtOidcAuthenticationInformation:
		return manifest.ClientAuthentication{
			Type:     "JWT_OIDC",
			BaseURL:  val.BaseUrl,
			Audience: val.Audience,
		}, nil
	default:
		return manifest.ClientAuthentication{}, fmt.Errorf("apiToManifestClientAuthentication: unknown ClientAuthentication type")
	}
}

func apiToManifestJwtClientInformation(in []api.JwtClientInformation) ([]manifest.ClientAuthenticationClient, error) {
	var result []manifest.ClientAuthenticationClient
	for _, c := range in {
		var allowedPolicyNames []string
		for _, id := range c.AllowedPolicyIds {
			allowedPolicyNames = append(allowedPolicyNames, id.String())
		}
		result = append(result, manifest.ClientAuthenticationClient{
			Name:            c.Name,
			Issuer:          c.Issuer,
			JwksURI:         c.JwksUri,
			Subjects:        c.Subjects,
			AllowedPolicies: allowedPolicyNames,
		})
	}
	return result, nil
}

// manifestToAPIClientAuthentication converts manifest ClientAuthentication to API union type.
// ClientAuthenticationInformation is a union type, so we use JSON marshaling to handle it.
func manifestToAPIClientAuthentication(resolvePolicy func(string) (api.ExtendedPolicyInformation, error), in manifest.ClientAuthentication) (api.ClientAuthenticationInformation, error) {
	switch in.Type {
	case "JWT_JWKS":
		var result api.ClientAuthenticationInformation
		err := result.MergeJwtJwksAuthenticationInformation(api.JwtJwksAuthenticationInformation{
			Urls: in.URLs,
		})
		if err != nil {
			return api.ClientAuthenticationInformation{}, err
		}
		return result, nil
	case "JWT_STANDARD_CLAIMS":
		var result api.ClientAuthenticationInformation
		jwtClients, err := manifestToAPIJwtClientInformation(resolvePolicy, in.Clients)
		if err != nil {
			return api.ClientAuthenticationInformation{}, fmt.Errorf("manifestToAPIClientAuthentication: while converting clients for clientAuthentication type=JWT_STANDARD_CLAIMS: %w", err)
		}
		err = result.MergeJwtStandardClaimsAuthenticationInformation(api.JwtStandardClaimsAuthenticationInformation{
			Audience: in.Audience,
			Clients:  jwtClients,
		})
		if err != nil {
			return api.ClientAuthenticationInformation{}, err
		}
		return result, nil
	case "JWT_OIDC":
		var result api.ClientAuthenticationInformation
		err := result.MergeJwtOidcAuthenticationInformation(api.JwtOidcAuthenticationInformation{
			BaseUrl:  in.BaseURL,
			Audience: in.Audience,
		})
		if err != nil {
			return api.ClientAuthenticationInformation{}, fmt.Errorf("manifestToAPIClientAuthentication: while converting clients for clientAuthentication type=JWT_OIDC: %w", err)
		}
		return result, nil
	default:
		return api.ClientAuthenticationInformation{}, fmt.Errorf("manifestToAPIClientAuthentication: unknown ClientAuthentication type: %s", in.Type)
	}
}

func manifestToAPIJwtClientInformation(resolvePolicy func(string) (api.ExtendedPolicyInformation, error), in []manifest.ClientAuthenticationClient) ([]api.JwtClientInformation, error) {
	var result []api.JwtClientInformation
	for _, c := range in {
		var allowedPolicyIDs []openapi_types.UUID
		for _, name := range c.AllowedPolicies {
			policy, err := resolvePolicy(name)
			if err != nil {
				return nil, err
			}
			allowedPolicyIDs = append(allowedPolicyIDs, policy.Id)
		}
		result = append(result, api.JwtClientInformation{
			Name:             c.Name,
			Issuer:           c.Issuer,
			JwksUri:          c.JwksURI,
			Subjects:         c.Subjects,
			AllowedPolicyIds: allowedPolicyIDs,
		})
	}
	return result, nil
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

func manifestPoliciesToAPI(policyNameToUUID func(string) (string, error), items []manifest.Policy) []api.ExtendedPolicyInformation {
	if len(items) == 0 {
		return nil
	}
	result := make([]api.ExtendedPolicyInformation, len(items))
	for i, item := range items {
		result[i] = manifestToAPIPolicy(item)
	}
	return result
}

func apiPoliciesToManifest(items []api.ExtendedPolicyInformation) []manifest.Policy {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.Policy, len(items))
	for i, item := range items {
		result[i] = apiToManifestExtendedPolicyInformation(item)
	}
	return result
}

func manifestToAPIPolicy(in manifest.Policy) api.ExtendedPolicyInformation {
	return api.ExtendedPolicyInformation{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           manifestToAPISubject(in.Subject),
		Sans:              manifestToAPISANs(in.SANs),
		KeyUsages:         manifestToAPIExtendedPolicyInformationKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: manifestToAPIExtendedPolicyInformationExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      manifestToAPIKeyAlgorithm(in.KeyAlgorithm),
	}
}

func manifestToAPIPolicyCreateRequest(in manifest.Policy) api.PolicyCreateRequest {
	return api.PolicyCreateRequest{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           manifestToAPISubject(in.Subject),
		Sans:              manifestToAPISANs(in.SANs),
		KeyUsages:         manifestToAPIPolicyCreateRequestKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: manifestToAPIPolicyCreateRequestExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      manifestToAPIKeyAlgorithm(in.KeyAlgorithm),
	}
}

func apiToManifestPolicyInformation(in api.PolicyInformation) manifest.Policy {
	return manifest.Policy{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           apiToManifestSubject(in.Subject),
		SANs:              apiToManifestSANs(in.Sans),
		KeyUsages:         apiToManifestPolicyInformationKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: apiToManifestPolicyInformationExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      apiToManifestKeyAlgorithm(in.KeyAlgorithm),
	}
}

func apiToManifestExtendedPolicyInformation(in api.ExtendedPolicyInformation) manifest.Policy {
	return manifest.Policy{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           apiToManifestSubject(in.Subject),
		SANs:              apiToManifestSANs(in.Sans),
		KeyUsages:         apiToManifestExtendedPolicyInformationKeyUsages(in.KeyUsages),
		ExtendedKeyUsages: apiToManifestExtendedPolicyInformationExtendedKeyUsages(in.ExtendedKeyUsages),
		KeyAlgorithm:      apiToManifestKeyAlgorithm(in.KeyAlgorithm),
	}
}

func manifestToAPIExtendedPolicyInformationKeyUsages(in []string) []api.ExtendedPolicyInformationKeyUsages {
	result := make([]api.ExtendedPolicyInformationKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.ExtendedPolicyInformationKeyUsages(v)
	}
	return result
}

func manifestToAPIExtendedPolicyInformationExtendedKeyUsages(in []string) []api.ExtendedPolicyInformationExtendedKeyUsages {
	result := make([]api.ExtendedPolicyInformationExtendedKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.ExtendedPolicyInformationExtendedKeyUsages(v)
	}
	return result
}

func manifestToAPIPolicyCreateRequestKeyUsages(in []string) []api.PolicyCreateRequestKeyUsages {
	result := make([]api.PolicyCreateRequestKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.PolicyCreateRequestKeyUsages(v)
	}
	return result
}

func manifestToAPIPolicyCreateRequestExtendedKeyUsages(in []string) []api.PolicyCreateRequestExtendedKeyUsages {
	result := make([]api.PolicyCreateRequestExtendedKeyUsages, len(in))
	for i, v := range in {
		result[i] = api.PolicyCreateRequestExtendedKeyUsages(v)
	}
	return result
}

func apiToManifestExtendedPolicyInformationKeyUsages(in []api.ExtendedPolicyInformationKeyUsages) []string {
	result := make([]string, len(in))
	for i, v := range in {
		result[i] = string(v)
	}
	return result
}

func apiToManifestPolicyInformationKeyUsages(in []api.PolicyInformationKeyUsages) []string {
	result := make([]string, len(in))
	for i, v := range in {
		result[i] = string(v)
	}
	return result
}

func apiToManifestPolicyInformationExtendedKeyUsages(in []api.PolicyInformationExtendedKeyUsages) []string {
	result := make([]string, len(in))
	for i, v := range in {
		result[i] = string(v)
	}
	return result
}

func apiToManifestExtendedPolicyInformationExtendedKeyUsages(in []api.ExtendedPolicyInformationExtendedKeyUsages) []string {
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

func ptr[T any](v T) *T {
	return &v
}

func apiToManifestCommonName(in api.PropertyInformation) manifest.CommonName {
	return manifest.CommonName{
		Type:           string(in.Type),
		AllowedValues:  append([]string(nil), in.AllowedValues...),
		DefaultValues:  append([]string(nil), in.DefaultValues...),
		MinOccurrences: in.MinOccurrences,
		MaxOccurrences: in.MaxOccurrences,
	}
}

func manifestServiceAccountsToAPI(items []manifest.ServiceAccount) []api.ServiceAccountDetails {
	if len(items) == 0 {
		return nil
	}
	result := make([]api.ServiceAccountDetails, len(items))
	for i, item := range items {
		result[i] = manifestToAPIServiceAccount(item)
	}
	return result
}

func apiServiceAccountsToManifest(items []api.ServiceAccountDetails) []manifest.ServiceAccount {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.ServiceAccount, len(items))
	for i, item := range items {
		result[i] = apiToManifestServiceAccount(item)
	}
	return result
}

func manifestToAPIServiceAccount(in manifest.ServiceAccount) api.ServiceAccountDetails {
	ownerUUID := openapi_types.UUID{}
	_ = ownerUUID.UnmarshalText([]byte(in.Owner))

	applications := make([]api.Application, len(in.Applications))
	for i, app := range in.Applications {
		appUUID := openapi_types.UUID{}
		_ = appUUID.UnmarshalText([]byte(app))
		applications[i] = appUUID
	}

	return api.ServiceAccountDetails{
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

func apiToManifestServiceAccount(in api.ServiceAccountDetails) manifest.ServiceAccount {
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

func manifestToAPISubCa(resolveIssuingTmpl func(string) (api.CertificateIssuingTemplateInformation1, error), in manifest.SubCa) (api.SubCaProviderInformation, error) {
	tmpl, err := resolveIssuingTmpl(in.IssuingTemplateName)
	if err != nil {
		return api.SubCaProviderInformation{}, fmt.Errorf("manifestToAPISubCa: while resolving 'issuingTemplateName' %q: %w", in.IssuingTemplateName, err)
	}

	return api.SubCaProviderInformation{
		Name: in.Name,

		// These three values are taken from the issuing template.
		CaType:            api.SubCaProviderInformationCaType(tmpl.CertificateAuthority),
		CaAccountId:       tmpl.CertificateAuthorityAccountId,
		CaProductOptionId: tmpl.CertificateAuthorityProductOptionId,

		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       api.SubCaProviderInformationKeyAlgorithm(in.KeyAlgorithm),
		Pkcs11:             manifestToAPIPKCS11(in.PKCS11),
	}, nil
}

func apiToManifestSubCa(resolve func(caAccountId, caProductOptionId openapi_types.UUID) (api.CertificateIssuingTemplateInformation1, error), in api.SubCaProviderInformation) (manifest.SubCa, error) {
	tmpl, err := resolve(in.CaAccountId, in.CaProductOptionId)
	if err != nil {
		return manifest.SubCa{}, fmt.Errorf("apiToManifestSubCa: while resolving issuing template for CaAccountId=%q and CaProductOptionId=%q: %w", in.CaAccountId, in.CaProductOptionId, err)
	}

	return manifest.SubCa{
		Name: in.Name,

		IssuingTemplateName: tmpl.Name,

		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       string(in.KeyAlgorithm),
		PKCS11:             apiToManifestPKCS11(in.Pkcs11),
	}, nil
}

func manifestToAPIPKCS11(in manifest.PKCS11) api.SubCaProviderPkcs11ConfigurationInformation {
	return api.SubCaProviderPkcs11ConfigurationInformation{
		AllowedClientLibraries: append([]string(nil), in.AllowedClientLibraries...),
		PartitionLabel:         in.PartitionLabel,
		PartitionSerialNumber:  in.PartitionSerialNumber,
		Pin:                    in.PIN,
		SigningEnabled:         in.SigningEnabled,
	}
}

func apiToManifestPKCS11(in api.SubCaProviderPkcs11ConfigurationInformation) manifest.PKCS11 {
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
