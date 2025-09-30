package main

import (
	api "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"
)

func manifestToAPIConfig(in manifest.Config) api.Config {
	return api.Config{
		Name:                 in.Name,
		ClientAuthentication: manifestToAPIClientAuthentication(in.ClientAuthentication),
		ClientAuthorization:  manifestToAPIClientAuthorization(in.ClientAuthorization),
		CloudProviders:       copyStringAnyMap(in.CloudProviders),
		MinTLSVersion:        in.MinTLSVersion,
		Policies:             manifestPoliciesToAPI(in.Policies),
		SubCaProvider:        manifestToAPISubCa(in.SubCaProvider),
		AdvancedSettings:     manifestToAPIAdvancedSettings(in.AdvancedSettings),
		ServiceAccounts:      manifestServiceAccountsToAPI(in.ServiceAccounts),
	}
}

func apiToManifestConfig(in api.Config) manifest.Config {
	return manifest.Config{
		Name:                 in.Name,
		ClientAuthentication: apiToManifestClientAuthentication(in.ClientAuthentication),
		ClientAuthorization:  apiToManifestClientAuthorization(in.ClientAuthorization),
		CloudProviders:       copyStringAnyMap(in.CloudProviders),
		MinTLSVersion:        in.MinTLSVersion,
		Policies:             apiPoliciesToManifest(in.Policies),
		SubCaProvider:        apiToManifestSubCa(in.SubCaProvider),
		AdvancedSettings:     apiToManifestAdvancedSettings(in.AdvancedSettings),
		ServiceAccounts:      apiServiceAccountsToManifest(in.ServiceAccounts),
	}
}

func manifestToAPIClientAuthentication(in manifest.ClientAuthentication) api.ClientAuthentication {
	result := api.ClientAuthentication{
		Type:     in.Type,
		URLs:     append([]string(nil), in.URLs...),
		Audience: in.Audience,
		BaseURL:  in.BaseURL,
	}
	if len(in.Clients) > 0 {
		result.Clients = make([]api.ClientAuthenticationClient, len(in.Clients))
		for i, client := range in.Clients {
			result.Clients[i] = manifestToAPIClientAuthenticationClient(client)
		}
	}
	return result
}

func apiToManifestClientAuthentication(in api.ClientAuthentication) manifest.ClientAuthentication {
	result := manifest.ClientAuthentication{
		Type:     in.Type,
		URLs:     append([]string(nil), in.URLs...),
		Audience: in.Audience,
		BaseURL:  in.BaseURL,
	}
	if len(in.Clients) > 0 {
		result.Clients = make([]manifest.ClientAuthenticationClient, len(in.Clients))
		for i, client := range in.Clients {
			result.Clients[i] = apiToManifestClientAuthenticationClient(client)
		}
	}
	return result
}

func manifestToAPIClientAuthenticationClient(in manifest.ClientAuthenticationClient) api.ClientAuthenticationClient {
	result := api.ClientAuthenticationClient{
		Name:     in.Name,
		Issuer:   in.Issuer,
		JwksURI:  in.JwksURI,
		Subjects: append([]string(nil), in.Subjects...),
	}
	if len(in.AllowedPolicies) > 0 {
		result.AllowedPolicies = append([]string(nil), in.AllowedPolicies...)
	}
	return result
}

func apiToManifestClientAuthenticationClient(in api.ClientAuthenticationClient) manifest.ClientAuthenticationClient {
	result := manifest.ClientAuthenticationClient{
		Name:     in.Name,
		Issuer:   in.Issuer,
		JwksURI:  in.JwksURI,
		Subjects: append([]string(nil), in.Subjects...),
	}
	if len(in.AllowedPolicies) > 0 {
		result.AllowedPolicies = append([]string(nil), in.AllowedPolicies...)
	}
	return result
}

func manifestToAPIClientAuthorization(in manifest.ClientAuthorization) api.ClientAuthorization {
	return api.ClientAuthorization{
		CustomClaimsAliases: manifestToAPICustomClaimsAliases(in.CustomClaimsAliases),
	}
}

func apiToManifestClientAuthorization(in api.ClientAuthorization) manifest.ClientAuthorization {
	return manifest.ClientAuthorization{
		CustomClaimsAliases: apiToManifestCustomClaimsAliases(in.CustomClaimsAliases),
	}
}

func manifestToAPICustomClaimsAliases(in manifest.CustomClaimsAliases) api.CustomClaimsAliases {
	return api.CustomClaimsAliases{
		Configuration:    in.Configuration,
		AllowAllPolicies: in.AllowAllPolicies,
		AllowedPolicies:  in.AllowedPolicies,
	}
}

func apiToManifestCustomClaimsAliases(in api.CustomClaimsAliases) manifest.CustomClaimsAliases {
	return manifest.CustomClaimsAliases{
		Configuration:    in.Configuration,
		AllowAllPolicies: in.AllowAllPolicies,
		AllowedPolicies:  in.AllowedPolicies,
	}
}

func manifestPoliciesToAPI(items []manifest.Policy) []api.Policy {
	if len(items) == 0 {
		return nil
	}
	result := make([]api.Policy, len(items))
	for i, item := range items {
		result[i] = manifestToAPIPolicy(item)
	}
	return result
}

func apiPoliciesToManifest(items []api.Policy) []manifest.Policy {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.Policy, len(items))
	for i, item := range items {
		result[i] = apiToManifestPolicy(item)
	}
	return result
}

func manifestToAPIPolicy(in manifest.Policy) api.Policy {
	return api.Policy{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           manifestToAPISubject(in.Subject),
		SANs:              manifestToAPISANs(in.SANs),
		KeyUsages:         append([]string(nil), in.KeyUsages...),
		ExtendedKeyUsages: append([]string(nil), in.ExtendedKeyUsages...),
		KeyAlgorithm:      manifestToAPIKeyAlgorithm(in.KeyAlgorithm),
	}
}

func apiToManifestPolicy(in api.Policy) manifest.Policy {
	return manifest.Policy{
		Name:              in.Name,
		ValidityPeriod:    in.ValidityPeriod,
		Subject:           apiToManifestSubject(in.Subject),
		SANs:              apiToManifestSANs(in.SANs),
		KeyUsages:         append([]string(nil), in.KeyUsages...),
		ExtendedKeyUsages: append([]string(nil), in.ExtendedKeyUsages...),
		KeyAlgorithm:      apiToManifestKeyAlgorithm(in.KeyAlgorithm),
	}
}

func manifestToAPISubject(in manifest.Subject) api.Subject {
	return api.Subject{
		CommonName:         manifestToAPICommonName(in.CommonName),
		Country:            manifestToAPICommonName(in.Country),
		Locality:           manifestToAPICommonName(in.Locality),
		Organization:       manifestToAPICommonName(in.Organization),
		OrganizationalUnit: manifestToAPICommonName(in.OrganizationalUnit),
		StateOrProvince:    manifestToAPICommonName(in.StateOrProvince),
	}
}

func apiToManifestSubject(in api.Subject) manifest.Subject {
	return manifest.Subject{
		CommonName:         apiToManifestCommonName(in.CommonName),
		Country:            apiToManifestCommonName(in.Country),
		Locality:           apiToManifestCommonName(in.Locality),
		Organization:       apiToManifestCommonName(in.Organization),
		OrganizationalUnit: apiToManifestCommonName(in.OrganizationalUnit),
		StateOrProvince:    apiToManifestCommonName(in.StateOrProvince),
	}
}

func manifestToAPISANs(in manifest.SANs) api.SANs {
	return api.SANs{
		DNSNames:                   manifestToAPICommonName(in.DNSNames),
		IPAddresses:                manifestToAPICommonName(in.IPAddresses),
		RFC822Names:                manifestToAPICommonName(in.RFC822Names),
		UniformResourceIdentifiers: manifestToAPICommonName(in.UniformResourceIdentifiers),
	}
}

func apiToManifestSANs(in api.SANs) manifest.SANs {
	return manifest.SANs{
		DNSNames:                   apiToManifestCommonName(in.DNSNames),
		IPAddresses:                apiToManifestCommonName(in.IPAddresses),
		RFC822Names:                apiToManifestCommonName(in.RFC822Names),
		UniformResourceIdentifiers: apiToManifestCommonName(in.UniformResourceIdentifiers),
	}
}

func manifestToAPIKeyAlgorithm(in manifest.KeyAlgorithm) api.KeyAlgorithm {
	return api.KeyAlgorithm{
		AllowedValues: append([]string(nil), in.AllowedValues...),
		DefaultValue:  in.DefaultValue,
	}
}

func apiToManifestKeyAlgorithm(in api.KeyAlgorithm) manifest.KeyAlgorithm {
	return manifest.KeyAlgorithm{
		AllowedValues: append([]string(nil), in.AllowedValues...),
		DefaultValue:  in.DefaultValue,
	}
}

func manifestToAPICommonName(in manifest.CommonName) api.CommonName {
	return api.CommonName{
		Type:           in.Type,
		AllowedValues:  append([]string(nil), in.AllowedValues...),
		DefaultValues:  append([]string(nil), in.DefaultValues...),
		MinOccurrences: in.MinOccurrences,
		MaxOccurrences: in.MaxOccurrences,
	}
}

func apiToManifestCommonName(in api.CommonName) manifest.CommonName {
	return manifest.CommonName{
		Type:           in.Type,
		AllowedValues:  append([]string(nil), in.AllowedValues...),
		DefaultValues:  append([]string(nil), in.DefaultValues...),
		MinOccurrences: in.MinOccurrences,
		MaxOccurrences: in.MaxOccurrences,
	}
}

func manifestServiceAccountsToAPI(items []manifest.ServiceAccount) []api.ServiceAccount {
	if len(items) == 0 {
		return nil
	}
	result := make([]api.ServiceAccount, len(items))
	for i, item := range items {
		result[i] = manifestToAPIServiceAccount(item)
	}
	return result
}

func apiServiceAccountsToManifest(items []api.ServiceAccount) []manifest.ServiceAccount {
	if len(items) == 0 {
		return nil
	}
	result := make([]manifest.ServiceAccount, len(items))
	for i, item := range items {
		result[i] = apiToManifestServiceAccount(item)
	}
	return result
}

func manifestToAPIServiceAccount(in manifest.ServiceAccount) api.ServiceAccount {
	return api.ServiceAccount{
		AuthenticationType: in.AuthenticationType,
		CredentialLifetime: in.CredentialLifetime,
		Enabled:            in.Enabled,
		Name:               in.Name,
		Owner:              in.Owner,
		Scopes:             append([]string(nil), in.Scopes...),
		Applications:       append([]string(nil), in.Applications...),
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		JwksURI:            in.JwksURI,
		Subject:            in.Subject,
		PublicKey:          in.PublicKey,
	}
}

func apiToManifestServiceAccount(in api.ServiceAccount) manifest.ServiceAccount {
	return manifest.ServiceAccount{
		AuthenticationType: in.AuthenticationType,
		CredentialLifetime: in.CredentialLifetime,
		Enabled:            in.Enabled,
		Name:               in.Name,
		Owner:              in.Owner,
		Scopes:             append([]string(nil), in.Scopes...),
		Applications:       append([]string(nil), in.Applications...),
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		JwksURI:            in.JwksURI,
		Subject:            in.Subject,
		PublicKey:          in.PublicKey,
	}
}

func manifestToAPISubCa(in manifest.SubCa) api.SubCa {
	return api.SubCa{
		Name:               in.Name,
		CaType:             in.CaType,
		CaAccountID:        in.CaAccountID,
		CaProductOptionID:  in.CaProductOptionID,
		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       in.KeyAlgorithm,
		PKCS11:             manifestToAPIPKCS11(in.PKCS11),
	}
}

func apiToManifestSubCa(in api.SubCa) manifest.SubCa {
	return manifest.SubCa{
		Name:               in.Name,
		CaType:             in.CaType,
		CaAccountID:        in.CaAccountID,
		CaProductOptionID:  in.CaProductOptionID,
		ValidityPeriod:     in.ValidityPeriod,
		CommonName:         in.CommonName,
		Organization:       in.Organization,
		Country:            in.Country,
		Locality:           in.Locality,
		OrganizationalUnit: in.OrganizationalUnit,
		StateOrProvince:    in.StateOrProvince,
		KeyAlgorithm:       in.KeyAlgorithm,
		PKCS11:             apiToManifestPKCS11(in.PKCS11),
	}
}

func manifestToAPIPKCS11(in manifest.PKCS11) api.PKCS11 {
	return api.PKCS11{
		AllowedClientLibraries: append([]string(nil), in.AllowedClientLibraries...),
		PartitionLabel:         in.PartitionLabel,
		PartitionSerialNumber:  in.PartitionSerialNumber,
		PIN:                    in.PIN,
		SigningEnabled:         in.SigningEnabled,
	}
}

func apiToManifestPKCS11(in api.PKCS11) manifest.PKCS11 {
	return manifest.PKCS11{
		AllowedClientLibraries: append([]string(nil), in.AllowedClientLibraries...),
		PartitionLabel:         in.PartitionLabel,
		PartitionSerialNumber:  in.PartitionSerialNumber,
		PIN:                    in.PIN,
		SigningEnabled:         in.SigningEnabled,
	}
}

func manifestToAPIAdvancedSettings(in manifest.AdvancedSettings) api.AdvancedSettings {
	return api.AdvancedSettings{
		EnableIssuanceAuditLog:       in.EnableIssuanceAuditLog,
		IncludeRawCertDataInAuditLog: in.IncludeRawCertDataInAuditLog,
		RequireFIPSCompliantBuild:    in.RequireFIPSCompliantBuild,
	}
}

func apiToManifestAdvancedSettings(in api.AdvancedSettings) manifest.AdvancedSettings {
	return manifest.AdvancedSettings{
		EnableIssuanceAuditLog:       in.EnableIssuanceAuditLog,
		IncludeRawCertDataInAuditLog: in.IncludeRawCertDataInAuditLog,
		RequireFIPSCompliantBuild:    in.RequireFIPSCompliantBuild,
	}
}

func copyStringAnyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	result := make(map[string]any, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}
