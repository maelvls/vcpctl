package api

import (
	"github.com/google/uuid"
)

func APIToAPICreateServiceAccountRequestBody(in ServiceAccountDetails) CreateServiceAccountRequestBody {
	return CreateServiceAccountRequestBody{
		AuthenticationType: in.AuthenticationType,
		CredentialLifetime: in.CredentialLifetime,
		Name:               in.Name,
		Owner:              in.Owner,
		Scopes:             in.Scopes,
		Applications:       in.Applications,
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		JwksURI:            in.JwksURI,
		Subject:            in.Subject,
		PublicKey:          in.PublicKey,

		CompanyId: uuid.Nil, // Not set.
	}
}

func APIToAPIConfigurationCreateRequest(in ExtendedConfigurationInformation) ConfigurationCreateRequest {
	return ConfigurationCreateRequest{
		AdvancedSettings:     in.AdvancedSettings,
		ClientAuthentication: in.ClientAuthentication,
		ClientAuthorization:  in.ClientAuthorization,
		CloudProviders:       in.CloudProviders,
		MinTlsVersion:        ConfigurationCreateRequestMinTlsVersion(in.MinTlsVersion),
		Name:                 in.Name,
		PolicyIds:            in.PolicyIds,
		ServiceAccountIds:    in.ServiceAccountIds,
		SubCaProviderId:      in.SubCaProvider.Id,
	}
}

func APIToAPISubCaProviderCreateRequest(in SubCaProviderInformation) SubCaProviderCreateRequest {
	return SubCaProviderCreateRequest{
		CaAccountId:        in.CaAccountId,
		CaProductOptionId:  in.CaProductOptionId,
		CaType:             SubCaProviderCreateRequestCaType(in.CaType),
		CommonName:         in.CommonName,
		Country:            in.Country,
		KeyAlgorithm:       SubCaProviderCreateRequestKeyAlgorithm(in.KeyAlgorithm),
		Locality:           in.Locality,
		Name:               in.Name,
		Organization:       in.Organization,
		OrganizationalUnit: in.OrganizationalUnit,
		Pkcs11:             in.Pkcs11,
		StateOrProvince:    in.StateOrProvince,
		ValidityPeriod:     in.ValidityPeriod,
	}
}
