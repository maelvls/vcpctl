package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

func GetConfigs(ctx context.Context, cl *Client) ([]ExtendedConfigurationInformation, error) {
	resp, err := cl.ConfigurationsGetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorf(resp, "getConfigs: returned status code %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}
	var result struct {
		Configurations []ExtendedConfigurationInformation `json:"configurations"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getConfigs: while reading response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("getConfigs: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result.Configurations, nil
}

func GetConfig(ctx context.Context, cl *Client, nameOrID string) (ExtendedConfigurationInformation, error) {
	if looksLikeAnID(nameOrID) {
		return GetConfigByID(ctx, cl, nameOrID)
	}

	confs, err := GetConfigs(ctx, cl)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("getConfigByName:urations: %w", err)
	}

	// We need to error out if duplicate names are found.
	var found []ExtendedConfigurationInformation
	for _, cur := range confs {
		if cur.Name == nameOrID || cur.Id.String() == nameOrID {
			found = append(found, cur)
		}
	}
	if len(found) == 0 {
		return ExtendedConfigurationInformation{}, errutil.NotFound{NameOrID: nameOrID}
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, f := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", f.Name, f.Id.String(), f.CreationDate))
		}
		return ExtendedConfigurationInformation{}, fmt.Errorf(undent.Undent(`
			getConfigByName: duplicate Workload Identity Manager configurations found with name '%s':
			%s
			Either use the Workload Identity Manager configuration ID instead of the name, or try
			removing the duplicates first with:
			    vcpctl rm %s
		`), nameOrID, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func GetConfigByID(ctx context.Context, cl *Client, id string) (ExtendedConfigurationInformation, error) {
	resp, err := cl.ConfigurationsGetById(ctx, id)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("getConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return ExtendedConfigurationInformation{}, HTTPErrorf(resp, "getConfig: returned status code %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	var result ExtendedConfigurationInformation
	if err := decodeJSON(resp.Body, &result); err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("getConfig: while decoding response: %w", err)
	}
	return result, nil
}

// CreateConfig creates a new Workload Identity Manager configuration or updates an
// existing one. Also deals with creating the subCA policies.
func CreateConfig(ctx context.Context, cl *Client, config ConfigurationCreateRequest) (ExtendedConfigurationInformation, error) {
	resp, err := cl.ConfigurationsCreate(ctx, config)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return ExtendedConfigurationInformation{}, HTTPErrorf(resp, "createConfig: got http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while reading response body: %w", err)
	}

	var result ExtendedConfigurationInformation
	err = json.Unmarshal(body, &result)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("createConfig: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

// https://api.venafi.cloud/v1/distributedissuers/configurations/{id}
func PatchConfig(ctx context.Context, cl *Client, id string, patch ConfigurationUpdateRequest) (ExtendedConfigurationInformation, error) {
	resp, err := cl.ConfigurationsUpdate(ctx, id, patch)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("patchConfig: while sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful, continue below.
	case http.StatusNotFound:
		return ExtendedConfigurationInformation{}, fmt.Errorf("WIM configuration: %w", errutil.NotFound{NameOrID: id})
	default:
		return ExtendedConfigurationInformation{}, HTTPErrorf(resp, "patchConfig: unexpected http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	body := new(bytes.Buffer)
	_, err = io.Copy(body, resp.Body)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("while reading service accounts: %w", err)
	}

	var result ExtendedConfigurationInformation
	err = json.Unmarshal(body.Bytes(), &result)
	if err != nil {
		return ExtendedConfigurationInformation{}, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result, nil
}

func RemoveConfig(ctx context.Context, cl *Client, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		config, err := GetConfig(ctx, cl, nameOrID)
		if err != nil {
			return fmt.Errorf("removeConfig: while getting the configuration with the name '%s': %w", nameOrID, err)
		}
		id = config.Id.String()
	}

	resp, err := cl.ConfigurationsDelete(ctx, id)
	if err != nil {
		return fmt.Errorf("removeConfig: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return &errutil.NotFound{NameOrID: nameOrID}
	default:
		return HTTPErrorf(resp, "removeConfig: returned status code %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}
}

func AttachSAToConf(ctx context.Context, cl *Client, confName, saName string) error {
	// Get configuration name by ID.
	existing, err := GetConfig(ctx, cl, confName)
	if err != nil {
		return fmt.Errorf("while fetching the ID of the Workload Identity Manager configuration '%s': %w", confName, err)
	}

	// Find service accounts.
	knownSvcaccts, err := GetServiceAccounts(context.Background(), cl)
	if err != nil {
		return fmt.Errorf("while fetching service accounts: %w", err)
	}

	var sa *ServiceAccountDetails
	// First, check if saName is actually a client ID (direct match with ID).
	for _, knownSa := range knownSvcaccts {
		if knownSa.Id.String() == saName {
			sa = &knownSa
			break
		}
	}

	// If no client ID match, try looking up by name.
	if sa == nil {
		for _, knownSa := range knownSvcaccts {
			if knownSa.Name == saName {
				if sa != nil {
					return fmt.Errorf("service account name '%s' is ambiguous, please use the client ID instead", saName)
				}
				sa = &knownSa
			}
		}
	}

	if sa == nil {
		return errutil.Fixable(fmt.Errorf("service account '%s' not found (not a valid name or client ID)", saName))
	}

	// Is this SA already in the configuration?
	if slices.Contains(existing.ServiceAccountIds, sa.Id) {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.Id.String(), existing.Name)
		return nil
	}

	// Add the service account to the configuration.
	desired := existing
	desired.ServiceAccountIds = append(desired.ServiceAccountIds, sa.Id)
	patch, changed, err := DiffToPatchConfig(existing, desired)
	if err != nil {
		return fmt.Errorf("while creating patch to attach service account '%s' to configuration '%s': %w", saName, confName, err)
	}
	if !changed {
		logutil.Debugf("Service account '%s' (ID: %s) is already in the configuration '%s', doing nothing.", sa.Name, sa.Id.String(), existing.Name)
		return nil
	}
	updated, err := PatchConfig(ctx, cl, existing.Id.String(), patch)
	if err != nil {
		return fmt.Errorf("while patching Workload Identity Manager configuration: %w", err)
	}

	if logutil.EnableDebug {
		d := ANSIDiff(existing, updated)
		logutil.Debugf("Service Account '%s' updated:\n%s", saName, d)
	}

	return nil
}

// DiffToPatchConfig computes the difference between existing and desired
// configs and returns a patch with only the changed fields.
func DiffToPatchConfig(existing, desired ExtendedConfigurationInformation) (ConfigurationUpdateRequest, bool, error) {
	patch := ConfigurationUpdateRequest{}
	var smthChanged, fieldChanged bool
	var err error

	if desired.AdvancedSettings.EnableIssuanceAuditLog != existing.AdvancedSettings.EnableIssuanceAuditLog {
		patch.AdvancedSettings.EnableIssuanceAuditLog = desired.AdvancedSettings.EnableIssuanceAuditLog
		smthChanged = true
	}
	if desired.AdvancedSettings.IncludeRawCertDataInAuditLog != existing.AdvancedSettings.IncludeRawCertDataInAuditLog {
		patch.AdvancedSettings.IncludeRawCertDataInAuditLog = desired.AdvancedSettings.IncludeRawCertDataInAuditLog
		smthChanged = true
	}
	if desired.AdvancedSettings.RequireFIPSCompliantBuild != existing.AdvancedSettings.RequireFIPSCompliantBuild {
		patch.AdvancedSettings.RequireFIPSCompliantBuild = desired.AdvancedSettings.RequireFIPSCompliantBuild
		smthChanged = true
	}

	patch.ClientAuthentication, fieldChanged, err = DiffToPatchClientAuthentication(existing.ClientAuthentication, desired.ClientAuthentication)
	if err != nil {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("diffToPatchConfig: while comparing the 'clientAuthentication' field on the existing and desired configurations: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.ClientAuthorization, fieldChanged = DiffToPatchClientAuthorization(existing.ClientAuthorization, desired.ClientAuthorization)
	smthChanged = smthChanged || fieldChanged

	patch.CloudProviders, fieldChanged = DiffToPatchCloudProviders(existing.CloudProviders, desired.CloudProviders)
	smthChanged = smthChanged || fieldChanged

	if desired.CompanyId != (openapi_types.UUID{}) && desired.CompanyId != existing.CompanyId {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'companyId' field in an existing configuration")
	}

	if desired.ControllerAllowedPolicyIds != nil && !slicesEqual(desired.ControllerAllowedPolicyIds, existing.ControllerAllowedPolicyIds) {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'controllerAllowedPolicyIds' field in an existing configuration")
	}

	if desired.CreationDate != "" && desired.CreationDate != existing.CreationDate {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'creationDate' field in an existing configuration")
	}

	if desired.Id != (openapi_types.UUID{}) && desired.Id != existing.Id {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'id' field in an existing configuration")
	}

	if desired.LongLivedCertCount != 0 && desired.LongLivedCertCount != existing.LongLivedCertCount {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'longLivedCertCount' field in an existing configuration")
	}

	if desired.MinTlsVersion != "" && desired.MinTlsVersion != existing.MinTlsVersion {
		patch.MinTlsVersion = ConfigurationUpdateRequestMinTlsVersion(desired.MinTlsVersion)
		smthChanged = true
	}

	if desired.ModificationDate != "" && desired.ModificationDate != existing.ModificationDate {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change ModificationDate of existing configuration")
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Policies != nil && !PoliciesEqual(existing.Policies, desired.Policies) {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'policies' field of an existing configuration")
	}

	if desired.PolicyDefinitions != nil && !PoliciesEqual(existing.PolicyDefinitions, desired.PolicyDefinitions) {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'policyDefinitions' field of an existing configuration")
	}

	if len(desired.PolicyIds) > 0 && !slicesEqual(desired.PolicyIds, existing.PolicyIds) {
		patch.PolicyIds = desired.PolicyIds
		smthChanged = true
	}

	// Compare ShortLivedCertCount.
	if desired.ShortLivedCertCount != 0 && desired.ShortLivedCertCount != existing.ShortLivedCertCount {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'shortLivedCertCount' field of an existing configuration")
	}

	_, changed, _ := DiffToPatchSubCAProvider(existing.SubCaProvider, desired.SubCaProvider)
	if changed {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'subCaProvider' field of an existing configuration")
	}

	if desired.UltraShortLivedCertCount != 0 && desired.UltraShortLivedCertCount != existing.UltraShortLivedCertCount {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'ultraShortLivedCertCount' field of an existing configuration")
	}

	if desired.UnixSocketAllowedPolicyIds != nil && !slicesEqual(desired.UnixSocketAllowedPolicyIds, existing.UnixSocketAllowedPolicyIds) {
		return ConfigurationUpdateRequest{}, false, fmt.Errorf("cannot change the 'unixSocketAllowedPolicyIds' field in an existing configuration")
	}

	return patch, smthChanged, nil
}

func DiffToPatchCloudProviders(existing, desired CloudProvidersInformation) (CloudProvidersInformation, bool) {
	patch := CloudProvidersInformation{}
	var fieldChanged, smthChanged bool

	patch.Aws, fieldChanged = DiffToPatchAwsCloudProviderInformation(existing.Aws, desired.Aws)
	smthChanged = smthChanged || fieldChanged
	patch.Azure, fieldChanged = DiffToPatchAzureCloudProviderInformation(existing.Azure, desired.Azure)
	smthChanged = smthChanged || fieldChanged
	patch.Google, fieldChanged = DiffToPatchGoogleCloudProviderInformation(existing.Google, desired.Google)
	smthChanged = smthChanged || fieldChanged

	return patch, smthChanged
}

func DiffToPatchAwsCloudProviderInformation(existing, desired AwsCloudProviderInformation) (AwsCloudProviderInformation, bool) {
	patch := AwsCloudProviderInformation{}
	var smthChanged bool

	if desired.AccountIds != nil && !slicesEqual(desired.AccountIds, existing.AccountIds) {
		patch.AccountIds = desired.AccountIds
		smthChanged = true
	}

	if desired.Regions != nil && !slicesEqual(desired.Regions, existing.Regions) {
		patch.Regions = desired.Regions
		smthChanged = true
	}

	return patch, smthChanged
}

func DiffToPatchAzureCloudProviderInformation(existing, desired AzureCloudProviderInformation) (AzureCloudProviderInformation, bool) {
	patch := AzureCloudProviderInformation{}
	var smthChanged bool

	if desired.SubscriptionIds != nil && !slicesEqual(desired.SubscriptionIds, existing.SubscriptionIds) {
		patch.SubscriptionIds = desired.SubscriptionIds
		smthChanged = true
	}

	return patch, smthChanged
}

func DiffToPatchGoogleCloudProviderInformation(existing, desired GoogleCloudProviderInformation) (GoogleCloudProviderInformation, bool) {
	patch := GoogleCloudProviderInformation{}
	var smthChanged bool

	if desired.ProjectIdentifiers != nil && !slicesEqual(desired.ProjectIdentifiers, existing.ProjectIdentifiers) {
		patch.ProjectIdentifiers = desired.ProjectIdentifiers
		smthChanged = true
	}

	if desired.Regions != nil && !slicesEqual(desired.Regions, existing.Regions) {
		patch.Regions = desired.Regions
		smthChanged = true
	}

	return patch, smthChanged
}

func DiffToPatchClientAuthentication(existing, desired ClientAuthenticationInformation) (ClientAuthenticationInformation, bool, error) {
	patch := ClientAuthenticationInformation{}
	var smthChanged bool

	desiredRaw, err := desired.ValueByDiscriminator()
	if err != nil {
		return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the desired 'clientAuthentication' field: %w", err)
	}
	existingRaw, err := existing.ValueByDiscriminator()
	if err != nil {
		return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the existing 'clientAuthentication' field: %w", err)
	}

	switch desiredVal := desiredRaw.(type) {
	case JwtJwksAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case JwtJwksAuthenticationInformation:
			var patchVal JwtJwksAuthenticationInformation
			if desiredVal.Urls != nil && !slicesEqual(desiredVal.Urls, existingVal.Urls) {
				patchVal.Urls = desiredVal.Urls
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtJwksAuthenticationInformation(patchVal)
				if err != nil {
					return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_JWKS in patch: %w", err)
				}
			}

		default:
			err = patch.FromJwtJwksAuthenticationInformation(desiredVal)
			smthChanged = true
		}
	case JwtOidcAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case JwtOidcAuthenticationInformation:
			var patchVal JwtOidcAuthenticationInformation
			if desiredVal.Audience != "" && desiredVal.Audience != existingVal.Audience {
				patchVal.Audience = desiredVal.Audience
				smthChanged = true
			}

			if desiredVal.BaseUrl != "" && desiredVal.BaseUrl != existingVal.BaseUrl {
				patchVal.BaseUrl = desiredVal.BaseUrl
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtOidcAuthenticationInformation(patchVal)
				if err != nil {
					return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_OIDC in patch: %w", err)
				}
			}
		default:
			err = patch.FromJwtOidcAuthenticationInformation(desiredVal)
			smthChanged = true
		}
	case JwtStandardClaimsAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case JwtStandardClaimsAuthenticationInformation:
			var patchVal JwtStandardClaimsAuthenticationInformation
			if desiredVal.Audience != "" && desiredVal.Audience != existingVal.Audience {
				patchVal.Audience = desiredVal.Audience
				smthChanged = true
			}

			patchJwtCl, fieldChanged := DiffToPatchJwtClientInformation(existingVal.Clients, desiredVal.Clients)
			smthChanged = smthChanged || fieldChanged
			patchVal.Clients = patchJwtCl

			if smthChanged {
				err = patch.FromJwtStandardClaimsAuthenticationInformation(patchVal)
				if err != nil {
					return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_STANDARD_CLAIMS in patch: %w", err)
				}
			}
		default:
			err = patch.FromJwtStandardClaimsAuthenticationInformation(desiredVal)
			if err != nil {
				return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_STANDARD_CLAIMS in patch: %w", err)
			}
			smthChanged = true
		}
	default:
		return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: unexpected, ValueByDiscriminator should have errored first for unsupported 'type' field value, got %T", desiredRaw)
	}
	return patch, smthChanged, nil
}

func DiffToPatchJwtClientInformation(existing, desired []JwtClientInformation) ([]JwtClientInformation, bool) {
	patch := []JwtClientInformation{}
	var smthChanged bool

	if len(desired) != len(existing) {
		patch = desired
		smthChanged = true
		return patch, smthChanged
	}

	patch = make([]JwtClientInformation, len(desired))
	for i := range len(desired) {
		if desired[i].AllowedPolicyIds != nil && !slicesEqual(desired[i].AllowedPolicyIds, existing[i].AllowedPolicyIds) {
			patch[i].AllowedPolicyIds = desired[i].AllowedPolicyIds
			smthChanged = true
		}

		if desired[i].Issuer != "" && desired[i].Issuer != existing[i].Issuer {
			patch[i].Issuer = desired[i].Issuer
			smthChanged = true
		}

		if desired[i].JwksUri != "" && desired[i].JwksUri != existing[i].JwksUri {
			patch[i].JwksUri = desired[i].JwksUri
			smthChanged = true
		}

		if desired[i].Name != "" && desired[i].Name != existing[i].Name {
			patch[i].Name = desired[i].Name
			smthChanged = true
		}

		if desired[i].Subjects != nil && !slicesEqual(desired[i].Subjects, existing[i].Subjects) {
			patch[i].Subjects = desired[i].Subjects
			smthChanged = true
		}
	}

	return patch, smthChanged
}

func DiffToPatchClientAuthorization(existing, desired ClientAuthorizationInformation) (ClientAuthorizationInformation, bool) {
	patch := ClientAuthorizationInformation{}
	var smthChanged bool

	if desired.CustomClaimsAliases.Configuration != "" && existing.CustomClaimsAliases.Configuration != desired.CustomClaimsAliases.Configuration {
		patch.CustomClaimsAliases.Configuration = desired.CustomClaimsAliases.Configuration
		smthChanged = true
	}

	if desired.CustomClaimsAliases.AllowAllPolicies != "" && existing.CustomClaimsAliases.AllowAllPolicies != desired.CustomClaimsAliases.AllowAllPolicies {
		patch.CustomClaimsAliases.AllowAllPolicies = desired.CustomClaimsAliases.AllowAllPolicies
		smthChanged = true
	}

	if desired.CustomClaimsAliases.AllowedPolicies != "" && existing.CustomClaimsAliases.AllowedPolicies != desired.CustomClaimsAliases.AllowedPolicies {
		patch.CustomClaimsAliases.AllowedPolicies = desired.CustomClaimsAliases.AllowedPolicies
		smthChanged = true
	}

	return patch, smthChanged
}
