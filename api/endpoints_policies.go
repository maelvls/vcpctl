package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/errutil"
)

func GetPolicies(ctx context.Context, cl *Client) ([]ExtendedPolicyInformation, error) {
	resp, err := cl.PoliciesGetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return nil, HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getPolicies: while reading response body: %w", err)
	}

	var result struct {
		Policies []ExtendedPolicyInformation `json:"policies"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("getPolicies: while decoding response: %w, body was: %s", err, string(body))
	}
	return result.Policies, nil
}

func GetPolicy(ctx context.Context, cl *Client, nameOrID string) (ExtendedPolicyInformation, error) {
	if looksLikeAnID(nameOrID) {
		return GetPolicyByID(ctx, cl, nameOrID)
	}

	policies, err := GetPolicies(ctx, cl)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("GetPolicy: while getting policies: %w", err)
	}

	// Find the policy by name. Error out if duplicate names are found.
	var found []ExtendedPolicyInformation
	for _, cur := range policies {
		if cur.Name == nameOrID {
			found = append(found, cur)
		}
	}
	if len(found) == 0 {
		return ExtendedPolicyInformation{}, errutil.NotFound{NameOrID: nameOrID}
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, cur := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s) created on %s\n", cur.Name, cur.Id.String(), cur.CreationDate))
		}
		return ExtendedPolicyInformation{}, fmt.Errorf(undent.Undent(`
			GetPolicy: duplicate policies found with name '%s':
			%s
			Please use an ID instead, or try to remove one of the service accounts
			first with:
			    vcpctl sa rm %s
			`), nameOrID, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func GetPolicyByID(ctx context.Context, cl *Client, id string) (ExtendedPolicyInformation, error) {
	resp, err := cl.PoliciesGetById(ctx, id)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("GetPolicyByID: while making request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// Continue below.
	default:
		return ExtendedPolicyInformation{}, HTTPErrorFrom(resp)
	}
	var result ExtendedPolicyInformation
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("GetPolicyByID: while reading %s response body: %w", resp.Status, err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("GetPolicyByID: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	return result, nil
}

func CreatePolicy(ctx context.Context, cl *Client, policy PolicyCreateRequest) (ExtendedPolicyInformation, error) {
	resp, err := cl.PoliciesCreate(ctx, policy)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("CreatePolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return ExtendedPolicyInformation{}, HTTPErrorFrom(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("CreatePolicy: while reading response body: %w", err)
	}

	var result ExtendedPolicyInformation
	err = json.Unmarshal(body, &result)
	if err != nil {
		return ExtendedPolicyInformation{}, fmt.Errorf("CreatePolicy: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

// https://api.venafi.cloud/v1/distributedissuers/policies/{id}
func PatchPolicy(ctx context.Context, cl *Client, id string, patch PolicyUpdateRequest) (ExtendedPolicyInformation, error) {
	resp, err := cl.PoliciesUpdate(ctx, id, patch)
	if err != nil {
		return ExtendedPolicyInformation{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		var updated ExtendedPolicyInformation
		err := decodeJSON(resp.Body, &updated)
		if err != nil {
			return ExtendedPolicyInformation{}, fmt.Errorf("while decoding response: %w, body: %s", err, resp.Body)
		}
		return updated, nil
	case http.StatusNotFound:
		return ExtendedPolicyInformation{}, fmt.Errorf("Workload Identity Manager policy: %w", errutil.NotFound{NameOrID: id})
	default:
		return ExtendedPolicyInformation{}, HTTPErrorFrom(resp)
	}
}

func RemovePolicy(ctx context.Context, cl *Client, policyName string) error {
	// Find the policy by name.
	policy, err := GetPolicy(ctx, cl, policyName)
	if err != nil {
		return fmt.Errorf("RemovePolicy: while getting policy by name %q: %w", policyName, err)
	}

	resp, err := cl.PoliciesDelete(ctx, policy.Id.String())
	if err != nil {
		return fmt.Errorf("RemovePolicy: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return HTTPErrorFrom(resp)
	}
}

func DiffToPatchServiceAccount(existing, desired ServiceAccountDetails) (PatchServiceAccountByClientIDRequestBody, bool, error) {
	patch := PatchServiceAccountByClientIDRequestBody{}
	var smthChanged bool

	if desired.Applications != nil && !slicesEqual(desired.Applications, existing.Applications) {
		patch.Applications = desired.Applications
		smthChanged = true
	}

	if desired.Audience != "" && desired.Audience != existing.Audience {
		patch.Audience = desired.Audience
		smthChanged = true
	}

	if desired.AuthenticationType != "" && desired.AuthenticationType != existing.AuthenticationType {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'authenticationType' field on an existing service account")
	}

	if desired.CompanyId != (uuid.UUID{}) && desired.CompanyId != existing.CompanyId {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'companyId' field on an existing service account")
	}

	if desired.Enabled != existing.Enabled {
		patch.Enabled.Set(desired.Enabled)
		smthChanged = true
	}

	// The assumption is that a zero 'credentialLifetime' isn't valid, which
	// means the zero value means "I don't want to change this field".
	if desired.CredentialLifetime != 0 && desired.CredentialLifetime != existing.CredentialLifetime {
		patch.CredentialLifetime = desired.CredentialLifetime
		smthChanged = true
	}

	// The assumption is that an empty 'credentialsExpiringOn' isn't valid,
	// which means the zero value means "I don't want to change this field".
	if !desired.CredentialsExpiringOn.IsZero() && !desired.CredentialsExpiringOn.Equal(existing.CredentialsExpiringOn) {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'credentialsExpiringOn' field on an existing service account")
	}

	if desired.IssuerURL != "" && desired.IssuerURL != existing.IssuerURL {
		patch.IssuerURL = desired.IssuerURL
		smthChanged = true
	}

	if desired.JwksURI != "" && desired.JwksURI != existing.JwksURI {
		patch.JwksURI = desired.JwksURI
		smthChanged = true
	}

	if !desired.LastUsedOn.IsZero() && desired.LastUsedOn != existing.LastUsedOn {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'lastUsedOn' field on an existing service account")
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Owner != (uuid.UUID{}) && desired.Owner != existing.Owner {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'owner' field on an existing service account")
	}

	if desired.PublicKey != "" && desired.PublicKey != existing.PublicKey {
		patch.PublicKey = desired.PublicKey
		smthChanged = true
	}

	if desired.Scopes != nil && !slicesEqual(desired.Scopes, existing.Scopes) {
		patch.Scopes = desired.Scopes
		smthChanged = true
	}

	if desired.Subject != "" && desired.Subject != existing.Subject {
		patch.Subject = desired.Subject
		smthChanged = true
	}

	if desired.UpdatedBy != (uuid.UUID{}) && desired.UpdatedBy != existing.UpdatedBy {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'updatedBy' field on an existing service account")
	}

	if !desired.UpdatedOn.IsZero() && !desired.UpdatedOn.Equal(existing.UpdatedOn) {
		return PatchServiceAccountByClientIDRequestBody{}, false, fmt.Errorf("cannot change the 'updatedOn' field on an existing service account")
	}

	return patch, smthChanged, nil
}

func PoliciesEqual(a, b []PolicyInformation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].CompanyId != b[i].CompanyId {
			return false
		}
		if a[i].CreationDate != b[i].CreationDate {
			return false
		}

		if !slicesEqual(a[i].ExtendedKeyUsages, b[i].ExtendedKeyUsages) {
			return false
		}

		if a[i].Id != b[i].Id {
			return false
		}

		_, changed, _ := DiffToPatchKeyAlgorithmInformation(a[i].KeyAlgorithm, b[i].KeyAlgorithm)
		if changed {
			return false
		}

		if !slicesEqual(a[i].KeyUsages, b[i].KeyUsages) {
			return false
		}

		if a[i].ModificationDate != b[i].ModificationDate {
			return false
		}

		if a[i].Name != b[i].Name {
			return false
		}

		_, changed, _ = DiffToPatchSansInformation(a[i].Sans, b[i].Sans)
		if changed {
			return false
		}

		_, changed, _ = DiffToPatchSubjectAttributesInformation(a[i].Subject, b[i].Subject)
		if changed {
			return false
		}

		if a[i].ValidityPeriod != b[i].ValidityPeriod {
			return false
		}
	}

	return true
}

func DiffToPatchPolicyUpdateRequest(existing, desired ExtendedPolicyInformation) (PolicyUpdateRequest, bool, error) {
	patch := PolicyUpdateRequest{}
	var smthChanged, fieldChanged bool

	if desired.CompanyId.ID() != 0 && desired.CompanyId != existing.CompanyId {
		return PolicyUpdateRequest{}, false, fmt.Errorf("cannot change CompanyId of existing policy")
	}

	if len(desired.Configurations) > 0 && !reflect.DeepEqual(desired.Configurations, existing.Configurations) {
		return PolicyUpdateRequest{}, false, fmt.Errorf("cannot change Configurations of existing policy")
	}

	if len(desired.ExtendedKeyUsages) > 0 && !slicesEqual(desired.ExtendedKeyUsages, existing.ExtendedKeyUsages) {
		for _, eku := range desired.ExtendedKeyUsages {
			patch.ExtendedKeyUsages = append(patch.ExtendedKeyUsages, PolicyUpdateRequestExtendedKeyUsages(eku))
		}
		smthChanged = true
	}

	var err error
	patch.KeyAlgorithm, fieldChanged, err = DiffToPatchKeyAlgorithmInformation(existing.KeyAlgorithm, desired.KeyAlgorithm)
	if err != nil {
		return PolicyUpdateRequest{}, false, err
	}
	smthChanged = smthChanged || fieldChanged

	if len(desired.KeyUsages) > 0 && !slicesEqual(desired.KeyUsages, existing.KeyUsages) {
		var usages []PolicyUpdateRequestKeyUsages
		for _, ku := range desired.KeyUsages {
			usages = append(usages, PolicyUpdateRequestKeyUsages(ku))
		}
		patch.KeyUsages = usages
		smthChanged = true
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	patch.Sans, fieldChanged, err = DiffToPatchSansInformation(existing.Sans, desired.Sans)
	if err != nil {
		return PolicyUpdateRequest{}, false, fmt.Errorf("diffToPatchPolicy: while comparing the 'sans' field on the existing and desired policies: %w", err)
	}
	patch.Subject, fieldChanged, err = DiffToPatchSubjectAttributesInformation(existing.Subject, desired.Subject)
	if err != nil {
		return PolicyUpdateRequest{}, false, fmt.Errorf("diffToPatchPolicy: while comparing the 'subject' field on the existing and desired policies: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	if desired.ValidityPeriod != "" && desired.ValidityPeriod != existing.ValidityPeriod {
		patch.ValidityPeriod = desired.ValidityPeriod
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func DiffToPatchKeyAlgorithmInformation(existing, desired KeyAlgorithmInformation) (KeyAlgorithmInformation, bool, error) {
	patch := KeyAlgorithmInformation{}
	var smthChanged bool

	if desired.AllowedValues != nil && !slicesEqual(desired.AllowedValues, existing.AllowedValues) {
		patch.AllowedValues = desired.AllowedValues
		smthChanged = true
	}

	if desired.DefaultValue != "" && desired.DefaultValue != existing.DefaultValue {
		patch.DefaultValue = desired.DefaultValue
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func DiffToPatchSansInformation(existing, desired SansInformation) (SansInformation, bool, error) {
	patch := SansInformation{}
	var fieldWasChanged, somethingChanged bool
	var err error

	patch.DnsNames, fieldWasChanged, err = DiffToPatchPropertyInformation(existing.DnsNames, desired.DnsNames)
	if err != nil {
		return SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'dnsNames' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.IpAddresses, fieldWasChanged, err = DiffToPatchPropertyInformation(existing.IpAddresses, desired.IpAddresses)
	if err != nil {
		return SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'ipAddresses' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.Rfc822Names, fieldWasChanged, err = DiffToPatchPropertyInformation(existing.Rfc822Names, desired.Rfc822Names)
	if err != nil {
		return SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'rfc822Names' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	patch.UniformResourceIdentifiers, fieldWasChanged, err = DiffToPatchPropertyInformation(existing.UniformResourceIdentifiers, desired.UniformResourceIdentifiers)
	if err != nil {
		return SansInformation{}, false, fmt.Errorf("diffToPatchSansInformation: while comparing the 'uniformResourceIdentifiers' field on the existing and desired 'sans' field: %w", err)
	}
	somethingChanged = somethingChanged || fieldWasChanged

	return patch, somethingChanged, nil
}

func DiffToPatchSubjectAttributesInformation(existing, desired SubjectAttributesInformation) (SubjectAttributesInformation, bool, error) {
	patch := SubjectAttributesInformation{}
	var smthChanged, fieldChanged bool
	var err error

	patch.CommonName, fieldChanged, err = DiffToPatchPropertyInformation(existing.CommonName, desired.CommonName)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'commonName' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Country, fieldChanged, err = DiffToPatchPropertyInformation(existing.Country, desired.Country)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'country' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Locality, fieldChanged, err = DiffToPatchPropertyInformation(existing.Locality, desired.Locality)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'locality' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.Organization, fieldChanged, err = DiffToPatchPropertyInformation(existing.Organization, desired.Organization)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'organization' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.OrganizationalUnit, fieldChanged, err = DiffToPatchPropertyInformation(existing.OrganizationalUnit, desired.OrganizationalUnit)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'organizationalUnit' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	patch.StateOrProvince, fieldChanged, err = DiffToPatchPropertyInformation(existing.StateOrProvince, desired.StateOrProvince)
	if err != nil {
		return SubjectAttributesInformation{}, false, fmt.Errorf("diffToPatchSubjectAttributesInformation: while comparing the 'stateOrProvince' field on the existing and desired 'subject' field: %w", err)
	}
	smthChanged = smthChanged || fieldChanged

	return patch, smthChanged, nil
}

func DiffToPatchPropertyInformation(existing, desired PropertyInformation) (PropertyInformation, bool, error) {
	patch := PropertyInformation{}
	changed := false

	if desired.AllowedValues != nil && !slicesEqual(desired.AllowedValues, existing.AllowedValues) {
		changed = true
	}

	if desired.DefaultValues != nil && !slicesEqual(desired.DefaultValues, existing.DefaultValues) {
		changed = true
	}

	if desired.MaxOccurrences != existing.MaxOccurrences {
		changed = true
	}

	if desired.MinOccurrences != existing.MinOccurrences {
		changed = true
	}

	if desired.Type != "" && desired.Type != existing.Type {
		changed = true
	}

	if changed {
		// All fields are mandatory if a change needs to be made to one of the
		// values. Thus, if a change is needed in one of the fields, the
		// existing values are carried over so that the API doesn't fail.
		// Otherwise, we keep everything zeroed out so that this field isn't
		// rendered to JSON.
		patch.Type = desired.Type
		patch.MinOccurrences = desired.MinOccurrences
		patch.MaxOccurrences = desired.MaxOccurrences
		patch.AllowedValues = desired.AllowedValues
		patch.DefaultValues = desired.DefaultValues

		err := validatePropertyInformation(patch)
		if err != nil {
			return PropertyInformation{}, false, err
		}
	}

	return patch, changed, nil
}

// Note that the logic for checking these fields ('type', 'maxOccurrences', etc)
// does not show any explanation whenever an error is found. The only way to
// know what the problem is is to look at the backend code... See:
// https://gitlab.com/venafi/vaas/applications/tls-protect/outage/-/blob/master/vcamanagement-service/src/main/java/com/venafi/condor/vcamanagement/web/v1/resource/VenafiCaIssuerPoliciesResourceV1.java#L545
func validatePropertyInformation(pi PropertyInformation) error {
	if pi.Type == "" &&
		pi.MinOccurrences == 0 &&
		pi.MaxOccurrences == 0 &&
		len(pi.AllowedValues) == 0 &&
		len(pi.DefaultValues) == 0 {
		// The JSON object is omitted entirely if all fields are zeroed out.
		// That's why it is allowed.
		return nil
	}

	if pi.Type == "" {
		return errutil.Fixable(fmt.Errorf("property information 'type' field is required"))
	}

	switch pi.Type {
	case "IGNORED", "FORBIDDEN":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		if len(pi.AllowedValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'allowedValues' field must be empty, but was %v", pi.Type, pi.AllowedValues)
		}
		if len(pi.DefaultValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must be empty, but was %v", pi.Type, pi.DefaultValues)
		}
	case "OPTIONAL":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences <= 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be greater than 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		for _, v := range pi.AllowedValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'allowedValues' field must not contain blank values, but was %v", pi.Type, pi.AllowedValues)
			}
		}
		for _, v := range pi.DefaultValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not contain blank values, but was %v", pi.Type, pi.DefaultValues)
			}
		}
	case "REQUIRED":
		if pi.MinOccurrences <= 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be greater than 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences < pi.MinOccurrences {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be greater than or equal to 'minOccurrences', but was %d", pi.Type, pi.MaxOccurrences)
		}
		for _, v := range pi.AllowedValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'allowedValues' field must not contain blank values, but was %v", pi.Type, pi.AllowedValues)
			}
		}
		if len(pi.DefaultValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must be empty, but was %v", pi.Type, pi.DefaultValues)
		}
	case "LOCKED":
		if pi.MinOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'minOccurrences' field must be 0, but was %d", pi.Type, pi.MinOccurrences)
		}
		if pi.MaxOccurrences != 0 {
			return fmt.Errorf("for property information of type %s, the 'maxOccurrences' field must be 0, but was %d", pi.Type, pi.MaxOccurrences)
		}
		if len(pi.AllowedValues) != 0 {
			return fmt.Errorf("for property information of type %s, the 'allowedValues' field must be empty, but was %v", pi.Type, pi.AllowedValues)
		}
		if len(pi.DefaultValues) == 0 {
			return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not be empty, but was %v", pi.Type, pi.DefaultValues)
		}
		for _, v := range pi.DefaultValues {
			if v == "" {
				return fmt.Errorf("for property information of type %s, the 'defaultValues' field must not contain blank values, but was %v", pi.Type, pi.DefaultValues)
			}
		}
	default:
		return errutil.Fixable(fmt.Errorf("property information 'type' field has invalid value: %s", pi.Type))
	}

	return nil
}
