package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/errutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

func GetSubCAProviders(ctx context.Context, cl *Client) ([]SubCaProviderInformation, error) {
	resp, err := cl.SubcaproviderGetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return nil, HTTPErrorf(resp, "http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCaProviderInformation `json:"subCaProviders"`
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("getSubCas: while reading response body: %w", err)
	}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, fmt.Errorf("getSubCas: while decoding %s response: %w, body was: %s", resp.Status, err, string(bytes))
	}

	return result.SubCaProviders, nil
}

func GetSubCAProvider(ctx context.Context, cl *Client, nameOrID string) (SubCaProviderInformation, error) {
	if looksLikeAnID(nameOrID) {
		id := nameOrID
		return GetSubCAByID(ctx, cl, id)
	}

	resp, err := cl.SubcaproviderGetAll(ctx)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("getSubCa: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	default:
		return SubCaProviderInformation{}, HTTPErrorf(resp, "getSubCa: returned status code %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	var result struct {
		SubCaProviders []SubCaProviderInformation `json:"subCaProviders"`
	}
	if err := decodeJSON(resp.Body, &result); err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("getSubCa: while decoding response: %w", err)
	}

	// Error out if a duplicate name is found.
	var found []SubCaProviderInformation
	for _, provider := range result.SubCaProviders {
		if provider.Name == nameOrID {
			found = append(found, provider)
		}
	}
	if len(found) == 0 {
		return SubCaProviderInformation{}, fmt.Errorf("subCA provider: %w", errutil.NotFound{NameOrID: nameOrID})
	}
	if len(found) > 1 {
		b := strings.Builder{}
		for _, cur := range found {
			_, _ = b.WriteString(fmt.Sprintf("- %s (%s)\n", cur.Name, cur.Id.String()))
		}
		return SubCaProviderInformation{}, fmt.Errorf(undent.Undent(`
			getSubCa: duplicate sub CAs found with name '%s':
			%s
			Either use the subCA ID instead of the name, or remove one of the
			subCAs first with:
			    vcpctl subca rm %s
		`), nameOrID, b.String(), found[0].Id.String())
	}

	return found[0], nil
}

func GetSubCAByID(ctx context.Context, cl *Client, id string) (SubCaProviderInformation, error) {
	resp, err := cl.SubcaprovidersGetById(ctx, id)
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.
	case http.StatusNotFound:
		return SubCaProviderInformation{}, &errutil.NotFound{NameOrID: id}
	default:
		return SubCaProviderInformation{}, HTTPErrorf(resp, "http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	var result SubCaProviderInformation
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("getSubCaByID: while reading response body: %w", err)
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("getSubCaByID: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}
	if result.Id.String() == "" {
		return SubCaProviderInformation{}, errutil.Fixable(fmt.Errorf("getSubCaByID: SubCA provider '%s' not found", id))
	}
	return result, nil
}

func CreateSubCAProvider(ctx context.Context, cl *Client, provider SubCaProviderCreateRequest) (SubCaProviderInformation, error) {
	resp, err := cl.SubcaprovidersCreate(ctx, provider)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("createSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Continue below.
	default:
		return SubCaProviderInformation{}, HTTPErrorf(resp, "createSubCaProvider: returned status code %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("createSubCaProvider: while reading response body: %w", err)
	}

	var result SubCaProviderInformation
	err = json.Unmarshal(body, &result)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("createSubCaProvider: while decoding %s response: %w, body was: %s", resp.Status, err, string(body))
	}

	return result, nil
}

func PatchSubCAProvider(ctx context.Context, cl *Client, id string, patch SubCaProviderUpdateRequest) (SubCaProviderInformation, error) {
	resp, err := cl.SubcaprovidersUpdate(ctx, id, patch)
	if err != nil {
		return SubCaProviderInformation{}, fmt.Errorf("patchSubCaProvider: while creating request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The patch was successful.
		var updated SubCaProviderInformation
		if err := decodeJSON(resp.Body, &updated); err != nil {
			return SubCaProviderInformation{}, fmt.Errorf("patchSubCaProvider: while decoding response: %w", err)
		}
		return updated, nil
	case http.StatusNotFound:
		return SubCaProviderInformation{}, fmt.Errorf("WIMSubCAProvider: %w", errutil.NotFound{NameOrID: id})
	default:
		return SubCaProviderInformation{}, HTTPErrorf(resp, "patchSubCaProvider: http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}
}

func RemoveSubCaProvider(ctx context.Context, cl *Client, nameOrID string) error {
	if looksLikeAnID(nameOrID) {
		return RemoveSubCaProviderByID(ctx, cl, nameOrID)
	}

	subCA, err := GetSubCAProvider(ctx, cl, nameOrID)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while getting SubCA provider by name '%s': %w", nameOrID, err)
	}
	if subCA.Id.String() == "" {
		return errutil.Fixable(fmt.Errorf("removeSubCaProvider: SubCA provider '%s' not found", nameOrID))
	}
	return RemoveSubCaProviderByID(ctx, cl, subCA.Id.String())
}

func RemoveSubCaProviderByID(ctx context.Context, cl *Client, id string) error {
	resp, err := cl.SubcaprovidersDelete(ctx, id)
	if err != nil {
		return fmt.Errorf("removeSubCaProvider: while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		// Successfully removed.
		return nil
	default:
		return HTTPErrorf(resp, "http %s: %w", resp.Status, ParseJSONErrorOrDumpBody(resp))
	}
}

func DiffToPatchSubCAProvider(existing, desired SubCaProviderInformation) (SubCaProviderUpdateRequest, bool, error) {
	patch := SubCaProviderUpdateRequest{}
	var smthChanged bool

	if desired.CaAccountId != (openapi_types.UUID{}) && desired.CaAccountId != existing.CaAccountId {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CaAccountId of existing subCA provider")
	}

	if desired.CaProductOptionId != (openapi_types.UUID{}) && desired.CaProductOptionId != existing.CaProductOptionId {
		patch.CaProductOptionId = desired.CaProductOptionId
		smthChanged = true
	}

	if desired.CaType != "" && desired.CaType != existing.CaType {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CaType of existing subCA provider")
	}

	if desired.CommonName != "" && desired.CommonName != existing.CommonName {
		patch.CommonName = desired.CommonName
		smthChanged = true
	}

	if desired.Country != "" && desired.Country != existing.Country {
		patch.Country = desired.Country
		smthChanged = true
	}

	if desired.CreationDate != "" && desired.CreationDate != existing.CreationDate {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change CreationDate of existing subCA provider")
	}

	if desired.Id != (openapi_types.UUID{}) && desired.Id != existing.Id {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change Id of existing subCA provider")
	}

	if desired.KeyAlgorithm != "" && desired.KeyAlgorithm != existing.KeyAlgorithm {
		patch.KeyAlgorithm = SubCaProviderUpdateRequestKeyAlgorithm(desired.KeyAlgorithm)
		smthChanged = true
	}

	if desired.Locality != "" && desired.Locality != existing.Locality {
		patch.Locality = desired.Locality
		smthChanged = true
	}

	if desired.ModificationDate != "" && desired.ModificationDate != existing.ModificationDate {
		return SubCaProviderUpdateRequest{}, false, fmt.Errorf("cannot change ModificationDate of existing subCA provider")
	}

	if desired.Name != "" && desired.Name != existing.Name {
		patch.Name = desired.Name
		smthChanged = true
	}

	if desired.Organization != "" && desired.Organization != existing.Organization {
		patch.Organization = desired.Organization
		smthChanged = true
	}

	if desired.OrganizationalUnit != "" && desired.OrganizationalUnit != existing.OrganizationalUnit {
		patch.OrganizationalUnit = desired.OrganizationalUnit
		smthChanged = true
	}

	patch.Pkcs11 = DiffToPatchSubCaProviderPkcs11ConfigurationInformation(existing.Pkcs11, desired.Pkcs11)

	if desired.StateOrProvince != "" && desired.StateOrProvince != existing.StateOrProvince {
		patch.StateOrProvince = desired.StateOrProvince
		smthChanged = true
	}

	if desired.ValidityPeriod != "" && desired.ValidityPeriod != existing.ValidityPeriod {
		patch.ValidityPeriod = desired.ValidityPeriod
		smthChanged = true
	}

	return patch, smthChanged, nil
}

func DiffToPatchSubCaProviderPkcs11ConfigurationInformation(existing, desired SubCaProviderPkcs11ConfigurationInformation) SubCaProviderPkcs11ConfigurationInformation {
	patch := SubCaProviderPkcs11ConfigurationInformation{}

	if desired.AllowedClientLibraries != nil && !slicesEqual(desired.AllowedClientLibraries, existing.AllowedClientLibraries) {
		patch.AllowedClientLibraries = desired.AllowedClientLibraries
	}

	if desired.PartitionSerialNumber != "" && desired.PartitionSerialNumber != existing.PartitionSerialNumber {
		patch.PartitionSerialNumber = desired.PartitionSerialNumber
	}

	if desired.PartitionLabel != "" && desired.PartitionLabel != existing.PartitionLabel {
		patch.PartitionLabel = desired.PartitionLabel
	}

	if desired.Pin != "" && desired.Pin != existing.Pin {
		patch.Pin = desired.Pin
	}

	if desired.SigningEnabled != existing.SigningEnabled {
		patch.SigningEnabled = desired.SigningEnabled
	}

	return patch
}

// In Go, you can't compare structs that contain slices, maps, or functions
// directly, so it was impossible to do:
//
//	if p == (PKCS11{})...
//
// Alternatively, we could use reflect.DeepEqual, but that would have been
// overkill.
func isZeroPKCS11(p SubCaProviderPkcs11ConfigurationInformation) bool {
	return len(p.AllowedClientLibraries) == 0 &&
		p.PartitionLabel == "" &&
		p.PartitionSerialNumber == "" &&
		p.Pin == "" &&
		!p.SigningEnabled
}
