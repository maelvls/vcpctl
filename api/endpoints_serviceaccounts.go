package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

func GetServiceAccounts(ctx context.Context, cl *Client) ([]ServiceAccountDetails, error) {
	resp, err := cl.GetV1Serviceaccounts(ctx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	case http.StatusUnauthorized:
		return nil, HTTPErrorFrom(resp)
	case http.StatusForbidden:
		return nil, HTTPErrorFrom(resp)
	default:
		return nil, HTTPErrorFrom(resp)
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("while reading service accounts: %w", err)
	}

	var result []ServiceAccountDetails
	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result, nil
}

func GetServiceAccountScopes(ctx context.Context, cl *Client) ([]ScopeDetails, error) {
	resp, err := cl.GetV1Serviceaccountscopes(ctx)
	if err != nil {
		return nil, fmt.Errorf("while making request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return nil, HTTPErrorFrom(resp)
	}

	body := new(bytes.Buffer)
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("while reading response body: %w", err)
	}

	var result []ScopeDetails
	if err := json.Unmarshal(body.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("while decoding %s response: %w, body was: %s", resp.Status, err, body.String())
	}

	return result, nil
}

func GetServiceAccount(ctx context.Context, cl *Client, nameOrID string) (ServiceAccountDetails, error) {
	if looksLikeAnID(nameOrID) {
		return GetServiceAccountByID(ctx, cl, nameOrID)
	}

	sas, err := GetServiceAccounts(ctx, cl)
	if err != nil {
		return ServiceAccountDetails{}, fmt.Errorf("while getting service accounts: %w", err)
	}

	// Error out if a duplicate service account name is found.
	var found []ServiceAccountDetails
	for _, sa := range sas {
		if sa.Name == nameOrID {
			found = append(found, sa)
		}
	}

	if len(found) == 0 {
		return ServiceAccountDetails{}, errutil.NotFound{NameOrID: nameOrID}
	}
	if len(found) == 1 {
		return found[0], nil
	}

	// If we have multiple service accounts with the same name, let the user
	// know about the duplicates.
	var b strings.Builder
	for _, sa := range found {
		_, _ = b.WriteString(fmt.Sprintf("  - %s (%s)\n", sa.Name, sa.Id))
	}
	return ServiceAccountDetails{}, fmt.Errorf(undent.Undent(`
		duplicate service account name '%s' found.
		The conflicting service accounts are:
		%s
		Please use a client ID (that's the same as the service account ID), or
		remove the duplicates using:
		    vcpctl sa rm %s
		`), nameOrID, b.String(), found[0].Id.String())
}

func GetServiceAccountByID(ctx context.Context, cl *Client, id string) (ServiceAccountDetails, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return ServiceAccountDetails{}, fmt.Errorf("getServiceAccountByID: while parsing service account ID '%s' as UUID: %w", id, err)
	}
	resp, err := cl.GetV1ServiceaccountsById(ctx, parsedID)
	if err != nil {
		return ServiceAccountDetails{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// The request was successful. Continue below to decode the response.
	default:
		return ServiceAccountDetails{}, HTTPErrorFrom(resp)
	}

	var result ServiceAccountDetails
	if err := decodeJSON(resp.Body, &result); err != nil {
		return ServiceAccountDetails{}, fmt.Errorf("getServiceAccountByID: while decoding response: %w", err)
	}
	return result, nil
}

// Owner can be left empty, in which case the first team will be used as the
// owner.
func CreateServiceAccount(ctx context.Context, cl *Client, desired ServiceAccountDetails) (CreateServiceAccountResponseBody, error) {
	// If no owner is specified, let's just use the first team we can find.
	if desired.Owner == (openapi_types.UUID{}) {
		teams, err := GetTeams(ctx, cl)
		if err != nil {
			return CreateServiceAccountResponseBody{}, fmt.Errorf("while getting teams: %w", err)
		}
		if len(teams) == 0 {
			return CreateServiceAccountResponseBody{}, fmt.Errorf("no teams found, please specify an owner")
		}
		ownerUUID := teams[0].Id

		logutil.Infof("ServiceAccount: no owner specified, using the first team '%s' (%s) as the owner.", teams[0].Name, teams[0].Id)
		desired.Owner = ownerUUID
	}

	resp, err := cl.CreateV1Serviceaccounts(ctx, APIToAPICreateServiceAccountRequestBody(desired))
	if err != nil {
		return CreateServiceAccountResponseBody{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// The creation was successful. Continue below to decode the response.
	case http.StatusConflict:
		return CreateServiceAccountResponseBody{}, fmt.Errorf("service account with the same name already exists, please choose a different name")
	default:
		return CreateServiceAccountResponseBody{}, HTTPErrorFrom(resp)
	}

	var result CreateServiceAccountResponseBody
	err = decodeJSON(resp.Body, &result)
	if err != nil {
		return CreateServiceAccountResponseBody{}, fmt.Errorf("while decoding response: %w", err)
	}
	return result, nil
}

func PatchServiceAccount(ctx context.Context, cl *Client, id string, patch PatchServiceAccountByClientIDRequestBody) error {
	uuidID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("patchServiceAccount: while parsing service account ID '%s' as UUID: %w", id, err)
	}

	resp, err := cl.PatchV1ServiceaccountsById(ctx, uuidID, patch)
	if err != nil {
		return fmt.Errorf("patchServiceAccount: while sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// The patch was successful.
	case http.StatusNotFound:
		return fmt.Errorf("service account: %w", errutil.NotFound{NameOrID: id})
	default:
		return HTTPErrorFrom(resp)
	}

	return nil
}

func DeleteServiceAccount(ctx context.Context, cl *Client, nameOrID string) error {
	var id string
	if looksLikeAnID(nameOrID) {
		id = nameOrID
	} else {
		sa, err := GetServiceAccount(ctx, cl, nameOrID)
		if err != nil {
			if errors.Is(err, errutil.NotFound{}) {
				return fmt.Errorf("service account '%s' not found", nameOrID)
			}
			return fmt.Errorf("while getting service account by name '%s': %w", nameOrID, err)
		}
		id = sa.Id.String()
	}

	uuidID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("removeServiceAccount: while parsing service account ID '%s' as UUID: %w", id, err)
	}
	resp, err := cl.DeleteV1ServiceaccountsById(ctx, uuidID)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("service account: %w", errutil.NotFound{NameOrID: id})
	case http.StatusNoContent:
		// The deletion was successful.
		return nil
	default:
		return HTTPErrorFrom(resp)
	}
}

func findServiceAccount(nameOrID string, allSAs []ServiceAccountDetails) (ServiceAccountDetails, error) {
	if looksLikeAnID(nameOrID) {
		for _, sa := range allSAs {
			if sa.Id.String() == nameOrID {
				return sa, nil
			}
		}
		return ServiceAccountDetails{}, errutil.NotFound{NameOrID: nameOrID}
	}

	for _, sa := range allSAs {
		if sa.Name == nameOrID {
			return sa, nil
		}
	}
	return ServiceAccountDetails{}, errutil.NotFound{NameOrID: nameOrID}
}
