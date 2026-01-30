package api

import (
	"fmt"
)

func DiffToPatchClientAuthentication(existing, desired ClientAuthenticationInformation) (ClientAuthenticationInformation, bool, error) {
	patch := ClientAuthenticationInformation{}
	var err error
	var smthChanged bool

	// The 'clientAuthentication' field is optional in the responses we get from
	// GET and POST, but the generated client has no way to handle optional
	// union types, so we skip the discriminator logic if the struct is
	// zero-valued.
	var desiredRaw any
	if !IsZero(desired) {
		desiredRaw, err = desired.ValueByDiscriminator()
		if err != nil {
			return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the desired 'clientAuthentication' field: %w", err)
		}
	}
	var existingRaw any
	if !IsZero(existing) {
		existingRaw, err = existing.ValueByDiscriminator()
		if err != nil {
			return patch, false, fmt.Errorf("diffToPatchClientAuthentication: while looking at the 'type' field under the existing 'clientAuthentication' field: %w", err)
		}
	}

	// The clientAuthentication object has all of its fields set to 'required':
	// when patching, we can't partially update it by omitting some fields, so
	// we need to copy over all existing fields even when they didn't change as
	// long one change happened in one of the fields.
	switch desiredVal := desiredRaw.(type) {
	case JwtJwksAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case JwtJwksAuthenticationInformation:
			patchVal := existingVal

			if !slicesEqual(desiredVal.Urls, existingVal.Urls) {
				patchVal.Urls = desiredVal.Urls
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtJwksAuthenticationInformation(patchVal)
				if err != nil {
					return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_JWKS in patch: %w", err)
				}
			}
		case nil, JwtOidcAuthenticationInformation, JwtStandardClaimsAuthenticationInformation:
			// The 'existing' type is different, which means we need to set the
			// whole desired value. (nil = clientAuthentication was empty).
			smthChanged = true
			err = patch.FromJwtJwksAuthenticationInformation(desiredVal)
		default:
			return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: unexpected case desired=%T,existing=%T", desiredVal, existingVal)
		}
	case JwtOidcAuthenticationInformation:
		switch existingVal := existingRaw.(type) {
		case JwtOidcAuthenticationInformation:
			patchVal := existingVal

			if desiredVal.Audience != existingVal.Audience {
				patchVal.Audience = desiredVal.Audience
				smthChanged = true
			}

			if desiredVal.BaseUrl != existingVal.BaseUrl {
				patchVal.BaseUrl = desiredVal.BaseUrl
				smthChanged = true
			}

			if smthChanged {
				err = patch.FromJwtOidcAuthenticationInformation(patchVal)
				if err != nil {
					return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_OIDC in patch: %w", err)
				}
			}
		case nil, JwtJwksAuthenticationInformation, JwtStandardClaimsAuthenticationInformation:
			// The 'existing' type is different, which means we need to set the
			// whole desired value. (nil = clientAuthentication was empty).
			smthChanged = true
			err = patch.FromJwtOidcAuthenticationInformation(desiredVal)
		default:
			return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: unexpected case desired=%T,existing=%T", desiredVal, existingVal)
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
		case nil, JwtJwksAuthenticationInformation, JwtOidcAuthenticationInformation:
			// The 'existing' type is different, which means we need to set the
			// whole desired value.
			err = patch.FromJwtStandardClaimsAuthenticationInformation(desiredVal)
			if err != nil {
				return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: while setting the 'clientAuthentication' field with type=JWT_STANDARD_CLAIMS in patch: %w", err)
			}
			smthChanged = true
		default:
			return ClientAuthenticationInformation{}, false, fmt.Errorf("diffToPatchClientAuthentication: unexpected case desired=%T,existing=%T", desiredVal, existingVal)
		}
	case nil:
		// The desired clientAuthentication field was left empty, which means we
		// don't need to do anything.
		return ClientAuthenticationInformation{}, false, nil
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

// We can't check if ClientAuthenticationInformation is empty by doing:
//
//	v != (ClientAuthenticationInformation{})
//
// because this struct contains a private field 'union'. So let's use JSON to
// check it.
func IsZero(in ClientAuthenticationInformation) bool {
	bytes, err := in.MarshalJSON()
	if err != nil {
		return false
	}
	if string(bytes) == "null" {
		return true
	}

	return false
}
