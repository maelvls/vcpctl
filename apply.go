package main

import (
	"context"
	"errors"
	"fmt"

	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// applyManifests walks through the provided manifests in order and applies each
// resource to CyberArk Certificate Manager, SaaS. Note that the manifests order
// matters.
func applyManifests(ctx context.Context, cl *api.Client, manifests []manifest.Manifest, dryRun bool) error {
	if err := validateManifests(manifests); err != nil {
		return fmt.Errorf("pre-flight validation failed: %w", err)
	}

	if err := validateReferences(ctx, cl, manifests); err != nil {
		return fmt.Errorf("reference validation failed: %w", err)
	}

	if dryRun {
		return applyManifestsDryRun(manifests)
	}

	applyCtx := newManifestApplyContext(ctx, cl)

	var successCount, failureCount int
	var errors []error

	for i, item := range manifests {
		var err error
		switch {
		case item.ServiceAccount != nil:
			err = applyCtx.applyServiceAccount(ctx, i, *item.ServiceAccount)
		case item.Policy != nil:
			err = applyCtx.applyPolicy(ctx, i, *item.Policy)
		case item.SubCa != nil:
			err = applyCtx.applySubCa(ctx, i, *item.SubCa)
		case item.WIMConfiguration != nil:
			err = applyCtx.applyConfig(ctx, i, *item.WIMConfiguration)
		default:
			err = fmt.Errorf("manifest #%d: empty or unknown manifest", i+1)
		}

		if err != nil {
			failureCount++
			errors = append(errors, err)
			// Fail-fast: return on first error
			return fmt.Errorf("manifest #%d: %w", i+1, err)
		} else {
			successCount++
		}
	}

	return nil
}

type manifestApplyContext struct {
	client *api.Client

	// Let's cache these resourcesto avoid having to fetch all service accounts,
	// sub CA providers, and policies every time we need to resolve a name to an
	// ID.
	//
	// Ideally, we should put a mutex... but not needed for now as nothing is
	// run currently for now.
	serviceAccounts map[string]api.ServiceAccountDetails
	policies        map[string]api.ExtendedPolicyInformation
	subCaProviders  map[string]api.SubCaProviderInformation
}

func newManifestApplyContext(ctx context.Context, cl *api.Client) *manifestApplyContext {
	return &manifestApplyContext{
		client:          cl,
		serviceAccounts: make(map[string]api.ServiceAccountDetails),
		policies:        make(map[string]api.ExtendedPolicyInformation),
		subCaProviders:  make(map[string]api.SubCaProviderInformation),
	}
}

func (applyctx *manifestApplyContext) applyServiceAccount(ctx context.Context, idx int, in manifest.ServiceAccount) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (ServiceAccount): name must be set", idx+1)
	}

	desired := manifestToAPIServiceAccount(in)
	existing, err := api.GetServiceAccount(ctx, applyctx.client, desired.Name)
	switch {
	case errors.As(err, &errutil.NotFound{}):
		createdResp, err := api.CreateServiceAccount(ctx, applyctx.client, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while creating: %w", idx+1, desired.Name, err)
		}

		// We ignore the fields 'publicKey' and 'privateKey' as we have provided
		// them in the request. These are only set when 'publicKey' isn't
		// provided in the creation request.
		//
		// We also ignore 'ociAccountName' and 'ociRegistryToken' as they aren't
		// used when authenticationType=rsaKey.
		desired.Id = createdResp.Id
		applyctx.serviceAccounts[desired.Name] = desired

		logutil.Infof("Created ServiceAccount '%s' with ID '%s'.", desired.Name, desired.Id.String())
	case err != nil:
		return fmt.Errorf("manifest #%d (ServiceAccount %q): while retrieving existing service account: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := api.DiffToPatchServiceAccount(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("ServiceAccount '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating ServiceAccount '%s'.", desired.Name)
		err = api.PatchServiceAccount(ctx, applyctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while patching: %w", idx+1, desired.Name, err)
		}
		updated, err := applyctx.refreshServiceAccount(ctx, desired.Name)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while refreshing state: %w", idx+1, desired.Name, err)
		}

		if logutil.EnableDebug {
			d := api.ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the Service Account '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (applyctx *manifestApplyContext) applyPolicy(ctx context.Context, idx int, in manifest.Policy) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy): name must be set", idx+1)
	}

	desired := manifestToAPIPolicy(in)
	existing, err := api.GetPolicy(ctx, applyctx.client, desired.Name)
	switch {
	case errors.As(err, &errutil.NotFound{}):
		created, err := api.CreatePolicy(ctx, applyctx.client, manifestToAPIPolicyCreateRequest(in))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while creating: %w", idx+1, desired.Name, err)
		}
		logutil.Infof("Created WIMIssuerPolicy '%s' with ID '%s'.", desired.Name, created.Id.String())
		applyctx.refreshPolicyWithExisting(created)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while retrieving existing policy: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := api.DiffToPatchPolicyUpdateRequest(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("WIMIssuerPolicy '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating WIMIssuerPolicy '%s'.", desired.Name)
		updated, err := api.PatchPolicy(ctx, applyctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while patching: %w", idx+1, desired.Name, err)
		}
		applyctx.refreshPolicyWithExisting(updated)

		if logutil.EnableDebug {
			d := api.ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the WIMIssuerPolicy '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (applyctx *manifestApplyContext) applySubCa(ctx context.Context, idx int, in manifest.SubCa) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider): name must be set", idx+1)
	}

	// The issuing template is needed when creating a new sub CA provider due to
	// the fields 'caType', 'caAccountId' and 'caProductOptionId'.
	desired, err := manifestToAPISubCa(func(s string) (api.CertificateIssuingTemplateInformation1, error) {
		return api.GetIssuingTemplateByName(ctx, applyctx.client, s)
	}, in)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while converting to API request: %w", idx+1, in.Name, err)
	}

	existing, err := api.GetSubCAProvider(ctx, applyctx.client, desired.Name)
	switch {
	case errors.As(err, &errutil.NotFound{}):
		created, err := api.CreateSubCAProvider(ctx, applyctx.client, api.APIToAPISubCaProviderCreateRequest(desired))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while creating: %w", idx+1, desired.Name, err)
		}
		logutil.Infof("Created WIMSubCAProvider '%s' with ID '%s'.", desired.Name, created.Id.String())
		applyctx.refreshSubCaWithExisting(created)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while retrieving existing SubCA provider: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := api.DiffToPatchSubCAProvider(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("WIMSubCAProvider '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating WIMSubCAProvider '%s'.", desired.Name)
		updated, err := api.PatchSubCAProvider(ctx, applyctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while patching: %w", idx+1, desired.Name, err)
		}
		applyctx.refreshSubCaWithExisting(updated)

		if logutil.EnableDebug {
			d := api.ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the WIM SubCA Provider '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (applyctx *manifestApplyContext) applyConfig(ctx context.Context, idx int, in manifest.WIMConfiguration) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMConfiguration): name must be set", idx+1)
	}

	var serviceAccountIDs []openapi_types.UUID
	var policies []api.PolicyInformation
	var policyIDs []openapi_types.UUID

	for _, saName := range in.ServiceAccountNames {
		sa, err := applyctx.resolveServiceAccount(ctx, saName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving service account %q: %w", idx+1, in.Name, saName, err)
		}
		serviceAccountIDs = append(serviceAccountIDs, sa.Id)
	}

	for _, policyName := range in.PolicyNames {
		policy, err := applyctx.resolvePolicy(ctx, policyName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving policy %q: %w", idx+1, in.Name, policyName, err)
		}
		policyInfo := api.PolicyInformation{
			Name: policy.Name,
			Id:   policy.Id,
		}
		policyIDs = append(policyIDs, policy.Id)
		policies = append(policies, policyInfo)
	}

	desired, err := manifestToAPIExtendedConfigurationInformation(ctx, applyctx.resolvePolicy, applyctx.resolveServiceAccount, applyctx.resolveSubCa, in)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMConfiguration %q): while converting to API request: %w", idx+1, in.Name, err)
	}

	existing, err := api.GetConfig(ctx, applyctx.client, in.Name)
	switch {
	case errors.As(err, &errutil.NotFound{}):
		created, err := api.CreateConfig(ctx, applyctx.client, api.APIToAPIConfigurationCreateRequest(desired))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while creating: %w", idx+1, in.Name, err)
		}
		logutil.Infof("Created WIMConfiguration '%s' with ID '%s'.", in.Name, created.Id.String())
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMConfiguration %q): while retrieving existing configuration: %w", idx+1, in.Name, err)
	default:
		patch, changed, err := api.DiffToPatchConfig(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while computing patch: %w", idx+1, in.Name, err)
		}
		if !changed {
			logutil.Infof("WIMConfiguration '%s' is up to date; no changes needed.", in.Name)
			break
		}

		logutil.Infof("Updating WIMConfiguration '%s' (ID '%s').", in.Name, existing.Id.String())
		updated, err := api.PatchConfig(ctx, applyctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while patching: %w", idx+1, in.Name, err)
		}

		if logutil.EnableDebug {
			d := api.ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the WIMConfiguration '%s':\n%s", in.Name, d)
		}
	}

	return nil
}

func (applyctx *manifestApplyContext) resolveServiceAccount(ctx context.Context, name string) (api.ServiceAccountDetails, error) {
	if sa, ok := applyctx.serviceAccounts[name]; ok {
		return sa, nil
	}
	return applyctx.refreshServiceAccount(ctx, name)
}

func (applyctx *manifestApplyContext) refreshServiceAccount(ctx context.Context, name string) (api.ServiceAccountDetails, error) {
	sa, err := api.GetServiceAccount(ctx, applyctx.client, name)
	if err != nil {
		return api.ServiceAccountDetails{}, err
	}
	applyctx.serviceAccounts[name] = sa
	return sa, nil
}

func (applyctx *manifestApplyContext) resolvePolicy(ctx context.Context, name string) (api.ExtendedPolicyInformation, error) {
	if policy, ok := applyctx.policies[name]; ok {
		return policy, nil
	}
	return applyctx.refreshPolicy(ctx, name)
}

func (applyctx *manifestApplyContext) refreshPolicy(ctx context.Context, name string) (api.ExtendedPolicyInformation, error) {
	policy, err := api.GetPolicy(ctx, applyctx.client, name)
	if err != nil {
		return api.ExtendedPolicyInformation{}, err
	}
	applyctx.policies[name] = policy
	return policy, nil
}

func (applyctx *manifestApplyContext) refreshPolicyWithExisting(updated api.ExtendedPolicyInformation) {
	applyctx.policies[updated.Name] = updated
}

func (applyctx *manifestApplyContext) resolveSubCa(ctx context.Context, name string) (api.SubCaProviderInformation, error) {
	if subca, ok := applyctx.subCaProviders[name]; ok {
		return subca, nil
	}

	err := applyctx.refreshSubCaWithName(ctx, name)
	if err != nil {
		return api.SubCaProviderInformation{}, err
	}

	return applyctx.subCaProviders[name], nil
}

func (applyctx *manifestApplyContext) refreshSubCaWithName(ctx context.Context, name string) error {
	subca, err := api.GetSubCAProvider(ctx, applyctx.client, name)
	if err != nil {
		return err
	}
	applyctx.subCaProviders[name] = subca
	return nil
}

func (applyctx *manifestApplyContext) refreshSubCaWithExisting(updated api.SubCaProviderInformation) {
	applyctx.subCaProviders[updated.Name] = updated
}

func (applyctx *manifestApplyContext) refreshSubCaWithID(ctx context.Context, id string) error {
	subca, err := api.GetSubCAByID(ctx, applyctx.client, id)
	if err != nil {
		return err
	}
	applyctx.subCaProviders[subca.Name] = subca
	return nil
}

func getManifestKind(m manifest.Manifest) string {
	switch {
	case m.ServiceAccount != nil:
		return kindServiceAccount
	case m.Policy != nil:
		return kindIssuerPolicy
	case m.SubCa != nil:
		return kindWIMSubCaProvider
	case m.WIMConfiguration != nil:
		return kindConfiguration
	default:
		return "unknown"
	}
}

// validateManifests performs pre-flight validation: checks that all required names are set
func validateManifests(manifests []manifest.Manifest) error {
	for i, m := range manifests {
		switch {
		case m.ServiceAccount != nil:
			if m.ServiceAccount.Name == "" {
				return fmt.Errorf("manifest #%d (ServiceAccount): name must be set", i+1)
			}
		case m.Policy != nil:
			if m.Policy.Name == "" {
				return fmt.Errorf("manifest #%d (WIMIssuerPolicy): name must be set", i+1)
			}
		case m.SubCa != nil:
			if m.SubCa.Name == "" {
				return fmt.Errorf("manifest #%d (WIMSubCAProvider): name must be set", i+1)
			}
		case m.WIMConfiguration != nil:
			if m.WIMConfiguration.Name == "" {
				return fmt.Errorf("manifest #%d (WIMConfiguration): name must be set", i+1)
			}
		default:
			return fmt.Errorf("manifest #%d: empty or unknown manifest", i+1)
		}
	}
	return nil
}

// validateReferences checks that all referenced resources exist in manifests or
// API.
func validateReferences(ctx context.Context, cl *api.Client, manifests []manifest.Manifest) error {
	// Build sets of names defined in manifests
	serviceAccountNames := make(map[string]bool)
	policyNames := make(map[string]bool)
	subCaNames := make(map[string]bool)

	for _, m := range manifests {
		if m.ServiceAccount != nil && m.ServiceAccount.Name != "" {
			serviceAccountNames[m.ServiceAccount.Name] = true
		}
		if m.Policy != nil && m.Policy.Name != "" {
			policyNames[m.Policy.Name] = true
		}
		if m.SubCa != nil && m.SubCa.Name != "" {
			subCaNames[m.SubCa.Name] = true
		}
	}

	// Validate references in WIMConfiguration manifests
	for i, m := range manifests {
		if m.WIMConfiguration == nil {
			continue
		}

		cfg := m.WIMConfiguration

		// Validate service account references
		for _, saName := range cfg.ServiceAccountNames {
			if !serviceAccountNames[saName] {
				// Check if it exists in API
				_, err := api.GetServiceAccount(ctx, cl, saName)
				if err != nil {
					if errors.As(err, &errutil.NotFound{}) {
						return errutil.Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): service account %q not found in manifests or API", i+1, cfg.Name, saName))
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking service account %q: %w", i+1, cfg.Name, saName, err)
				}
			}
		}

		// Validate policy references
		for _, policyName := range cfg.PolicyNames {
			if !policyNames[policyName] {
				// Check if it exists in API
				_, err := api.GetPolicy(ctx, cl, policyName)
				if err != nil {
					if errors.As(err, &errutil.NotFound{}) {
						return errutil.Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): policy %q not found in manifests or API", i+1, cfg.Name, policyName))
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking policy %q: %w", i+1, cfg.Name, policyName, err)
				}
			}
		}

		// Validate subCA provider reference
		if cfg.SubCaProviderName != "" {
			if !subCaNames[cfg.SubCaProviderName] {
				// Check if it exists in API
				_, err := api.GetSubCAProvider(ctx, cl, cfg.SubCaProviderName)
				if err != nil {
					if errors.As(err, &errutil.NotFound{}) {
						return errutil.Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): subCA provider %q not found in manifests or API", i+1, cfg.Name, cfg.SubCaProviderName))
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking subCA provider %q: %w", i+1, cfg.Name, cfg.SubCaProviderName, err)
				}
			}
		}
	}

	return nil
}

// applyManifestsDryRun shows what would be created/updated without making API calls
func applyManifestsDryRun(manifests []manifest.Manifest) error {
	logutil.Infof("DRY RUN: Would apply %d manifest(s):", len(manifests))
	for i, m := range manifests {
		switch {
		case m.ServiceAccount != nil:
			logutil.Infof("  #%d: ServiceAccount '%s' (would create or update)", i+1, m.ServiceAccount.Name)
		case m.Policy != nil:
			logutil.Infof("  #%d: WIMIssuerPolicy '%s' (would create or update)", i+1, m.Policy.Name)
		case m.SubCa != nil:
			logutil.Infof("  #%d: WIMSubCAProvider '%s' (would create or update)", i+1, m.SubCa.Name)
		case m.WIMConfiguration != nil:
			logutil.Infof("  #%d: WIMConfiguration '%s' (would create or update)", i+1, m.WIMConfiguration.Name)
		}
	}
	return nil
}

// printApplySummary prints a summary of the apply operation
func printApplySummary(successCount, failureCount, skippedCount, totalCount int) {
	if failureCount == 0 {
		logutil.Infof("Successfully applied %d resource(s).", successCount)
	} else {
		logutil.Errorf("Applied %d of %d resource(s) (%d failed).", successCount, totalCount, failureCount)
	}
}
