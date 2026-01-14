package main

import (
	"context"
	"errors"
	"fmt"

	api "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"
	"github.com/maelvls/vcpctl/logutil"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// applyManifests walks through the provided manifests in order and applies each
// resource to CyberArk Certificate Manager, SaaS. Note that the manifests order
// matters.
func applyManifests(cl *api.Client, manifests []manifest.Manifest, dryRun bool) error {
	if err := validateManifests(manifests); err != nil {
		return fmt.Errorf("pre-flight validation failed: %w", err)
	}

	if err := validateReferences(cl, manifests); err != nil {
		return fmt.Errorf("reference validation failed: %w", err)
	}

	if dryRun {
		return applyManifestsDryRun(manifests)
	}

	applyCtx := newManifestApplyContext(context.Background(), cl)

	var successCount, failureCount int
	var errors []error

	for i, item := range manifests {
		var err error
		switch {
		case item.ServiceAccount != nil:
			err = applyCtx.applyServiceAccount(i, *item.ServiceAccount)
		case item.Policy != nil:
			err = applyCtx.applyPolicy(i, *item.Policy)
		case item.SubCa != nil:
			err = applyCtx.applySubCa(i, *item.SubCa)
		case item.WIMConfiguration != nil:
			err = applyCtx.applyConfig(i, *item.WIMConfiguration)
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
	client          *api.Client
	apiURL          string
	apiKey          string
	serviceAccounts map[string]ServiceAccount
	policies        map[string]Policy
	subCaProviders  map[string]SubCa
}

func newManifestApplyContext(ctx context.Context, cl *api.Client) *manifestApplyContext {
	return &manifestApplyContext{
		client:          cl,
		serviceAccounts: make(map[string]ServiceAccount),
		policies:        make(map[string]Policy),
		subCaProviders:  make(map[string]SubCa),
	}
}

func (ctx *manifestApplyContext) applyServiceAccount(idx int, in manifest.ServiceAccount) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (ServiceAccount): name must be set", idx+1)
	}

	desired := manifestToAPIServiceAccount(in)
	existing, err := getServiceAccount(context.Background(), ctx.client, desired.Name)
	switch {
	case errors.As(err, &NotFound{}):
		createdResp, err := createServiceAccount(context.Background(), ctx.client, desired)
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
		ctx.serviceAccounts[desired.Name] = desired

		logutil.Infof("Created service account '%s' with ID '%s'.", desired.Name, desired.Id.String())
	case err != nil:
		return fmt.Errorf("manifest #%d (ServiceAccount %q): while retrieving existing service account: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := diffToPatchServiceAccount(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("ServiceAccount '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating ServiceAccount '%s'.", desired.Name)
		err = patchServiceAccount(context.Background(), ctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while patching: %w", idx+1, desired.Name, err)
		}
		updated, err := ctx.refreshServiceAccount(desired.Name)
		if err != nil {
			return fmt.Errorf("manifest #%d (ServiceAccount %q): while refreshing state: %w", idx+1, desired.Name, err)
		}

		if logutil.EnableDebug {
			d := ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the Service Account '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (ctx *manifestApplyContext) applyPolicy(idx int, in manifest.Policy) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy): name must be set", idx+1)
	}

	desired := manifestToAPIPolicy(in)
	existing, err := getPolicy(context.Background(), ctx.client, desired.Name)
	switch {
	case errors.As(err, &NotFound{}):
		created, err := createPolicy(context.Background(), ctx.client, manifestToAPIPolicyCreateRequest(in))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while creating: %w", idx+1, desired.Name, err)
		}
		logutil.Infof("Creating WIMIssuerPolicy '%s' with ID '%s'.", desired.Name, created.Id.String())
		ctx.refreshPolicyWithExisting(created)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while retrieving existing policy: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := diffToPatchPolicy(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("WIMIssuerPolicy '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating WIMIssuerPolicy '%s'.", desired.Name)
		updated, err := patchPolicy(context.Background(), ctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMIssuerPolicy %q): while patching: %w", idx+1, desired.Name, err)
		}
		ctx.refreshPolicyWithExisting(updated)

		if logutil.EnableDebug {
			d := ANSIDiff(existing, updated, transformClientAuthentication)
			logutil.Debugf("Diff before/after of the WIMIssuerPolicy '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (ctx *manifestApplyContext) applySubCa(idx int, in manifest.SubCa) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider): name must be set", idx+1)
	}

	// The issuing template is needed when creating a new sub CA provider due to
	// the fields 'caType', 'caAccountId' and 'caProductOptionId'.
	desired, err := manifestToAPISubCa(func(s string) (api.CertificateIssuingTemplateInformation1, error) {
		return getIssuingTemplateByName(context.Background(), ctx.client, s)
	}, in)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while converting to API request: %w", idx+1, in.Name, err)
	}

	existing, err := getSubCa(context.Background(), ctx.client, desired.Name)
	switch {
	case errors.As(err, &NotFound{}):
		created, err := createSubCaProvider(context.Background(), ctx.client, apiToAPISubCaProviderCreateRequest(desired))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while creating: %w", idx+1, desired.Name, err)
		}
		logutil.Infof("Creating WIMSubCAProvider '%s' with ID '%s'.", desired.Name, created.Id.String())
		ctx.refreshSubCaWithExisting(created)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while retrieving existing SubCA provider: %w", idx+1, desired.Name, err)
	default:
		patch, changed, err := diffToPatchSubCAProvider(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while computing patch: %w", idx+1, desired.Name, err)
		}
		if !changed {
			logutil.Infof("WIMSubCAProvider '%s' is up to date; no changes needed.", desired.Name)
			break
		}

		logutil.Infof("Updating WIMSubCAProvider '%s'.", desired.Name)
		updated, err := patchSubCaProvider(context.Background(), ctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMSubCAProvider %q): while patching: %w", idx+1, desired.Name, err)
		}
		ctx.refreshSubCaWithExisting(updated)

		if logutil.EnableDebug {
			d := ANSIDiff(existing, updated)
			logutil.Debugf("Diff before/after of the WIM SubCA Provider '%s':\n%s", desired.Name, d)
		}
	}

	return nil
}

func (ctx *manifestApplyContext) applyConfig(idx int, in manifest.WIMConfiguration) error {
	if in.Name == "" {
		return fmt.Errorf("manifest #%d (WIMConfiguration): name must be set", idx+1)
	}

	var serviceAccountIDs []openapi_types.UUID
	var policies []api.PolicyInformation
	var policyIDs []openapi_types.UUID

	for _, saName := range in.ServiceAccountNames {
		sa, err := ctx.resolveServiceAccount(saName)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while resolving service account %q: %w", idx+1, in.Name, saName, err)
		}
		serviceAccountIDs = append(serviceAccountIDs, sa.Id)
	}

	for _, policyName := range in.PolicyNames {
		policy, err := ctx.resolvePolicy(policyName)
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

	desired, err := manifestToAPIExtendedConfigurationInformation(ctx.resolvePolicy, ctx.resolveServiceAccount, ctx.resolveSubCa, in)
	if err != nil {
		return fmt.Errorf("manifest #%d (WIMConfiguration %q): while converting to API request: %w", idx+1, in.Name, err)
	}

	existing, err := getConfig(context.Background(), ctx.client, in.Name)
	switch {
	case errors.As(err, &NotFound{}):
		_, err := createConfig(context.Background(), ctx.client, apiToAPIConfigurationCreateRequest(desired))
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while creating: %w", idx+1, in.Name, err)
		}
		logutil.Infof("Creating WIMConfiguration '%s'.", in.Name)
	case err != nil:
		return fmt.Errorf("manifest #%d (WIMConfiguration %q): while retrieving existing configuration: %w", idx+1, in.Name, err)
	default:
		patch, changed, err := diffToPatchConfig(existing, desired)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while computing patch: %w", idx+1, in.Name, err)
		}
		if !changed {
			logutil.Infof("WIMConfiguration '%s' is up to date; no changes needed.", in.Name)
			break
		}

		logutil.Infof("Updating WIMConfiguration '%s' (ID '%s').", in.Name, existing.Id.String())
		updated, err := patchConfig(context.Background(), ctx.client, existing.Id.String(), patch)
		if err != nil {
			return fmt.Errorf("manifest #%d (WIMConfiguration %q): while patching: %w", idx+1, in.Name, err)
		}

		if logutil.EnableDebug {
			d := ANSIDiff(existing, updated, transformClientAuthentication)
			logutil.Debugf("Diff before/after of the WIMConfiguration '%s':\n%s", in.Name, d)
		}
	}

	return nil
}

func (ctx *manifestApplyContext) resolveServiceAccount(name string) (ServiceAccount, error) {
	if sa, ok := ctx.serviceAccounts[name]; ok {
		return sa, nil
	}
	return ctx.refreshServiceAccount(name)
}

func (ctx *manifestApplyContext) refreshServiceAccount(name string) (ServiceAccount, error) {
	sa, err := getServiceAccount(context.Background(), ctx.client, name)
	if err != nil {
		return ServiceAccount{}, err
	}
	ctx.serviceAccounts[name] = sa
	return sa, nil
}

func (ctx *manifestApplyContext) resolvePolicy(name string) (Policy, error) {
	if policy, ok := ctx.policies[name]; ok {
		return policy, nil
	}
	return ctx.refreshPolicy(name)
}

func (ctx *manifestApplyContext) refreshPolicy(name string) (Policy, error) {
	policy, err := getPolicy(context.Background(), ctx.client, name)
	if err != nil {
		return Policy{}, err
	}
	ctx.policies[name] = policy
	return policy, nil
}

func (ctx *manifestApplyContext) refreshPolicyWithExisting(updated Policy) {
	ctx.policies[updated.Name] = updated
}

func (ctx *manifestApplyContext) resolveSubCa(name string) (SubCa, error) {
	if subca, ok := ctx.subCaProviders[name]; ok {
		return subca, nil
	}

	err := ctx.refreshSubCaWithName(name)
	if err != nil {
		return SubCa{}, err
	}

	return ctx.subCaProviders[name], nil
}

func (ctx *manifestApplyContext) refreshSubCaWithName(name string) error {
	subca, err := getSubCa(context.Background(), ctx.client, name)
	if err != nil {
		return err
	}
	ctx.subCaProviders[name] = subca
	return nil
}

func (ctx *manifestApplyContext) refreshSubCaWithExisting(updated SubCa) {
	ctx.subCaProviders[updated.Name] = updated
}

func (ctx *manifestApplyContext) refreshSubCaWithID(id string) error {
	subca, err := getSubCaByID(context.Background(), ctx.client, id)
	if err != nil {
		return err
	}
	ctx.subCaProviders[subca.Name] = subca
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
func validateReferences(cl *api.Client, manifests []manifest.Manifest) error {
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
				_, err := getServiceAccount(context.Background(), cl, saName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): service account %q not found in manifests or API", i+1, cfg.Name, saName))
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking service account %q: %w", i+1, cfg.Name, saName, err)
				}
			}
		}

		// Validate policy references
		for _, policyName := range cfg.PolicyNames {
			if !policyNames[policyName] {
				// Check if it exists in API
				_, err := getPolicy(context.Background(), cl, policyName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): policy %q not found in manifests or API", i+1, cfg.Name, policyName))
					}
					return fmt.Errorf("manifest #%d (WIMConfiguration %q): while checking policy %q: %w", i+1, cfg.Name, policyName, err)
				}
			}
		}

		// Validate subCA provider reference
		if cfg.SubCaProviderName != "" {
			if !subCaNames[cfg.SubCaProviderName] {
				// Check if it exists in API
				_, err := getSubCa(context.Background(), cl, cfg.SubCaProviderName)
				if err != nil {
					if errors.As(err, &NotFound{}) {
						return Fixable(fmt.Errorf("manifest #%d (WIMConfiguration %q): subCA provider %q not found in manifests or API", i+1, cfg.Name, cfg.SubCaProviderName))
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
