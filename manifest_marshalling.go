package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"
	_ "github.com/maelvls/vcpctl/api"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	manifest "github.com/maelvls/vcpctl/manifest"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

const (
	kindServiceAccount   = "ServiceAccount"
	kindIssuerPolicy     = "WIMIssuerPolicy"
	kindWIMSubCaProvider = "WIMSubCAProvider"
	kindConfiguration    = "WIMConfiguration"
)

func parseManifests(raw []byte) ([]manifest.Manifest, error) {
	var manifests []manifest.Manifest

	// Due to the polymorphism created by 'kind', we decode the YAML documents
	// twice: first to extract the 'kind' field, then to decode the full
	// document into the appropriate struct.
	decForKind := yaml.NewDecoder(bytes.NewReader(raw))
	decForReal := yaml.NewDecoder(bytes.NewReader(raw), yaml.DisallowUnknownField())

	for i := 0; ; i++ {
		var header struct {
			Kind string `yaml:"kind"`
		}
		err := decForKind.Decode(&header)
		switch {
		case errors.Is(err, io.EOF):
			return manifests, nil
		case err != nil:
			return nil, fmt.Errorf("while decoding manifest #%d: %w", i+1, errutil.Fixable(err))
		}

		// An empty document (e.g. only comments). Skip it. If a document contains
		// fields but no 'kind', surface a fixable error.
		if header.Kind == "" {
			var raw map[string]any
			err = decForReal.Decode(&raw)
			if err != nil {
				return nil, fmt.Errorf("while decoding manifest #%d: %w", i+1, errutil.Fixable(err))
			}
			if len(raw) == 0 {
				continue
			}
			return nil, errutil.Fixable(fmt.Errorf("manifest #%d is missing the required 'kind' field", i+1))
		}

		switch header.Kind {
		case kindServiceAccount:
			var parsed serviceAccountManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding ServiceAccount manifest #%d: %w", i+1, errutil.Fixable(err))
			}

			manifests = append(manifests, manifest.Manifest{ServiceAccount: &parsed.ServiceAccount})
		case kindIssuerPolicy:
			var parsed policyManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMIssuerPolicy manifest #%d: %w", i+1, errutil.Fixable(err))
			}
			manifests = append(manifests, manifest.Manifest{Policy: &parsed.Policy})
		case kindWIMSubCaProvider:
			var parsed subCaProviderManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMSubCAProvider manifest #%d: %w", i+1, errutil.Fixable(err))
			}
			manifests = append(manifests, manifest.Manifest{SubCa: &parsed.SubCa})
		case kindConfiguration:
			var parsed configurationManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMConfiguration manifest #%d: %w", i+1, errutil.Fixable(err))
			}
			manifests = append(manifests, manifest.Manifest{WIMConfiguration: &parsed.WIMConfiguration})
		default:
			return nil, errutil.Fixable(fmt.Errorf("manifest #%d has unsupported kind %q", i+1, header.Kind))
		}
	}
}

func renderToManifests(
	ctx context.Context,
	resolveSA func(context.Context, openapi_types.UUID) (api.ServiceAccountDetails, error),
	resolveIssuingTemplates func(ctx context.Context, caAccountId, caProductOptionId openapi_types.UUID) (api.CertificateIssuingTemplateInformation, error),
	nameCounts map[string]int,
	cfg api.ExtendedConfigurationInformation,
) (manifest.WIMConfiguration, []manifest.ServiceAccount, []manifest.Policy, manifest.SubCa, []api.ServiceAccountDetails, error) {
	var wimConfig manifest.WIMConfiguration
	wimConfig.SubCaProviderName = cfg.SubCaProvider.Name

	var serviceAccounts []manifest.ServiceAccount
	var resolvedServiceAccounts []api.ServiceAccountDetails
	for _, sa := range cfg.ServiceAccountIds {
		resolvedSA, err := resolveSA(ctx, sa)
		if err != nil {
			return manifest.WIMConfiguration{}, nil, nil, manifest.SubCa{}, nil, fmt.Errorf("while resolving ServiceAccount ID %q: %w", sa, err)
		}
		serviceAccounts = append(serviceAccounts, apiToManifestServiceAccount(resolvedSA))
		resolvedServiceAccounts = append(resolvedServiceAccounts, resolvedSA)
	}

	var policies []manifest.Policy
	for _, p := range cfg.Policies {
		policies = append(policies, apiToManifestPolicyInformation(p))
	}

	wimConfig, err := apiToManifestWIMConfiguration(ctx, resolveSA, nameCounts, cfg)
	if err != nil {
		return manifest.WIMConfiguration{}, nil, nil, manifest.SubCa{}, nil, fmt.Errorf("while converting WIMConfiguration: %w", err)
	}

	var subCa manifest.SubCa
	subCa, err = apiToManifestSubCa(ctx, resolveIssuingTemplates, cfg.SubCaProvider)
	if err != nil {
		return manifest.WIMConfiguration{}, nil, nil, manifest.SubCa{}, nil, fmt.Errorf("while converting SubCaProvider: %w", err)
	}

	return wimConfig, serviceAccounts, policies, subCa, resolvedServiceAccounts, nil
}

// marshalWIMConfigWithSAComments marshals a WIMConfiguration to YAML with
// inline comments showing UUIDs for unique names or names for duplicate UUIDs.
func marshalWIMConfigWithSAComments(
	configManifest configurationManifest,
	serviceAccounts []api.ServiceAccountDetails,
) ([]byte, error) {
	// Build lookup maps for fast access
	saByID := make(map[string]api.ServiceAccountDetails)
	saByName := make(map[string]api.ServiceAccountDetails)
	for _, sa := range serviceAccounts {
		saByID[sa.Id.String()] = sa
		saByName[sa.Name] = sa
	}

	// Create comment map for service account array elements
	commentMap := yaml.CommentMap{}

	for i, saNameOrID := range configManifest.ServiceAccountNames {
		path := fmt.Sprintf("$.serviceAccountNames[%d]", i)

		if api.LooksLikeAnID(saNameOrID) {
			// Value is a UUID (duplicate case) - add comment with the name
			if sa, ok := saByID[saNameOrID]; ok {
				commentMap[path] = []*yaml.Comment{
					yaml.LineComment(" " + sa.Name),
				}
			}
		} else {
			// Value is a name (unique case) - add comment with the UUID
			if sa, ok := saByName[saNameOrID]; ok {
				commentMap[path] = []*yaml.Comment{
					yaml.LineComment(" " + sa.Id.String()),
				}
			}
		}
	}

	if len(commentMap) == 0 {
		// No comments needed, use standard marshaling
		return yaml.Marshal(configManifest)
	}

	// Marshal with comment support
	return yaml.MarshalWithOptions(configManifest, yaml.WithComment(commentMap))
}

func renderToYAML(
	ctx context.Context,
	resolveSA func(context.Context, openapi_types.UUID) (api.ServiceAccountDetails, error),
	resolveIssuingTemplates func(ctx context.Context, caAccountId, caProductOptionId openapi_types.UUID) (api.CertificateIssuingTemplateInformation, error),
	nameCounts map[string]int,
	cfg api.ExtendedConfigurationInformation,
) ([]byte, error) {
	manifests := []manifest.Manifest{}

	wimConfig, serviceAccounts, policies, subCa, resolvedServiceAccounts, err := renderToManifests(ctx, resolveSA, resolveIssuingTemplates, nameCounts, cfg)
	if err != nil {
		return nil, fmt.Errorf("while rendering to manifests: %w", err)
	}
	manifests = append(manifests, manifest.Manifest{WIMConfiguration: &wimConfig})

	for _, sa := range serviceAccounts {
		manifests = append(manifests, manifest.Manifest{ServiceAccount: &sa})
	}

	for _, p := range policies {
		manifests = append(manifests, manifest.Manifest{Policy: &p})
	}

	manifests = append(manifests, manifest.Manifest{SubCa: &subCa})

	var buf bytes.Buffer

	for i, m := range manifests {
		var yamlBytes []byte
		var err error

		switch {
		case m.WIMConfiguration != nil:
			configManifest := configurationManifest{
				Kind:             kindConfiguration,
				WIMConfiguration: *m.WIMConfiguration,
			}
			// Use custom marshaller with comments for WIMConfiguration
			yamlBytes, err = marshalWIMConfigWithSAComments(configManifest, resolvedServiceAccounts)
		case m.ServiceAccount != nil:
			yamlBytes, err = yaml.Marshal(serviceAccountManifest{
				Kind:           kindServiceAccount,
				ServiceAccount: *m.ServiceAccount,
			})
		case m.Policy != nil:
			yamlBytes, err = yaml.Marshal(policyManifest{
				Kind:   kindIssuerPolicy,
				Policy: *m.Policy,
			})
		case m.SubCa != nil:
			yamlBytes, err = yaml.Marshal(subCaProviderManifest{
				Kind:  kindWIMSubCaProvider,
				SubCa: *m.SubCa,
			})
		default:
			return nil, fmt.Errorf("manifest #%d has no content", i+1)
		}

		if err != nil {
			return nil, fmt.Errorf("while encoding manifest #%d to YAML: %w", i+1, errutil.Fixable(err))
		}

		buf.Write(yamlBytes)
		buf.WriteString("---\n")
	}

	return buf.Bytes(), nil
}

type serviceAccountManifest struct {
	Kind                    string `yaml:"kind"`
	manifest.ServiceAccount `yaml:",inline"`
}

type policyManifest struct {
	Kind            string `yaml:"kind"`
	manifest.Policy `yaml:",inline"`
}

type subCaProviderManifest struct {
	Kind           string `yaml:"kind"`
	manifest.SubCa `yaml:",inline"`
}

type configurationManifest struct {
	Kind                      string `yaml:"kind"`
	manifest.WIMConfiguration `yaml:",inline"`
}
