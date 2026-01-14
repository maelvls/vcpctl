package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"
	_ "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"
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
			return nil, fmt.Errorf("while decoding manifest #%d: %w", i+1, err)
		}

		// An empty document (e.g. only comments). Skip it. If a document contains
		// fields but no 'kind', surface a fixable error.
		if header.Kind == "" {
			var raw map[string]any
			err = decForReal.Decode(&raw)
			if err != nil {
				return nil, fmt.Errorf("while decoding manifest #%d: %w", i+1, err)
			}
			if len(raw) == 0 {
				continue
			}
			return nil, Fixable(fmt.Errorf("manifest #%d is missing the required 'kind' field", i+1))
		}

		switch header.Kind {
		case kindServiceAccount:
			var parsed serviceAccountManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding ServiceAccount manifest #%d: %w", i+1, err)
			}

			manifests = append(manifests, manifest.Manifest{ServiceAccount: &parsed.ServiceAccount})
		case kindIssuerPolicy:
			var parsed policyManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMIssuerPolicy manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{Policy: &parsed.Policy})
		case kindWIMSubCaProvider:
			var parsed subCaProviderManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMSubCAProvider manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{SubCa: &parsed.SubCa})
		case kindConfiguration:
			var parsed configurationManifest
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMConfiguration manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{WIMConfiguration: &parsed.WIMConfiguration})
		default:
			return nil, Fixable(fmt.Errorf("manifest #%d has unsupported kind %q", i+1, header.Kind))
		}
	}
}

func renderToManifests(resolveSA func(openapi_types.UUID) (ServiceAccount, error), cfg Config) (manifest.WIMConfiguration, []manifest.ServiceAccount, []manifest.Policy, manifest.SubCa, error) {
	var wimConfig manifest.WIMConfiguration
	wimConfig.SubCaProviderName = cfg.SubCaProvider.Name

	var serviceAccounts []manifest.ServiceAccount
	for _, sa := range cfg.ServiceAccountIds {
		resolvedSA, err := resolveSA(sa)
		if err != nil {
			return manifest.WIMConfiguration{}, nil, nil, manifest.SubCa{}, fmt.Errorf("renderToManifests: while resolving ServiceAccount ID %q: %w", sa, err)
		}
		serviceAccounts = append(serviceAccounts, apiToManifestServiceAccount(resolvedSA))
	}

	var policies []manifest.Policy
	for _, p := range cfg.Policies {
		policies = append(policies, apiToManifestPolicyInformation(p))
	}

	wimConfig, err := apiToManifestWIMConfiguration(resolveSA, cfg)
	if err != nil {
		return manifest.WIMConfiguration{}, nil, nil, manifest.SubCa{}, fmt.Errorf("renderToManifests: while converting WIMConfiguration: %w", err)
	}

	var subCa manifest.SubCa
	subCa = apiToManifestSubCa(cfg.SubCaProvider)

	return wimConfig, serviceAccounts, policies, subCa, nil
}

func renderToYAML(resolveSA func(openapi_types.UUID) (ServiceAccount, error), cfg Config) ([]byte, error) {
	manifests := []manifest.Manifest{}

	wimConfig, serviceAccounts, policies, subCa, err := renderToManifests(resolveSA, cfg)
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
	enc := yaml.NewEncoder(&buf)

	for i, m := range manifests {
		var toEncode any
		switch {
		case m.WIMConfiguration != nil:
			toEncode = configurationManifest{
				Kind:             kindConfiguration,
				WIMConfiguration: *m.WIMConfiguration,
			}
		case m.ServiceAccount != nil:
			toEncode = serviceAccountManifest{
				Kind:           kindServiceAccount,
				ServiceAccount: *m.ServiceAccount,
			}
		case m.Policy != nil:
			toEncode = policyManifest{
				Kind:   kindIssuerPolicy,
				Policy: *m.Policy,
			}
		case m.SubCa != nil:
			toEncode = subCaProviderManifest{
				Kind:  kindWIMSubCaProvider,
				SubCa: *m.SubCa,
			}
		default:
			return nil, fmt.Errorf("manifest #%d has no content", i+1)
		}

		err := enc.Encode(toEncode)
		if err != nil {
			return nil, fmt.Errorf("while encoding manifest #%d to YAML: %w", i+1, err)
		}
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
