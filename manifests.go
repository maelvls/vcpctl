package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"
	_ "github.com/maelvls/vcpctl/internal/api"
	manifest "github.com/maelvls/vcpctl/internal/manifest"
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

func manifestsToAPI(manifests []manifest.Manifest) (any, error) {
	var result []any
	for i, m := range manifests {
		var converted any
		switch {
		case m.WIMConfiguration != nil:
			// WIMConfiguration conversion is handled directly in applyConfig
			converted = *m.WIMConfiguration
		case m.ServiceAccount != nil:
			converted = manifestToAPIServiceAccount(*m.ServiceAccount)
		case m.Policy != nil:
			converted = manifestToAPIPolicy(*m.Policy)
		case m.SubCa != nil:
			converted = manifestToAPISubCa(*m.SubCa)
		default:
			return nil, fmt.Errorf("manifest #%d has no content", i+1)
		}
		result = append(result, converted)
	}
	if len(result) == 1 {
		return result[0], nil
	}
	return result, nil
}

func renderManifests(cfg Config) ([]byte, error) {
	// renderManifests is currently not fully implemented for the new API structure
	// It needs to be updated to handle ServiceAccountIds instead of ServiceAccounts
	// For now, return an error indicating this needs implementation
	_ = cfg
	return nil, fmt.Errorf("renderManifests is not yet fully implemented for the current API structure")
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
