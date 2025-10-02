package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
	api "github.com/maelvls/vcpctl/internal/api"
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

		// An empty document (e.g. only comments). Skip it.
		if header.Kind == "" {
			_ = decForReal.Decode(&struct{}{})
			continue
		}

		switch header.Kind {
		case kindServiceAccount:
			var parsed manifest.ServiceAccount
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding ServiceAccount manifest #%d: %w", i+1, err)
			}

			manifests = append(manifests, manifest.Manifest{ServiceAccount: &parsed})
		case kindIssuerPolicy:
			var parsed manifest.Policy
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMIssuerPolicy manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{Policy: &parsed})
		case kindWIMSubCaProvider:
			var parsed manifest.SubCa
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMSubCAProvider manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{SubCa: &parsed})
		case kindConfiguration:
			var parsed manifest.Config
			err = decForReal.Decode(&parsed)
			if err != nil {
				return nil, fmt.Errorf("while decoding WIMConfiguration manifest #%d: %w", i+1, err)
			}
			manifests = append(manifests, manifest.Manifest{Config: &parsed})
		default:
			return nil, Fixable(fmt.Errorf("manifest #%d has unsupported kind %q", i+1, header.Kind))
		}
	}
}

func extractManifestKind(b []byte) string {
	type header struct {
		Kind string `yaml:"kind"`
	}
	var h header
	if err := yaml.Unmarshal(b, &h); err != nil {
		return ""
	}
	return strings.TrimSpace(h.Kind)
}

func renderFireflyConfigManifests(cfg api.Config) ([]byte, error) {
	manifestCfg := apiToManifestConfig(cfg)
	var docs [][]byte

	for _, sa := range manifestCfg.ServiceAccountNames {
		manifest := serviceAccountManifest{
			Kind:           kindServiceAccount,
			ServiceAccount: sa,
		}
		doc, err := yaml.MarshalWithOptions(manifest, yaml.Indent(2))
		if err != nil {
			return nil, fmt.Errorf("while encoding ServiceAccount %q: %w", sa.Name, err)
		}
		docs = append(docs, doc)
	}

	for _, policy := range manifestCfg.Policies {
		manifest := policyManifest{
			Kind:   kindIssuerPolicy,
			Policy: policy,
		}
		doc, err := yaml.MarshalWithOptions(manifest, yaml.Indent(2))
		if err != nil {
			return nil, fmt.Errorf("while encoding WIMIssuerPolicy %q: %w", policy.Name, err)
		}
		docs = append(docs, doc)
	}

	if manifestCfg.SubCaProvider.Name != "" {
		manifest := subCaProviderManifest{
			Kind:  kindWIMSubCaProvider,
			SubCa: manifestCfg.SubCaProvider,
		}
		doc, err := yaml.MarshalWithOptions(manifest, yaml.Indent(2))
		if err != nil {
			return nil, fmt.Errorf("while encoding WIMSubCAProvider %q: %w", manifestCfg.SubCaProvider.Name, err)
		}
		docs = append(docs, doc)
	}

	configDoc := manifestCfg
	configDoc.ServiceAccountNames = nil
	configDoc.Policies = nil
	manifest := configurationManifest{
		Kind:   kindConfiguration,
		Config: configDoc,
	}
	configBytes, err := yaml.MarshalWithOptions(manifest, yaml.Indent(2))
	if err != nil {
		return nil, fmt.Errorf("while encoding WIMConfiguration %q: %w", cfg.Name, err)
	}
	docs = append(docs, configBytes)

	var buf bytes.Buffer
	for i, doc := range docs {
		if i > 0 {
			buf.WriteString("---\n")
		}
		buf.Write(doc)
		if len(doc) == 0 || doc[len(doc)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}

	return buf.Bytes(), nil
}
