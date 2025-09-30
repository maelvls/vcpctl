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

var manifestKindOrder = map[string]int{
	kindServiceAccount:   0,
	kindIssuerPolicy:     1,
	kindWIMSubCaProvider: 2,
	kindConfiguration:    3,
}

type serviceAccountManifest struct {
	APIVersion              string `yaml:"apiVersion,omitempty"`
	Kind                    string `yaml:"kind"`
	manifest.ServiceAccount `yaml:",inline"`
}

type policyManifest struct {
	APIVersion      string `yaml:"apiVersion,omitempty"`
	Kind            string `yaml:"kind"`
	manifest.Policy `yaml:",inline"`
}

type subCaProviderManifest struct {
	APIVersion     string `yaml:"apiVersion,omitempty"`
	Kind           string `yaml:"kind"`
	manifest.SubCa `yaml:",inline"`
}

type configurationManifest struct {
	APIVersion      string `yaml:"apiVersion,omitempty"`
	Kind            string `yaml:"kind"`
	manifest.Config `yaml:",inline"`
}

func parseFireflyConfigManifests(raw []byte) (api.Config, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return api.Config{}, Fixable(fmt.Errorf("manifest is empty"))
	}

	dec := yaml.NewDecoder(bytes.NewReader(raw))

	type rawDoc struct {
		index int
		kind  string
		data  []byte
	}

	var docs []rawDoc
	for i := 0; ; i++ {
		var value interface{}
		err := dec.Decode(&value)
		switch {
		case errors.Is(err, io.EOF):
			goto done
		case err != nil:
			return api.Config{}, fmt.Errorf("while decoding manifest #%d: %w", i+1, err)
		}

		if value == nil {
			// An empty document (e.g. only comments). Skip it.
			continue
		}

		// Re-marshal the document so we can run strict decoding later.
		docBytes, err := yaml.Marshal(value)
		if err != nil {
			return api.Config{}, fmt.Errorf("while normalizing manifest #%d: %w", i+1, err)
		}

		kind := extractManifestKind(docBytes)

		docs = append(docs, rawDoc{index: len(docs) + 1, kind: kind, data: docBytes})
	}

done:
	if len(docs) == 0 {
		return api.Config{}, Fixable(fmt.Errorf("manifest is empty"))
	}

	// No 'kind' present anywhere: fall back to legacy single-document parsing.
	var (
		manifestResult       manifest.Config
		serviceAccounts      []manifest.ServiceAccount
		policies             []manifest.Policy
		subCaProvidersByName = make(map[string]manifest.SubCa)
		configSeen           bool
		lastKindOrderValue   = -1
		saByName             = make(map[string]struct{})
		policiesByName       = make(map[string]struct{})
	)

	for _, doc := range docs {
		kind := doc.kind
		if kind == "" {
			return api.Config{}, Fixable(fmt.Errorf("manifest #%d is missing 'kind'", doc.index))
		}
		order, ok := manifestKindOrder[kind]
		if !ok {
			return api.Config{}, Fixable(fmt.Errorf("manifest #%d has unsupported kind %q", doc.index, kind))
		}
		if order < lastKindOrderValue {
			return api.Config{}, Fixable(fmt.Errorf("manifest #%d (%s) appears after a manifest that depends on it; please reorder the documents", doc.index, kind))
		}
		if order > lastKindOrderValue {
			lastKindOrderValue = order
		}
		if err := validateManifestDocument(doc.index, kind, doc.data); err != nil {
			return api.Config{}, err
		}

		switch kind {
		case kindServiceAccount:
			var docManifest serviceAccountManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &docManifest, yaml.Strict()); err != nil {
				return api.Config{}, fmt.Errorf("while decoding ServiceAccount manifest #%d: %w", doc.index, err)
			}
			name := strings.TrimSpace(docManifest.Name)
			if name == "" {
				return api.Config{}, Fixable(fmt.Errorf("ServiceAccount manifest #%d must set 'name'", doc.index))
			}
			if _, exists := saByName[name]; exists {
				return api.Config{}, Fixable(fmt.Errorf("duplicate ServiceAccount named %q (manifest #%d)", name, doc.index))
			}
			saByName[name] = struct{}{}
			serviceAccounts = append(serviceAccounts, docManifest.ServiceAccount)
		case kindIssuerPolicy:
			var docManifest policyManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &docManifest, yaml.Strict()); err != nil {
				return api.Config{}, fmt.Errorf("while decoding WIMIssuerPolicy manifest #%d: %w", doc.index, err)
			}
			name := strings.TrimSpace(docManifest.Policy.Name)
			if name == "" {
				return api.Config{}, Fixable(fmt.Errorf("WIMIssuerPolicy manifest #%d must set 'name'", doc.index))
			}
			if _, exists := policiesByName[name]; exists {
				return api.Config{}, Fixable(fmt.Errorf("duplicate policy named %q (manifest #%d)", name, doc.index))
			}
			policiesByName[name] = struct{}{}
			policies = append(policies, docManifest.Policy)
		case kindWIMSubCaProvider:
			var docManifest subCaProviderManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &docManifest, yaml.Strict()); err != nil {
				return api.Config{}, fmt.Errorf("while decoding WIMSubCAProvider manifest #%d: %w", doc.index, err)
			}
			name := strings.TrimSpace(docManifest.SubCa.Name)
			if name == "" {
				return api.Config{}, Fixable(fmt.Errorf("WIMSubCAProvider manifest #%d must set 'name'", doc.index))
			}
			if _, exists := subCaProvidersByName[name]; exists {
				return api.Config{}, Fixable(fmt.Errorf("duplicate WIMSubCAProvider named %q (manifest #%d)", name, doc.index))
			}
			subCaProvidersByName[name] = docManifest.SubCa
		case kindConfiguration:
			if configSeen {
				return api.Config{}, Fixable(fmt.Errorf("only one WIMConfiguration manifest is allowed (found another at #%d)", doc.index))
			}
			var docManifest configurationManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &docManifest, yaml.Strict()); err != nil {
				return api.Config{}, fmt.Errorf("while decoding WIMConfiguration manifest #%d: %w", doc.index, err)
			}
			if len(docManifest.Config.ServiceAccounts) > 0 {
				return api.Config{}, Fixable(fmt.Errorf("WIMConfiguration manifest must not embed serviceAccounts directly; define them in dedicated ServiceAccount manifests"))
			}
			if len(docManifest.Config.Policies) > 0 {
				return api.Config{}, Fixable(fmt.Errorf("WIMConfiguration manifest must not embed policies directly; define them in dedicated WIMIssuerPolicy manifests"))
			}
			subCaName := strings.TrimSpace(docManifest.Config.SubCaProviderName)
			if subCaName == "" {
				return api.Config{}, Fixable(fmt.Errorf("WIMConfiguration manifest #%d must reference a WIMSubCAProvider via 'subCaProvider'", doc.index))
			}
			provider, ok := subCaProvidersByName[subCaName]
			if !ok {
				return api.Config{}, Fixable(fmt.Errorf("WIMConfiguration manifest #%d references unknown WIMSubCAProvider %q", doc.index, subCaName))
			}
			docManifest.Config.SubCaProviderName = subCaName
			manifestResult = docManifest.Config
			manifestResult.SubCaProvider = provider
			configSeen = true
		}
	}

	if !configSeen {
		return api.Config{}, Fixable(fmt.Errorf("no WIMConfiguration manifest found"))
	}

	// Attach the collected dependencies back onto the configuration.
	manifestResult.ServiceAccounts = append(manifestResult.ServiceAccounts, serviceAccounts...)
	manifestResult.Policies = append(manifestResult.Policies, policies...)

	return manifestToAPIConfig(manifestResult), nil
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

	for _, sa := range manifestCfg.ServiceAccounts {
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
	configDoc.ServiceAccounts = nil
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
