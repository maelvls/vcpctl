package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
)

const (
	kindServiceAccount = "ServiceAccount"
	kindIssuerPolicy   = "WIMIssuerPolicy"
	kindConfiguration  = "WIMConfiguration"
	legacyKindPolicy   = "Policy"
	legacyKindIssuer   = "IssuerPolicy"
)

var manifestKindOrder = map[string]int{
	kindServiceAccount: 0,
	kindIssuerPolicy:   1,
	legacyKindPolicy:   1,
	legacyKindIssuer:   1,
	kindConfiguration:  2,
}

type serviceAccountManifest struct {
	APIVersion     string `yaml:"apiVersion,omitempty"`
	Kind           string `yaml:"kind"`
	ServiceAccount `yaml:",inline"`
}

type policyManifest struct {
	APIVersion string `yaml:"apiVersion,omitempty"`
	Kind       string `yaml:"kind"`
	Policy     `yaml:",inline"`
}

type configurationManifest struct {
	APIVersion    string `yaml:"apiVersion,omitempty"`
	Kind          string `yaml:"kind"`
	FireflyConfig `yaml:",inline"`
}

func parseFireflyConfigManifests(raw []byte) (FireflyConfig, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return FireflyConfig{}, Fixable(fmt.Errorf("manifest is empty"))
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
			return FireflyConfig{}, fmt.Errorf("while decoding manifest #%d: %w", i+1, err)
		}

		if value == nil {
			// An empty document (e.g. only comments). Skip it.
			continue
		}

		// Re-marshal the document so we can run strict decoding later.
		docBytes, err := yaml.Marshal(value)
		if err != nil {
			return FireflyConfig{}, fmt.Errorf("while normalizing manifest #%d: %w", i+1, err)
		}

		kind := extractManifestKind(docBytes)

		docs = append(docs, rawDoc{index: len(docs) + 1, kind: kind, data: docBytes})
	}

done:
	if len(docs) == 0 {
		return FireflyConfig{}, Fixable(fmt.Errorf("manifest is empty"))
	}

	// No 'kind' present anywhere: fall back to legacy single-document parsing.
	var (
		result             FireflyConfig
		serviceAccounts    []ServiceAccount
		policies           []Policy
		configSeen         bool
		lastKindOrderValue = -1
		saByName           = make(map[string]struct{})
		policiesByName     = make(map[string]struct{})
	)

	for _, doc := range docs {
		kind := doc.kind
		if kind == "" {
			return FireflyConfig{}, Fixable(fmt.Errorf("manifest #%d is missing 'kind'", doc.index))
		}
		order, ok := manifestKindOrder[kind]
		if !ok {
			return FireflyConfig{}, Fixable(fmt.Errorf("manifest #%d has unsupported kind %q", doc.index, kind))
		}
		if order < lastKindOrderValue {
			return FireflyConfig{}, Fixable(fmt.Errorf("manifest #%d (%s) appears after a manifest that depends on it; please reorder the documents", doc.index, kind))
		}
		if order > lastKindOrderValue {
			lastKindOrderValue = order
		}

		switch kind {
		case kindServiceAccount:
			var manifest serviceAccountManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &manifest, yaml.Strict()); err != nil {
				return FireflyConfig{}, fmt.Errorf("while decoding ServiceAccount manifest #%d: %w", doc.index, err)
			}
			name := strings.TrimSpace(manifest.Name)
			if name == "" {
				return FireflyConfig{}, Fixable(fmt.Errorf("ServiceAccount manifest #%d must set 'name'", doc.index))
			}
			if _, exists := saByName[name]; exists {
				return FireflyConfig{}, Fixable(fmt.Errorf("duplicate ServiceAccount named %q (manifest #%d)", name, doc.index))
			}
			saByName[name] = struct{}{}
			serviceAccounts = append(serviceAccounts, manifest.ServiceAccount)
		case kindIssuerPolicy, legacyKindPolicy, legacyKindIssuer:
			var manifest policyManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &manifest, yaml.Strict()); err != nil {
				return FireflyConfig{}, fmt.Errorf("while decoding WIMIssuerPolicy manifest #%d: %w", doc.index, err)
			}
			name := strings.TrimSpace(manifest.Policy.Name)
			if name == "" {
				return FireflyConfig{}, Fixable(fmt.Errorf("WIMIssuerPolicy manifest #%d must set 'name'", doc.index))
			}
			if _, exists := policiesByName[name]; exists {
				return FireflyConfig{}, Fixable(fmt.Errorf("duplicate policy named %q (manifest #%d)", name, doc.index))
			}
			policiesByName[name] = struct{}{}
			policies = append(policies, manifest.Policy)
		case kindConfiguration:
			if configSeen {
				return FireflyConfig{}, Fixable(fmt.Errorf("only one WIMConfiguration manifest is allowed (found another at #%d)", doc.index))
			}
			var manifest configurationManifest
			if err := yaml.UnmarshalWithOptions(doc.data, &manifest, yaml.Strict()); err != nil {
				return FireflyConfig{}, fmt.Errorf("while decoding WIMConfiguration manifest #%d: %w", doc.index, err)
			}
			if len(manifest.FireflyConfig.ServiceAccounts) > 0 {
				return FireflyConfig{}, Fixable(fmt.Errorf("WIMConfiguration manifest must not embed serviceAccounts directly; define them in dedicated ServiceAccount manifests"))
			}
			if len(manifest.FireflyConfig.Policies) > 0 {
				return FireflyConfig{}, Fixable(fmt.Errorf("WIMConfiguration manifest must not embed policies directly; define them in dedicated WIMIssuerPolicy manifests"))
			}
			result = manifest.FireflyConfig
			configSeen = true
		}
	}

	if !configSeen {
		return FireflyConfig{}, Fixable(fmt.Errorf("no WIMConfiguration manifest found"))
	}

	// Attach the collected dependencies back onto the configuration.
	result.ServiceAccounts = append(result.ServiceAccounts, serviceAccounts...)
	result.Policies = append(result.Policies, policies...)

	return result, nil
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

func renderFireflyConfigManifests(cfg FireflyConfig) ([]byte, error) {
	var docs [][]byte

	for _, sa := range cfg.ServiceAccounts {
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

	for _, policy := range cfg.Policies {
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

	configDoc := cfg
	configDoc.ServiceAccounts = nil
	configDoc.Policies = nil
	configDoc.ServiceAccountIDs = nil
	manifest := configurationManifest{
		Kind:          kindConfiguration,
		FireflyConfig: configDoc,
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
