# vcpctl

## Overview

To edit the CyberArk Workload Identity Manager configuration (formerly known as Firefly), the associated Sub CA configuration, and policy configuration, you can use the `vcpctl` command line tool.

First off, set the `VEN_API_KEY` and optionally `VEN_API_URL` environment variables for CyberArk Certificate Manager, SaaS:

```bash
export VEN_API_KEY=yourapikey
export VEN_API_URL=https://api.uk.venafi.cloud
```

Then you can use the `vcpctl` command to manage your Workload Identity Manager configurations.

You can list Workload Identity Manager configurations and the related service accounts with:

```bash
vcpctl conf ls
```

You can edit the configuration in your `$EDITOR` with the command:

```bash
vcpctl conf edit test
```

To edit the configuration together with all dependencies (Service Accounts,
policies, and Sub CA), use:

```bash
vcpctl conf edit test --deps
```

You can export a Workload Identity Manager configuration with:

```bash
vcpctl conf get test
```

To also export the associated Sub CA, policies, and service accounts, use the `--deps` flag:

```bash
vcpctl conf get test --deps
```

You can edit a Service Account, Policy, or SubCA Provider with:

```bash
vcpctl sa edit <sa-name>
vcpctl policy edit <policy-name>
vcpctl subca edit <subca-name>
```

You can delete a Workload Identity Manager configuration with:

```bash
vcpctl conf rm test
```

To also delete the associated Sub CA, policies, and service accounts, use the `--deps` flag:

```bash
vcpctl conf rm test --deps
```

You can create (and update) a Workload Identity Manager configuration with:

```bash
vcpctl apply -f test.yaml
```

You can delete the resources declared in a manifest with:

```bash
vcpctl delete -f test.yaml
```

Use `--ignore-not-found` to skip missing resources without failing the command.

> [!NOTE]
>
> The `apply` command expects a kubectl-style multi-document manifest. The order
> of declaration of the resources matters: for example, if want to create a
> `WIMConfiguration` that depends on a `WIMSubCAProvider`, you will have to
> declare the `WIMSubCAProvider` first in the manifest.
>
> The `conf edit --deps` command outputs a multi-document manifest in the same
> order as `conf get --deps`: `WIMConfiguration`, `ServiceAccount`,
> `WIMIssuerPolicy`, `WIMSubCAProvider`.

Example manifest consumed by `vcpctl apply`:

```yaml
kind: ServiceAccount
name: demo
authenticationType: rsaKey
credentialLifetime: 365
scopes:
  - distributed-issuance
---
kind: WIMIssuerPolicy
name: demo
validityPeriod: P90D
subject:
  commonName: { type: OPTIONAL, maxOccurrences: 6 }
sans:
  dnsNames: { type: OPTIONAL, maxOccurrences: 6 }
keyUsages:
  - digitalSignature
extendedKeyUsages:
  - ANY
keyAlgorithm:
  allowedValues:
    - EC_P256
  defaultValue: EC_P256
---
kind: WIMSubCAProvider
name: demo
issuingTemplateName: Default
validityPeriod: P90D
commonName: demo
organization: foo
country: France
locality: Toulouse
organizationalUnit: Engineering
stateOrProvince: Occitanie
keyAlgorithm: EC_P256
---
kind: WIMConfiguration
name: demo
clientAuthentication:
  type: JWT_JWKS
  urls:
    - https://google.com/.well-known/jwks.json
cloudProviders: {}
minTlsVersion: TLS13
subCaProviderName: demo
policyNames:
  - demo
serviceAccountNames:
  - demo
advancedSettings:
  enableIssuanceAuditLog: true
```

## Schema of config.yaml

In VSCode or any other editor supporting the YAML LSP, you can add the following
comment to the top of your `config.yaml` file to enable schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/maelvls/vcpctl/refs/heads/main/genschema/schema.json
name: test
```
