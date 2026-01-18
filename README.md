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
vcpctl edit test
```

You can export a Workload Identity Manager configuration with:

```bash
vcpctl conf get test
```

To also export the associated Sub CA, policies, and service accounts, use the `--deps` flag:

```bash
vcpctl conf get test --deps
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
> The `apply` and `edit` commands expect a kubectl-style multi-document manifest. Declare
> `ServiceAccount` resources first, followed by `WIMIssuerPolicy` resources, and finish
> with a single `WIMConfiguration` resource. All dependencies (service accounts, issuer
> policies, and the Sub CA) are created or patched automatically.

Example manifest consumed by `vcpctl apply`:

```yaml
kind: ServiceAccount
name: sa-demo
authenticationType: rsaKey
credentialLifetime: 365
enabled: true
scopes:
  - distributed-issuance
---
kind: WIMIssuerPolicy
name: policy-demo
validityPeriod: P90D
subject:
  commonName: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  country: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  locality: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  organization: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  organizationalUnit: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  stateOrProvince: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
sans:
  dnsNames: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  ipAddresses: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  rfc822Names: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
  uniformResourceIdentifiers: {type: OPTIONAL, allowedValues: [], defaultValues: [], minOccurrences: 0, maxOccurrences: 1}
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
caType: BUILTIN
validityPeriod: P90D
commonName: demo
organization: DemoOrg
country: US
locality: City
organizationalUnit: Unit
stateOrProvince: State
keyAlgorithm: EC_P256
pkcs11:
  allowedClientLibraries: []
  partitionLabel: ""
  partitionSerialNumber: ""
  pin: ""
  signingEnabled: false
---
kind: WIMConfiguration
name: wim-demo
clientAuthentication: {}
clientAuthorization:
  customClaimsAliases:
    configuration: ""
    allowAllPolicies: ""
    allowedPolicies: ""
cloudProviders: {}
minTlsVersion: TLS13
subCaProvider: demo
advancedSettings:
  enableIssuanceAuditLog: true
  includeRawCertDataInAuditLog: false
  requireFIPSCompliantBuild: false
```


## Schema of config.yaml

In VSCode or any other editor supporting the YAML LSP, you can add the following
comment to the top of your `config.yaml` file to enable schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/maelvls/vcpctl/refs/heads/main/genschema/schema.json
name: test
```
