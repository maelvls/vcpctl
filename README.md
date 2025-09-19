# vcpctl

## Overview

To edit the CyberArk Workload Identity Manager configuration (formerly known as Firefly), the associated Sub CA configuration, and policy configuration, you can use the `vcpctl` command line tool.

First off, set the `APIKEY` and optionally `APIURL` environment variables for CyberArk Certificate Manager, SaaS:

```bash
export APIKEY=yourapikey
export APIURL=https://api.uk.venafi.cloud
```

Then you can use the `vcpctl` command to manage your Workload Identity Manager configurations.

You can list Workload Identity Manager configurations and the related service accounts with:

```bash
vcpctl ls
```

You can edit the configuration in your `$EDITOR` with the command:

```bash
vcpctl edit test
```

You can export a Workload Identity Manager configuration along with its associated Sub CA, policies, and service account with:

```bash
vcpctl get test
```

You can create (and update) a Workload Identity Manager configuration with:

```bash
vcpctl put -f test.yaml
```

> [!NOTE]
>
> The `put` and `edit` commands will create the missing Workload Identity Manager Sub CA,
> policies, and service accounts.


## Schema of config.yaml

In VSCode or any other editor supporting the YAML LSP, you can add the following
comment to the top of your `config.yaml` file to enable schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/maelvls/vcpctl/refs/heads/main/genschema/schema.json
name: test
```
