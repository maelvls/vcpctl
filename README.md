# vcpctl

## Overview

To edit the Firefly configuration, Firefly Sub CA configuration, and Firefly
Policies configuration, you can use the `vcpctl` command line tool.

First off, set the `APIKEY` and optionally `APIURL` environment variables:

```bash
export APIKEY=yourapikey
export APIURL=https://api.uk.venafi.cloud
```

Then you can use the `vcpctl` command to manage your Firefly configurations.

You can list the Firefly configurations and Firefly service accounts with:

```bash
vcpctl ls
```

You can edit the configuration in your `$EDITOR` with the command:

```bash
vcpctl edit test
```

You can export a Firefly configuration along with its associated Sub CA, Policies, and Service Account with:

```bash
vcpctl get test
```

You can create (and update) a Firefly configuration with:

```bash
vcpctl put -f test.yaml
```

> [!NOTE]
>
> The `put` and `edit` commands will create the missing Firefly Sub CA,
> Firefly Policies, and Service Accounts.


## Schema of config.yaml

In VSCode or any other editor supporting the YAML LSP, you can add the following
comment to the top of your `config.yaml` file to enable schema validation:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/maelvls/vcpctl/refs/heads/main/genschema/schema.json
name: test
```