# vcpctl

## Overview

To edit the Firefly configuration, Firefly Sub CA configuration, and Firefly
Policies configuration, you can use the `vcpctl` command line tool.

First off, set `APIKEY`:

```bash
export APIKEY=yourapikey
```

You can list the Firefly configurations with:

```bash
vcpctl ls
```

You can edit the configuration in your `$EDITOR` with the command:

```bash
vcpctl edit test
```
