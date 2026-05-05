package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

func authDockerCmd() *cobra.Command {
	var scopes []string
	var saName string
	cmd := &cobra.Command{
		Use:   "docker",
		Short: "Configure Docker to pull from the Venafi OCI registry",
		Long: undent.Undent(`
			Creates or updates an OCI token service account, generates a fresh token,
			and runs 'docker login' against the Venafi OCI registry.

			The service account name defaults to your OS username ($USER). You can
			override it with --sa.

			By default all available ociToken scopes are requested. Use --scope to
			restrict to specific scopes.
		`),
		Example: undent.Undent(`
			vcpctl auth docker
			vcpctl auth docker --scope oci-registry-firefly-ent
			vcpctl auth docker --sa my-sa --scope oci-registry-cm
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			registry, err := ociRegistryFromConf(conf)
			if err != nil {
				return err
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			saName, err = resolveSAName(saName, "-docker")
			if err != nil {
				return err
			}

			resolvedScopes, err := resolveOciScopes(cmd.Context(), apiClient, scopes)
			if err != nil {
				return err
			}

			saID, err := ensureOciServiceAccount(cmd.Context(), apiClient, saName, resolvedScopes)
			if err != nil {
				return err
			}
			creds, err := genOciCreds(cmd.Context(), apiClient, saID, conf.APIURL, registry)
			if err != nil {
				return err
			}

			if err := dockerLogin(creds.Username, creds.Password, registry); err != nil {
				return err
			}

			logutil.Infof("✅  Docker configured for %s", registry)
			logutil.Infof("    Service account: %s (client ID: %s)", saName, saID)
			logutil.Infof("    OCI username:    %s", creds.Username)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"all"}, "OCI scopes to request. Use 'all' for all available ociToken scopes.")
	cmd.Flags().StringVar(&saName, "sa", "", "Service account name (default: $USER-docker)")
	return cmd
}

// resolveSAName returns saName if non-empty, otherwise falls back to $USER+suffix.
func resolveSAName(saName, suffix string) (string, error) {
	if saName != "" {
		return saName, nil
	}
	if v := os.Getenv("USER"); v != "" {
		return v + suffix, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("could not determine current user for SA name; set --sa explicitly: %w", err)
	}
	return u.Username + suffix, nil
}

// resolveOciScopes expands the "all" shorthand into the full list of ociToken scopes.
func resolveOciScopes(ctx context.Context, apiClient *api.Client, scopes []string) ([]string, error) {
	if len(scopes) == 1 && scopes[0] == "all" {
		all, err := api.GetServiceAccountScopesByType(ctx, apiClient, "ociToken")
		if err != nil {
			return nil, fmt.Errorf("while retrieving available scopes for 'ociToken': %w", err)
		}
		logutil.Debugf("Using all available scopes for 'ociToken': %s", strings.Join(all, ", "))
		return all, nil
	}
	return scopes, nil
}

// ociRegistryFromConf returns the OCI registry hostname for the given context.
//
// For NGTS (tsg) contexts the registry is determined by environment:
//   - prod → registry.ngts.paloaltonetworks.com
//   - qa   → registry.ngts.qa.venafi.io
//   - dev  → error (not yet known)
//
// For VCP contexts the registry is derived from the API URL hostname:
//   - api.venafi.cloud        → private-registry.venafi.cloud
//   - api.eu.venafi.cloud     → private-registry.eu.venafi.cloud
//   - api-dev210.qa.venafi.io → private-registry-dev210.qa.venafi.io
func ociRegistryFromConf(conf ToolConf) (string, error) {
	if conf.AuthenticationType == "tsg" {
		env := envFromAuthURL(&ToolContext{AuthURL: conf.AuthURL})
		switch env {
		case "prod":
			return "registry.ngts.paloaltonetworks.com", nil
		case "qa":
			return "registry.ngts.qa.venafi.io", nil
		default:
			return "", fmt.Errorf("OCI registry URL not yet known for NGTS environment %q", env)
		}
	}

	u, err := url.Parse(conf.APIURL)
	if err != nil {
		return "", fmt.Errorf("invalid API URL %q: %w", conf.APIURL, err)
	}
	host := u.Hostname()

	// api.venafi.cloud → private-registry.venafi.cloud
	// api.eu.venafi.cloud → private-registry.eu.venafi.cloud
	if suffix, ok := strings.CutPrefix(host, "api."); ok {
		return "private-registry." + suffix, nil
	}
	// api-dev210.qa.venafi.io → private-registry-dev210.qa.venafi.io
	if suffix, ok := strings.CutPrefix(host, "api-"); ok {
		return "private-registry-" + suffix, nil
	}

	return "", fmt.Errorf("cannot determine OCI registry from API URL %q", conf.APIURL)
}

// dockerLogin runs 'docker login' for the given registry.
func dockerLogin(username, password, registry string) error {
	cmd := exec.Command("docker", "login", registry, "--username", username, "--password-stdin")
	cmd.Stdin = strings.NewReader(password)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("'docker login %s' failed: %w", registry, err)
	}
	return nil
}

func authPullSecretCmd() *cobra.Command {
	var scopes []string
	var saName string
	var namespace string
	var secretName string
	var printYAML bool

	const defaultSecretName = "ngts-image-pull-secret"
	const defaultNamespace = "venafi"

	cmd := &cobra.Command{
		Use:   "pullsecret",
		Short: "Create or update a Kubernetes image pull secret for the Venafi OCI registry",
		Long: undent.Undent(`
			Creates or updates an OCI token service account, generates a fresh token,
			and creates or updates a Kubernetes docker-registry Secret with the
			resulting credentials.

			The secret name defaults to 'ngts-image-pull-secret' and the namespace
			defaults to 'venafi'. The namespace is created if it does not already exist.
			The secret is applied via 'kubectl apply', so it is safe to run repeatedly.

			Use --print-yaml to print the Secret manifest to stdout instead of applying
			it with kubectl. This is useful for piping into GitOps workflows or for
			inspecting the result before applying.

			The service account name defaults to your OS username ($USER). You can
			override it with --sa.
		`),
		Example: undent.Undent(`
			vcpctl auth pullsecret
			vcpctl auth pullsecret -n cert-manager
			vcpctl auth pullsecret --secret-name my-pull-secret -n cert-manager
			vcpctl auth pullsecret --print-yaml
			vcpctl auth pullsecret --print-yaml -n cert-manager
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			registry, err := ociRegistryFromConf(conf)
			if err != nil {
				return err
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("while creating API client: %w", err)
			}

			saName, err = resolveSAName(saName, "-pullsecret")
			if err != nil {
				return err
			}

			resolvedScopes, err := resolveOciScopes(cmd.Context(), apiClient, scopes)
			if err != nil {
				return err
			}

			saID, err := ensureOciServiceAccount(cmd.Context(), apiClient, saName, resolvedScopes)
			if err != nil {
				return err
			}

			creds, err := genOciCreds(cmd.Context(), apiClient, saID, conf.APIURL, registry)
			if err != nil {
				return err
			}

			ns := namespace
			if ns == "" {
				ns = defaultNamespace
			}
			name := secretName
			if name == "" {
				name = defaultSecretName
			}

			if printYAML {
				return kubectlPrintSecretYAML(name, ns, creds.Username, creds.Password, registry)
			}

			if err := kubectlEnsureNamespace(ns); err != nil {
				return err
			}
			if err := kubectlCreateSecret(name, ns, creds.Username, creds.Password, registry); err != nil {
				return err
			}

			logutil.Infof("✅  Kubernetes secret '%s' created/updated in namespace '%s'", name, ns)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"all"}, "OCI scopes to request. Use 'all' for all available ociToken scopes.")
	cmd.Flags().StringVar(&saName, "sa", "", "Service account name (default: $USER-pullsecret)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", `Kubernetes namespace for the secret (default: "venafi")`)
	cmd.Flags().StringVar(&secretName, "secret-name", "", `Name of the Kubernetes secret (default: "ngts-image-pull-secret")`)
	cmd.Flags().BoolVar(&printYAML, "print-yaml", false, "Print the Secret manifest as YAML to stdout instead of applying it with kubectl")
	return cmd
}

// kubectlEnsureNamespace creates the namespace if it does not already exist,
// using 'kubectl create namespace --dry-run=client -o yaml | kubectl apply -f -'.
func kubectlEnsureNamespace(namespace string) error {
	create := exec.Command("kubectl", "create", "namespace", namespace, "--dry-run=client", "-o", "yaml")
	create.Stderr = os.Stderr

	apply := exec.Command("kubectl", "apply", "-f", "-")
	apply.Stdout = os.Stdout
	apply.Stderr = os.Stderr

	pipe, err := create.StdoutPipe()
	if err != nil {
		return fmt.Errorf("while creating pipe: %w", err)
	}
	apply.Stdin = pipe

	if err := create.Start(); err != nil {
		return fmt.Errorf("while starting 'kubectl create namespace': %w", err)
	}
	if err := apply.Start(); err != nil {
		return fmt.Errorf("while starting 'kubectl apply': %w", err)
	}
	if err := create.Wait(); err != nil {
		return fmt.Errorf("'kubectl create namespace' failed: %w", err)
	}
	if err := apply.Wait(); err != nil {
		return fmt.Errorf("'kubectl apply' failed: %w", err)
	}
	return nil
}

// kubectlPrintSecretYAML prints the YAML manifest for a docker-registry secret
// to stdout without applying it.
func kubectlPrintSecretYAML(secretName, namespace, username, password, server string) error {
	cmd := exec.Command("kubectl",
		"create", "secret", "docker-registry", secretName,
		"--docker-server="+server,
		"--docker-username="+username,
		"--docker-password="+password,
		"--namespace="+namespace,
		"--dry-run=client", "-o", "yaml",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("'kubectl create secret' failed: %w", err)
	}
	return nil
}

// kubectlCreateSecret creates or updates a Kubernetes docker-registry secret
// by piping 'kubectl create secret ... --dry-run=client -o yaml' into
// 'kubectl apply -f -'.
func kubectlCreateSecret(secretName, namespace, username, password, server string) error {
	createArgs := []string{
		"create", "secret", "docker-registry", secretName,
		"--docker-server=" + server,
		"--docker-username=" + username,
		"--docker-password=" + password,
		"--dry-run=client", "-o", "yaml",
	}
	if namespace != "" {
		createArgs = append(createArgs, "--namespace="+namespace)
	}

	applyArgs := []string{"apply", "-f", "-"}
	if namespace != "" {
		applyArgs = append(applyArgs, "--namespace="+namespace)
	}

	create := exec.Command("kubectl", createArgs...)
	create.Stderr = os.Stderr

	apply := exec.Command("kubectl", applyArgs...)
	apply.Stdout = os.Stdout
	apply.Stderr = os.Stderr

	pipe, err := create.StdoutPipe()
	if err != nil {
		return fmt.Errorf("while creating pipe: %w", err)
	}
	apply.Stdin = pipe

	if err := create.Start(); err != nil {
		return fmt.Errorf("while starting 'kubectl create secret': %w", err)
	}
	if err := apply.Start(); err != nil {
		return fmt.Errorf("while starting 'kubectl apply': %w", err)
	}
	if err := create.Wait(); err != nil {
		return fmt.Errorf("'kubectl create secret' failed: %w", err)
	}
	if err := apply.Wait(); err != nil {
		return fmt.Errorf("'kubectl apply' failed: %w", err)
	}
	return nil
}
