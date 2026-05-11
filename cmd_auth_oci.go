package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

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
			Creates a new OCI token service account with a unique timestamp suffix,
			generates a token, and runs 'docker login' against the Venafi OCI registry.

			Each run creates a NEW service account (e.g., 'user-docker-20260511143022')
			rather than reusing an existing one. This ensures that previous credentials
			remain valid and are not invalidated by subsequent runs.

			The service account base name defaults to your OS username ($USER). You can
			override it with --sa, but a timestamp suffix will still be appended to
			ensure uniqueness.

			By default all available ociToken scopes are requested. Use --scope to
			restrict to specific scopes.

			Note: Old service accounts are not automatically cleaned up. You may want to
			periodically review and delete unused service accounts. To help you do that
			interactively, you can use:

			  vcpctl sa rm -i
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

			baseName, err := resolveSAName(saName, "-docker")
			if err != nil {
				return err
			}
			saName = makeUniqueSAName(baseName)

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
	cmd.Flags().StringVar(&saName, "sa", "", "Service account base name (default: $USER-docker, timestamp will be appended)")
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

// makeUniqueSAName appends a timestamp suffix to ensure the service account name is unique.
// This prevents token rotation issues by creating a new SA on each run.
func makeUniqueSAName(baseName string) string {
	timestamp := time.Now().Format("20060102150405")
	return baseName + "-" + timestamp
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

	const defaultSecretNameNGTS = "ngts-image-pull-secret"
	const defaultSecretNameVenafi = "venafi-image-pull-secret"
	const defaultNamespace = "venafi"

	cmd := &cobra.Command{
		Use:   "pullsecret",
		Short: "Create or update a Kubernetes image pull secret for the Venafi OCI registry",
		Long: undent.Undent(`
			Creates a new OCI token service account with a unique timestamp suffix,
			generates a token, and creates or updates Kubernetes docker-registry Secrets
			with the resulting credentials.

			Each run creates a NEW service account (e.g., 'user-pullsecret-20260511143022')
			rather than reusing an existing one. This ensures that previous credentials
			remain valid and are not invalidated by subsequent runs.

			By default, two secrets are created for compatibility:
			  - 'venafi-image-pull-secret' (for CyberArk Certificate Manager SaaS and Self-Hosted)
			  - 'ngts-image-pull-secret' (for NGTS documentation)

			If you specify a custom --secret-name, only that single secret is created.

			The namespace defaults to 'venafi' and is created if it does not already exist.
			Secrets are applied via 'kubectl apply', so it is safe to run repeatedly.

			Use --print-yaml to print the Secret manifest(s) to stdout instead of applying
			them with kubectl. This is useful for piping into GitOps workflows or for
			inspecting the result before applying.

			The service account base name defaults to your OS username ($USER). You can
			override it with --sa, but a timestamp suffix will still be appended to
			ensure uniqueness.

			Note: Old service accounts are not automatically cleaned up. You may want to
			periodically review and delete unused service accounts. To help you do that
			interactively, you can use:

			  vcpctl sa rm -i
		`),
		Example: undent.Undent(`
			# Create both default secrets (venafi-image-pull-secret and ngts-image-pull-secret):
			vcpctl auth pullsecret

			# Create both default secrets in a different namespace:
			vcpctl auth pullsecret -n cert-manager

			# Create only a custom-named secret:
			vcpctl auth pullsecret --secret-name my-pull-secret -n cert-manager

			# Print YAML for both default secrets:
			vcpctl auth pullsecret --print-yaml

			# Print YAML for a custom secret:
			vcpctl auth pullsecret --secret-name my-pull-secret --print-yaml -n cert-manager
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

			baseName, err := resolveSAName(saName, "-pullsecret")
			if err != nil {
				return err
			}
			saName = makeUniqueSAName(baseName)

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

			// Determine which secrets to create
			var secretNames []string
			if secretName != "" {
				// Custom secret name provided - only create that one
				secretNames = []string{secretName}
			} else {
				// No custom name - create both default secrets for compatibility
				secretNames = []string{defaultSecretNameVenafi, defaultSecretNameNGTS}
			}

			if printYAML {
				for i, name := range secretNames {
					if i > 0 {
						fmt.Println("---")
					}
					if err := kubectlPrintSecretYAML(name, ns, creds.Username, creds.Password, registry); err != nil {
						return err
					}
				}
				return nil
			}

			if err := kubectlEnsureNamespace(ns); err != nil {
				return err
			}

			for _, name := range secretNames {
				if err := kubectlCreateSecret(name, ns, creds.Username, creds.Password, registry); err != nil {
					return err
				}
			}

			// Print summary
			if len(secretNames) == 1 {
				logutil.Infof("✅  Kubernetes secret '%s' created/updated in namespace '%s'", secretNames[0], ns)
			} else {
				logutil.Infof("✅  Kubernetes secret created/updated in namespace '%s': %s", ns, strings.Join(secretNames, ", "))
			}
			logutil.Infof("    Service account: %s (client ID: %s)", saName, saID)
			logutil.Infof("    OCI username:    %s", creds.Username)
			logutil.Infof("    Registry:        %s", registry)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&scopes, "scope", []string{"all"}, "OCI scopes to request. Use 'all' for all available ociToken scopes.")
	cmd.Flags().StringVar(&saName, "sa", "", "Service account base name (default: $USER-pullsecret, timestamp will be appended)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", `Kubernetes namespace for the secret (default: "venafi")`)
	cmd.Flags().StringVar(&secretName, "secret-name", "", `Name of the Kubernetes secret (default: creates both "venafi-image-pull-secret" and "ngts-image-pull-secret")`)
	cmd.Flags().BoolVar(&printYAML, "print-yaml", false, "Print the Secret manifest(s) as YAML to stdout instead of applying them with kubectl")
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
