package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ngtsDataplaneURL returns the NGTS-only dataplane URL for the given TSG ID and
// environment. The environment is derived from the AuthURL of the current
// context (see envFromAuthURL).
func ngtsDataplaneURL(tsgID, env string) (string, error) {
	switch env {
	case "prod":
		return fmt.Sprintf("https://%s.ngts.paloaltonetworks.com", tsgID), nil
	case "qa":
		return fmt.Sprintf("https://%s.ngts.qa.venafi.io", tsgID), nil
	default:
		return "", fmt.Errorf("NGTS dataplane URL not yet known for environment %q", env)
	}
}

func tsgurlCmd(groupID string) *cobra.Command {
	return &cobra.Command{
		Use:           "tsgurl",
		Short:         "Prints the NGTS dataplane URL for the current TSG context.",
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := loadFileConf(cmd.Context())
			if err != nil {
				return fmt.Errorf("loading configuration: %w", err)
			}

			ctx, ok := currentFrom(conf)
			if !ok {
				return fmt.Errorf("not logged in. Log in with:\n    vcpctl login-tsg\n")
			}

			if ctx.AuthenticationType != "tsg" {
				return fmt.Errorf("current context uses %q authentication; tsgurl requires a TSG context (log in with vcpctl login-tsg)", ctx.AuthenticationType)
			}

			tsgID, err := extractTSGID(ctx.ClientID)
			if err != nil {
				return fmt.Errorf("extracting TSG ID from client ID %q: %w", ctx.ClientID, err)
			}

			env := envFromAuthURL(&ctx)
			url, err := ngtsDataplaneURL(tsgID, env)
			if err != nil {
				return err
			}

			fmt.Println(url)
			return nil
		},
	}
}
