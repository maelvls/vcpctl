package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/maelvls/undent"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/spf13/cobra"
)

type tenantServiceGroup struct {
	ID              string               `json:"id"`
	DisplayName     string               `json:"display_name"`
	ParentID        string               `json:"parent_id,omitempty"`
	Children        []tenantServiceGroup `json:"children,omitempty"`
	ScimEnabled     string               `json:"scim_enabled,omitempty"`
	InactivityTimeout int                `json:"inactivity_timeout,omitempty"`
	LocalEnabled    string               `json:"local_enabled,omitempty"`
	IDPEnabled      string               `json:"idp_enabled,omitempty"`
	Vertical        string               `json:"vertical,omitempty"`
}

type tenantServiceGroupResponse struct {
	Items []tenantServiceGroup `json:"items"`
	Count int                  `json:"count"`
}

func tsgSubcmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tsg",
		Short:   "Manage TSGs (Tenant Service Groups)",
		GroupID: groupID,
	}

	cmd.AddCommand(
		tsgLsCmd(),
		tsgSwitchCmd(),
	)

	return cmd
}

func tsgLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List TSGs in a hierarchical view",
		Long: undent.Undent(`
			List all TSGs (Tenant Service Groups) in a hierarchical tree view.
			Each TSG is displayed with its ID and display name, with indentation
			showing the hierarchy level.
		`),
		Example: undent.Undent(`
			# List all TSGs
			vcpctl tsg ls
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTsgLs(cmd)
		},
	}

	return cmd
}

func runTsgLs(cmd *cobra.Command) error {
	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	cl, err := newAPIClient(conf)
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	resp, err := makeAPIRequest(cmd.Context(), cl, conf.AuthenticationType, "GET", "/tenancy/v1/tenant_service_groups?hierarchy=true", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var data tenantServiceGroupResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Print the hierarchy
	for _, item := range data.Items {
		printTsgHierarchy(item, 0)
	}

	return nil
}

func printTsgHierarchy(tsg tenantServiceGroup, level int) {
	indent := strings.Repeat("  ", level)
	fmt.Printf("%s%s  %s\n", indent, tsg.ID, tsg.DisplayName)

	for _, child := range tsg.Children {
		printTsgHierarchy(child, level+1)
	}
}

func tsgSwitchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch [tsg-id]",
		Short: "Switch the current context to use a different TSG",
		Long: undent.Undent(`
			Switch the current context to use a different TSG ID.

			When run without arguments, presents an interactive selector to choose
			from available TSGs. When run with a TSG ID argument, directly updates
			the current context to use that TSG.

			This command requires an active TSG (NGTS) context. Use 'vcpctl tsg ls'
			to see available TSGs.
		`),
		Example: undent.Undent(`
			# Interactive TSG selection
			vcpctl tsg switch

			# Switch to a specific TSG
			vcpctl tsg switch 1526746475
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTsgSwitch(cmd, args)
		},
	}

	return cmd
}

func runTsgSwitch(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	conf, err := getToolConfig(cmd)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	// Verify it's a TSG context
	if conf.AuthenticationType != "tsg" {
		return fmt.Errorf("current context is not a TSG context (type: %s). Use 'vcpctl switch' to select a TSG context first.", conf.AuthenticationType)
	}

	var newTSGID string

	if len(args) > 0 {
		// TSG ID provided as argument
		newTSGID = args[0]
	} else {
		// Interactive TSG selection
		// Determine default TSG ID
		defaultTSGID := conf.TSGID
		if defaultTSGID == "" {
			// Extract from ClientID if not stored
			extracted, err := extractTSGIDForRefresh(conf.ClientID)
			if err != nil {
				return fmt.Errorf("extracting TSG ID from client ID: %w", err)
			}
			defaultTSGID = extracted
		}

		// Prompt for TSG selection
		selectedTSG, err := promptTSGSelection(ctx, conf, defaultTSGID)
		if err != nil {
			return fmt.Errorf("TSG selection: %w", err)
		}
		newTSGID = selectedTSG
	}

	// Check if we need to fetch a new access token for the new TSG
	// by examining the tsg_id claim in the current JWT access token
	var newAccessToken string
	if conf.AccessToken != "" {
		currentTokenTSGID, err := extractTSGIDFromToken(conf.AccessToken)
		if err != nil {
			logutil.Debugf("Failed to extract tsg_id from current token: %v. Will fetch new token.", err)
			// If we can't extract the TSG ID from the token, fetch a new one to be safe
			newAccessToken, err = fetchTSGAccessToken(ctx, conf.AuthURL, conf.ClientID, conf.ClientSecret, newTSGID)
			if err != nil {
				return fmt.Errorf("obtaining access token for TSG %s: %w", newTSGID, err)
			}
			logutil.Infof("✅  Successfully obtained access token for TSG %s", newTSGID)
		} else if currentTokenTSGID != newTSGID {
			logutil.Infof("Current token is for TSG %s, switching to TSG %s requires a new access token", currentTokenTSGID, newTSGID)

			// Fetch new access token with the new TSG scope
			newAccessToken, err = fetchTSGAccessToken(ctx, conf.AuthURL, conf.ClientID, conf.ClientSecret, newTSGID)
			if err != nil {
				return fmt.Errorf("obtaining access token for TSG %s: %w", newTSGID, err)
			}

			logutil.Infof("✅  Successfully obtained access token for TSG %s", newTSGID)
		} else {
			logutil.Debugf("Current token already has tsg_id=%s, no need to fetch a new one", newTSGID)
		}
	} else {
		// No access token available, fetch a new one
		logutil.Debugf("No access token available, fetching new token for TSG %s", newTSGID)
		newAccessToken, err = fetchTSGAccessToken(ctx, conf.AuthURL, conf.ClientID, conf.ClientSecret, newTSGID)
		if err != nil {
			return fmt.Errorf("obtaining access token for TSG %s: %w", newTSGID, err)
		}
		logutil.Infof("✅  Successfully obtained access token for TSG %s", newTSGID)
	}

	// Update the context with new TSG ID and access token (if we got a new one)
	if err := updateContextTSGID(ctx, conf.ContextName, newTSGID, newAccessToken); err != nil {
		return fmt.Errorf("updating context: %w", err)
	}

	return nil
}

// updateContextTSGID updates the TSG ID and optionally the access token for a specific context in the config file
func updateContextTSGID(ctx context.Context, contextName, tsgID, newAccessToken string) error {
	conf, err := loadFileConf(ctx)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	found := false
	for i := range conf.ToolContexts {
		if conf.ToolContexts[i].Name == contextName {
			conf.ToolContexts[i].TSGID = tsgID
			// Update access token only if a new one was provided
			if newAccessToken != "" {
				conf.ToolContexts[i].AccessToken = newAccessToken
			}
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("context %q not found", contextName)
	}

	if err := saveFileConf(conf); err != nil {
		return fmt.Errorf("saving configuration: %w", err)
	}

	logutil.Infof("✅  Updated TSG ID to %s for context '%s'", tsgID, contextName)
	return nil
}

// extractTSGIDFromToken extracts the tsg_id claim from a JWT access token
func extractTSGIDFromToken(accessToken string) (string, error) {
	// Parse the JWT without validating the signature (we just need to read claims)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims type")
	}

	// Extract tsg_id from claims
	tsgID, ok := claims["tsg_id"].(string)
	if !ok {
		return "", fmt.Errorf("tsg_id claim not found or not a string")
	}

	return tsgID, nil
}
