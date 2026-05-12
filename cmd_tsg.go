package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/maelvls/undent"
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
