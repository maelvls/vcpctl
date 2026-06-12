package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/maelvls/vcpctl/logutil"
	"github.com/mattn/go-isatty"
)

// tsgOption represents a TSG option for selection
type tsgOption struct {
	id      string
	display string
}

// fetchAvailableTSGs fetches all TSGs from the API using the provided ToolConf
func fetchAvailableTSGs(ctx context.Context, conf ToolConf) ([]tenantServiceGroup, error) {
	cl, err := newAccessTokenAPIClient(conf)
	if err != nil {
		return nil, fmt.Errorf("creating API client: %w", err)
	}

	resp, err := makeAPIRequest(ctx, cl, conf.AuthenticationType, "GET", "/tenancy/v1/tenant_service_groups?hierarchy=true", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching TSGs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var data tenantServiceGroupResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decoding TSG response: %w", err)
	}

	return data.Items, nil
}

// flattenTSGHierarchy converts a hierarchical TSG tree to a flat list with visual indentation
func flattenTSGHierarchy(tsgs []tenantServiceGroup, level int) []tsgOption {
	var options []tsgOption
	for _, tsg := range tsgs {
		indent := strings.Repeat("  ", level)
		display := fmt.Sprintf("%s%s  %s", indent, tsg.ID, tsg.DisplayName)
		options = append(options, tsgOption{
			id:      tsg.ID,
			display: display,
		})
		if len(tsg.Children) > 0 {
			options = append(options, flattenTSGHierarchy(tsg.Children, level+1)...)
		}
	}
	return options
}

// promptTSGSelection presents an interactive UI for selecting a TSG
func promptTSGSelection(ctx context.Context, conf ToolConf, defaultTSGID string) (string, error) {
	// Check if running in a TTY
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		logutil.Debugf("Not a TTY, skipping TSG selection prompt")
		return defaultTSGID, nil
	}

	// Fetch available TSGs
	tsgs, err := fetchAvailableTSGs(ctx, conf)
	if err != nil {
		return "", fmt.Errorf("fetching available TSGs: %w", err)
	}

	if len(tsgs) == 0 {
		logutil.Infof("No TSGs available for selection")
		return defaultTSGID, nil
	}

	// Flatten the hierarchy to a list
	options := flattenTSGHierarchy(tsgs, 0)

	if len(options) == 0 {
		return defaultTSGID, nil
	}

	// If there's only one option, use it without prompting
	if len(options) == 1 {
		logutil.Infof("Only one TSG available: %s", options[0].id)
		return options[0].id, nil
	}

	// Convert to huh options format
	var huhOptions []huh.Option[string]
	defaultIndex := 0
	for i, opt := range options {
		huhOptions = append(huhOptions, huh.NewOption(opt.display, opt.id))
		if opt.id == defaultTSGID {
			defaultIndex = i
		}
	}

	var selectedTSGID string
	// Set default to the TSG from email if found
	if defaultIndex < len(options) {
		selectedTSGID = options[defaultIndex].id
	} else if len(options) > 0 {
		selectedTSGID = options[0].id
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Which TSG should this context use?").
				Options(huhOptions...).
				Value(&selectedTSGID),
		),
	)

	if err := form.RunWithContext(ctx); err != nil {
		return "", fmt.Errorf("TSG selection cancelled: %w", err)
	}

	return selectedTSGID, nil
}
