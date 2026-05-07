package main

import (
	"fmt"
	"sort"

	"github.com/maelvls/undent"
	api "github.com/maelvls/vcpctl/api"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"
)

func zonesCmd(groupID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zones",
		Short: "List application zones (application and issuing template combinations)",
		Long: undent.Undent(`
			This command helps you discover the valid zone values you can use with
			VCert, cert-manager, or enterprise-issuer when working with Certificate
			Manager SaaS or NGTS. It outputs one zone per line, in the format:

			<Application Name>\<Issuing Template Name>

			ABOUT ZONES

			The concept of "zones" only exists in VCert, cert-manager, and
			enterprise-issuer (formerly known as Venafi Enhanced Issuer). It does
			not appear in the Certificate Manager SaaS UI or NGTS UI.

			In the context of Certificate Manager SaaS and NGTS, the meaning of
			"zone" is:

			  <Application Name>\<Issuing Template Name>

			The backslash comes from the fact that back when we only had TPP
			(Certificate Manager Self-Hosted), the path to the folder DN
			(distinguished name) used backslashes. It used to look like this:

			  \VED\Policy\venafi-enhanced-issuer\cluster-1

			You could skip the \VED\Policy prefix, which meant the folder DN looked
			like this:

			  venafi-enhanced-issuer\cluster-1

			To keep things coherent between the new product (SaaS) and TPP, it was
			decided to keep the same backslash-based approach, but with a different
			meaning.
		`),
		Example: undent.Undent(`
			vcpctl zones
		`),
		SilenceErrors: true,
		SilenceUsage:  true,
		GroupID:       groupID,
		RunE: func(cmd *cobra.Command, args []string) error {
			conf, err := getToolConfig(cmd)
			if err != nil {
				return fmt.Errorf("getting config: %w", err)
			}

			apiClient, err := newAPIClient(conf)
			if err != nil {
				return fmt.Errorf("creating API client: %w", err)
			}

			// Fetch all issuing templates
			templates, err := api.GetIssuingTemplates(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("getting issuing templates: %w", err)
			}

			// Create a map of template ID -> template name
			templateMap := make(map[openapi_types.UUID]string)
			for _, t := range templates {
				templateMap[t.Id] = t.Name
			}

			// Fetch all applications
			applications, err := api.GetApplications(cmd.Context(), apiClient)
			if err != nil {
				return fmt.Errorf("getting applications: %w", err)
			}

			// Collect all zones (application\template combinations)
			type zone struct {
				appName      string
				templateName string
			}
			var zones []zone

			for _, app := range applications {
				if app.CertificateIssuingTemplateAliasIdMap == nil {
					continue
				}

				// Iterate through all issuing templates associated with this application
				for _, templateID := range app.CertificateIssuingTemplateAliasIdMap {
					if templateName, exists := templateMap[templateID]; exists {
						zones = append(zones, zone{
							appName:      app.Name,
							templateName: templateName,
						})
					}
				}
			}

			// Sort zones by application name, then by template name
			sort.Slice(zones, func(i, j int) bool {
				if zones[i].appName != zones[j].appName {
					return zones[i].appName < zones[j].appName
				}
				return zones[i].templateName < zones[j].templateName
			})

			// Print zones in the format: Application Name\Issuing Template Name
			for _, z := range zones {
				fmt.Printf("%s\\%s\n", z.appName, z.templateName)
			}

			return nil
		},
	}

	return cmd
}
