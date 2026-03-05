package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
)

func loginWithBearerToken(ctx context.Context, tenantUrl string, bearerToken string, contextFlag string) error {
	tenantUrl = strings.TrimSpace(tenantUrl)

	if bearerToken == "" {
		return errutil.Fixable(fmt.Errorf("bearer token cannot be empty"))
	}
	if !strings.HasPrefix(tenantUrl, "https://") && !strings.HasPrefix(tenantUrl, "http://") {
		tenantUrl = "https://" + tenantUrl
	}

	current := Auth{
		APIURL:             tenantUrl,
		AuthenticationType: "bearerToken",
		AccessToken:        bearerToken,
	}

	current, err := saveCurrentContext(ctx, current, contextFlag)
	if err != nil {
		return fmt.Errorf("saving configuration for %s: %w", current.TenantURL, err)
	}

	logutil.Infof("✅  You are now authenticated. Context: %s", displayContextForSelection(current))
	return nil
}
