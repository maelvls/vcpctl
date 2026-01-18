package main

import (
	"fmt"

	api "github.com/maelvls/vcpctl/api"
)

func newAPIClient(conf ToolConf) (*api.Client, error) {
	if conf.AccessToken != "" {
		return api.NewAccessTokenClient(conf.APIURL, conf.AccessToken)
	}
	if conf.APIKey == "" {
		return nil, fmt.Errorf("missing authentication credentials (no access token or API key)")
	}
	return api.NewAPIKeyClient(conf.APIURL, conf.APIKey)
}
