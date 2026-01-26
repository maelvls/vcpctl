package main

import (
	"context"
	"errors"
	"fmt"

	api "github.com/maelvls/vcpctl/api"
	"github.com/maelvls/vcpctl/errutil"
	"github.com/maelvls/vcpctl/logutil"
	manifest "github.com/maelvls/vcpctl/manifest"
)

// deleteManifests walks through the provided manifests in reverse order and deletes each
// resource from CyberArk Certificate Manager, SaaS. Note that the manifests order
// matters.
func deleteManifests(ctx context.Context, cl *api.Client, manifests []manifest.Manifest, ignoreNotFound bool) error {
	if err := validateManifests(manifests); err != nil {
		return fmt.Errorf("pre-flight validation failed: %w", err)
	}
	lastErr := error(nil)

	deleteCtx := newManifestDeleteContext(ctx, cl, ignoreNotFound)

	for i := len(manifests) - 1; i >= 0; i-- {
		item := manifests[i]
		var err error
		switch {
		case item.ServiceAccount != nil:
			err = deleteCtx.deleteServiceAccount(ctx, *item.ServiceAccount)
		case item.Policy != nil:
			err = deleteCtx.deletePolicy(ctx, *item.Policy)
		case item.SubCa != nil:
			err = deleteCtx.deleteSubCa(ctx, *item.SubCa)
		case item.WIMConfiguration != nil:
			err = deleteCtx.deleteConfig(ctx, *item.WIMConfiguration)
		default:
			err = fmt.Errorf("manifest #%d: empty or unknown manifest", i+1)
		}

		if err != nil {
			logutil.Errorf("manifest #%d: %v", i+1, err)
			lastErr = err
			continue
		}
	}

	if lastErr != nil {
		return fmt.Errorf("one or more manifests failed to delete")
	}
	return lastErr
}

type manifestDeleteContext struct {
	client         *api.Client
	ignoreNotFound bool
}

func newManifestDeleteContext(ctx context.Context, cl *api.Client, ignoreNotFound bool) *manifestDeleteContext {
	return &manifestDeleteContext{
		client:         cl,
		ignoreNotFound: ignoreNotFound,
	}
}

func (deletectx *manifestDeleteContext) deleteServiceAccount(ctx context.Context, in manifest.ServiceAccount) error {
	if in.Name == "" {
		return fmt.Errorf("ServiceAccount: name must be set")
	}

	err := api.DeleteServiceAccount(ctx, deletectx.client, in.Name)
	switch {
	case errutil.ErrIsNotFound(err) && deletectx.shouldIgnoreNotFound(err):
		return nil
	case errutil.ErrIsNotFound(err):
		return fmt.Errorf("ServiceAccount %q not found", in.Name)
	case err != nil:
		return fmt.Errorf("ServiceAccount %q: %w", in.Name, err)
	}

	logutil.Infof("Deleted ServiceAccount '%s'.", in.Name)
	return nil
}

func (deletectx *manifestDeleteContext) deletePolicy(ctx context.Context, in manifest.Policy) error {
	if in.Name == "" {
		return fmt.Errorf("WIMIssuerPolicy: name must be set")
	}

	err := api.DeletePolicy(ctx, deletectx.client, in.Name)
	switch {
	case errutil.ErrIsNotFound(err) && deletectx.shouldIgnoreNotFound(err):
		return nil
	case errutil.ErrIsNotFound(err):
		return fmt.Errorf("WIMIssuerPolicy %q not found", in.Name)
	case err != nil:
		return fmt.Errorf("WIMIssuerPolicy %q: %w", in.Name, err)
	}

	logutil.Infof("Deleted WIMIssuerPolicy '%s'.", in.Name)
	return nil
}

func (deletectx *manifestDeleteContext) deleteSubCa(ctx context.Context, in manifest.SubCa) error {
	if in.Name == "" {
		return fmt.Errorf("WIMSubCAProvider: name must be set")
	}

	err := api.DeleteSubCaProvider(ctx, deletectx.client, in.Name)
	switch {
	case errutil.ErrIsNotFound(err) && deletectx.shouldIgnoreNotFound(err):
		return nil
	case errutil.ErrIsNotFound(err):
		return fmt.Errorf("WIMSubCAProvider %q not found", in.Name)
	case err != nil:
		return fmt.Errorf("WIMSubCAProvider %q: %w", in.Name, err)
	}

	logutil.Infof("Deleted WIMSubCAProvider '%s'.", in.Name)
	return nil
}

func (deletectx *manifestDeleteContext) deleteConfig(ctx context.Context, in manifest.WIMConfiguration) error {
	if in.Name == "" {
		return fmt.Errorf("WIMConfiguration: name must be set")
	}

	err := api.RemoveConfig(ctx, deletectx.client, in.Name)
	switch {
	case errutil.ErrIsNotFound(err) && deletectx.shouldIgnoreNotFound(err):
		return nil
	case errutil.ErrIsNotFound(err):
		return fmt.Errorf("WIMConfiguration %q not found", in.Name)
	case err != nil:
		return fmt.Errorf("WIMConfiguration %q: %w", in.Name, err)
	}

	logutil.Infof("Deleted WIMConfiguration '%s'.", in.Name)
	return nil
}

func (deletectx *manifestDeleteContext) shouldIgnoreNotFound(err error) bool {
	if !deletectx.ignoreNotFound {
		return false
	}
	var notFound errutil.NotFound
	return errors.As(err, &notFound)
}
