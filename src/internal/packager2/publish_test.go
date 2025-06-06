// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

package packager2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/defenseunicorns/pkg/oci"
	goyaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/require"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/internal/packager2/filters"
	"github.com/zarf-dev/zarf/src/internal/packager2/layout"
	"github.com/zarf-dev/zarf/src/pkg/lint"
	"github.com/zarf-dev/zarf/src/pkg/zoci"
	"github.com/zarf-dev/zarf/src/test/testutil"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

func defaultTestRemoteOptions() RemoteOptions {
	return RemoteOptions{
		PlainHTTP: true,
	}
}

func pullFromRemote(ctx context.Context, t *testing.T, packageRef string, architecture string, publicKeyPath string) *layout.PackageLayout {
	t.Helper()

	// Generate tmpdir and pull published package from local registry
	tmpdir := t.TempDir()
	pullOCIOpts := pullOCIOptions{
		Source:        packageRef,
		Directory:     tmpdir,
		Architecture:  architecture,
		Filter:        filters.Empty(),
		RemoteOptions: defaultTestRemoteOptions(),
	}
	_, tarPath, err := pullOCI(context.Background(), pullOCIOpts)
	require.NoError(t, err)

	layoutActual, err := layout.LoadFromTar(ctx, tarPath, layout.PackageLayoutOptions{
		Filter:        filters.Empty(),
		PublicKeyPath: publicKeyPath,
	})
	require.NoError(t, err)

	return layoutActual
}

func createRegistry(ctx context.Context, t *testing.T) registry.Reference {
	// Setup destination registry
	dstPort, err := helpers.GetAvailablePort()
	require.NoError(t, err)
	dstRegistryURL := testutil.SetupInMemoryRegistry(ctx, t, dstPort)
	dstRegistryRef := registry.Reference{
		Registry:   dstRegistryURL,
		Repository: "my-namespace",
	}

	return dstRegistryRef
}

func TestPublishError(t *testing.T) {
	ctx := context.Background()
	lint.ZarfSchema = testutil.LoadSchema(t, "../../../zarf.schema.json")

	registryURL := testutil.SetupInMemoryRegistry(ctx, t, 5000)
	defaultRef := registry.Reference{
		Registry:   registryURL,
		Repository: "my-namespace",
	}

	tt := []struct {
		name      string
		path      string
		ref       registry.Reference
		opts      PublishPackageOpts
		expectErr error
	}{
		{
			name:      "Test empty publish opts",
			opts:      PublishPackageOpts{},
			expectErr: errors.New("invalid registry"),
		},
		{
			name:      "Test empty path",
			path:      "",
			ref:       defaultRef,
			opts:      PublishPackageOpts{},
			expectErr: errors.New("path must be specified"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := PublishPackage(context.Background(), tc.path, tc.ref, tc.opts)
			require.ErrorContains(t, err, tc.expectErr.Error())
		})
	}
}

func TestPublishFromOCIValidation(t *testing.T) {
	ctx := context.Background()
	lint.ZarfSchema = testutil.LoadSchema(t, "../../../zarf.schema.json")

	tt := []struct {
		name      string
		src       registry.Reference
		dst       registry.Reference
		opts      PublishFromOCIOpts
		expectErr error
	}{
		{
			name: "errors if src is not a valid ref",
			src: registry.Reference{
				Registry:   "example.com",
				Repository: "my-namespace",
			},
			dst:       registry.Reference{},
			opts:      PublishFromOCIOpts{},
			expectErr: errdef.ErrInvalidReference,
		},
		{
			name: "errors if dst is not a valid ref",
			src: registry.Reference{
				Registry:   "example.com",
				Repository: "my-namespace",
			},
			dst:       registry.Reference{},
			opts:      PublishFromOCIOpts{},
			expectErr: errdef.ErrInvalidReference,
		},
		{
			name: "errors if src's repo name is not the same as dst's",
			src: registry.Reference{
				Registry:   "example.com",
				Repository: "my-namespace",
			},
			dst: registry.Reference{
				Registry:   "example.com",
				Repository: "my-other-namespace",
			},
			opts:      PublishFromOCIOpts{},
			expectErr: errors.New("source and destination repositories must have the same name"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := PublishFromOCI(ctx, tc.src, tc.dst, tc.opts)
			if tc.expectErr != nil {
				require.ErrorContains(t, err, tc.expectErr.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPublishSkeleton(t *testing.T) {
	lint.ZarfSchema = testutil.LoadSchema(t, "../../../zarf.schema.json")

	tt := []struct {
		name string
		path string
		opts PublishSkeletonOpts
	}{
		{
			name: "Publish skeleton package",
			path: "testdata/skeleton",
			opts: PublishSkeletonOpts{
				RemoteOptions: defaultTestRemoteOptions(),
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.TestContext(t)
			registryRef := createRegistry(ctx, t)

			// Publish test package
			err := PublishSkeleton(ctx, tc.path, registryRef, tc.opts)
			require.NoError(t, err)

			// Read and unmarshall expected
			data, err := os.ReadFile(filepath.Join(tc.path, layout.ZarfYAML))
			require.NoError(t, err)
			var expectedPkg v1alpha1.ZarfPackage
			err = goyaml.Unmarshal(data, &expectedPkg)
			require.NoError(t, err)
			// This verifies that publish deletes the manifest that is auto created by oras
			require.NoFileExists(t, expectedPkg.Metadata.Name)

			// Format url and instantiate remote
			ref, err := zoci.ReferenceFromMetadata(registryRef.String(), expectedPkg)
			require.NoError(t, err)
			rmt, err := zoci.NewRemote(ctx, ref, zoci.PlatformForSkeleton(), oci.WithPlainHTTP(true))
			require.NoError(t, err)

			// Fetch from remote and compare
			pkg, err := rmt.FetchZarfYAML(ctx)
			require.NoError(t, err)

			// HACK(mkcp): Match necessary fields to establish equality
			pkg.Build = v1alpha1.ZarfBuildData{}
			pkg.Metadata.AggregateChecksum = ""
			expectedPkg.Metadata.Architecture = "skeleton"

			// NOTE(mkcp): In future schema version move ZarfPackage.Metadata.AggregateChecksum
			// to ZarfPackage.Build.AggregateChecksum. See ADR #26
			require.Equal(t, expectedPkg, pkg)
		})
	}
}

func TestPublishPackage(t *testing.T) {
	tt := []struct {
		name          string
		path          string
		opts          PublishPackageOpts
		publicKeyPath string
	}{
		{
			name: "Publish package",
			path: filepath.Join("testdata", "load-package", "compressed", "zarf-package-test-amd64-0.0.1.tar.zst"),
			opts: PublishPackageOpts{
				Architecture:  "amd64",
				RemoteOptions: defaultTestRemoteOptions(),
			},
		},
		{
			name: "Sign and publish package",
			path: filepath.Join("testdata", "load-package", "compressed", "zarf-package-test-amd64-0.0.1.tar.zst"),
			opts: PublishPackageOpts{
				Architecture:       "amd64",
				RemoteOptions:      defaultTestRemoteOptions(),
				SigningKeyPath:     filepath.Join("testdata", "publish", "cosign.key"),
				SigningKeyPassword: "password",
			},
			publicKeyPath: filepath.Join("testdata", "publish", "cosign.pub"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.TestContext(t)
			registryRef := createRegistry(ctx, t)

			// Publish test package
			err := PublishPackage(ctx, tc.path, registryRef, tc.opts)
			require.NoError(t, err)

			// We want to pull the package and sure the content is the same as the local package
			layoutExpected, err := layout.LoadFromTar(ctx, tc.path, layout.PackageLayoutOptions{Filter: filters.Empty()})
			require.NoError(t, err)
			// Format url and instantiate remote
			packageRef, err := zoci.ReferenceFromMetadata(registryRef.String(), layoutExpected.Pkg)
			require.NoError(t, err)

			layoutActual := pullFromRemote(ctx, t, packageRef, "amd64", tc.publicKeyPath)
			require.Equal(t, layoutExpected.Pkg, layoutActual.Pkg, "Uploaded package is not identical to downloaded package")
			if tc.opts.SigningKeyPath != "" {
				require.FileExists(t, filepath.Join(layoutActual.DirPath(), layout.Signature))
			}
		})
	}
}

func TestPublishPackageDeterministic(t *testing.T) {
	tt := []struct {
		name string
		path string
		opts PublishPackageOpts
	}{
		{
			name: "Publish package",
			path: filepath.Join("testdata", "load-package", "compressed", "zarf-package-test-amd64-0.0.1.tar.zst"),
			opts: PublishPackageOpts{
				RemoteOptions: defaultTestRemoteOptions(),
				Architecture:  "amd64",
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.TestContext(t)
			registryRef := createRegistry(ctx, t)

			// Publish test package
			err := PublishPackage(ctx, tc.path, registryRef, tc.opts)
			require.NoError(t, err)

			// We want to pull the package and sure the content is the same as the local package
			layoutExpected, err := layout.LoadFromTar(ctx, tc.path, layout.PackageLayoutOptions{Filter: filters.Empty()})
			require.NoError(t, err)
			// Format url and instantiate remote
			packageRef, err := zoci.ReferenceFromMetadata(registryRef.String(), layoutExpected.Pkg)
			require.NoError(t, err)

			// Attempt to get the digest
			platform := oci.PlatformForArch(tc.opts.Architecture)
			remote, err := zoci.NewRemote(ctx, packageRef, platform, oci.WithPlainHTTP(tc.opts.PlainHTTP))
			require.NoError(t, err)
			desc, err := remote.ResolveRoot(ctx)
			require.NoError(t, err)
			expectedDigest := desc.Digest.String()

			// Re-publish the package to ensure the digest does not change
			err = PublishPackage(ctx, tc.path, registryRef, tc.opts)
			require.NoError(t, err)
			// Publish creates a local oci manifest file using the package name, which gets deleted
			require.NoFileExists(t, layoutExpected.Pkg.Metadata.Name)

			latestDesc, err := remote.ResolveRoot(ctx)
			require.NoError(t, err)

			require.Equal(t, expectedDigest, latestDesc.Digest.String(), "Original digest is not the same as the latest")
		})
	}
}

func TestPublishCopySHA(t *testing.T) {
	tt := []struct {
		name             string
		packageToPublish string
		opts             PublishPackageOpts
	}{
		{
			name:             "Publish package",
			packageToPublish: filepath.Join("testdata", "load-package", "compressed", "zarf-package-test-amd64-0.0.1.tar.zst"),
			opts: PublishPackageOpts{
				RemoteOptions: defaultTestRemoteOptions(),
				Architecture:  "amd64",
				Concurrency:   3,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.TestContext(t)
			registryRef := createRegistry(ctx, t)

			// Publish test package
			err := PublishPackage(ctx, tc.packageToPublish, registryRef, tc.opts)
			require.NoError(t, err)

			// Setup destination registry
			dstRegistryRef := createRegistry(ctx, t)

			// This gets the test package digest from the first package publish
			localRepo := &remote.Repository{PlainHTTP: true}
			ociSrc := fmt.Sprintf("%s/%s", registryRef.String(), "test:0.0.1")
			localRepo.Reference, err = registry.ParseReference(ociSrc)
			require.NoError(t, err)
			indexDesc, err := oras.Resolve(ctx, localRepo, ociSrc, oras.ResolveOptions{})
			require.NoError(t, err)
			src := fmt.Sprintf("%s/%s@%s", registryRef.String(), "test:0.0.1", indexDesc.Digest)
			srcRef, err := registry.ParseReference(src)
			require.NoError(t, err)

			dst := fmt.Sprintf("%s/%s", dstRegistryRef.String(), "test:0.0.1")
			dstRef, err := registry.ParseReference(dst)
			require.NoError(t, err)

			opts := PublishFromOCIOpts{
				RemoteOptions: tc.opts.RemoteOptions,
				Architecture:  tc.opts.Architecture,
				Concurrency:   tc.opts.Concurrency,
			}

			// Publish test package to the destination registry
			err = PublishFromOCI(ctx, srcRef, dstRef, opts)
			require.NoError(t, err)

			// We want to pull the package and sure the content is the same as the local package
			layoutExpected, err := layout.LoadFromTar(ctx, tc.packageToPublish, layout.PackageLayoutOptions{})
			require.NoError(t, err)
			// This verifies that publish deletes the manifest that is auto created by oras
			require.NoFileExists(t, layoutExpected.Pkg.Metadata.Name)
			// Format url and instantiate remote
			packageRef, err := zoci.ReferenceFromMetadata(dstRegistryRef.String(), layoutExpected.Pkg)
			require.NoError(t, err)

			pkgRefsha := fmt.Sprintf("%s@%s", packageRef, indexDesc.Digest)

			layoutActual := pullFromRemote(ctx, t, pkgRefsha, tc.opts.Architecture, "")
			require.Equal(t, layoutExpected.Pkg, layoutActual.Pkg, "Uploaded package is not identical to downloaded package")
		})
	}
}

func TestPublishCopyTag(t *testing.T) {
	tt := []struct {
		name             string
		packageToPublish string
		opts             PublishPackageOpts
	}{
		{
			name:             "Publish package",
			packageToPublish: filepath.Join("testdata", "load-package", "compressed", "zarf-package-test-amd64-0.0.1.tar.zst"),
			opts: PublishPackageOpts{
				RemoteOptions: defaultTestRemoteOptions(),
				Architecture:  "amd64",
				Concurrency:   3,
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testutil.TestContext(t)
			registryRef := createRegistry(ctx, t)

			// Publish test package
			err := PublishPackage(ctx, tc.packageToPublish, registryRef, tc.opts)
			require.NoError(t, err)

			dstRegistryRef := createRegistry(ctx, t)

			src := fmt.Sprintf("%s/%s", registryRef.String(), "test:0.0.1")
			srcRegistry, err := registry.ParseReference(src)
			require.NoError(t, err)
			dst := fmt.Sprintf("%s/%s", dstRegistryRef.String(), "test:0.0.1")
			dstRegistry, err := registry.ParseReference(dst)
			require.NoError(t, err)

			opts := PublishFromOCIOpts{
				RemoteOptions: tc.opts.RemoteOptions,
				Architecture:  tc.opts.Architecture,
				Concurrency:   tc.opts.Concurrency,
			}

			// Publish test package
			err = PublishFromOCI(ctx, srcRegistry, dstRegistry, opts)
			require.NoError(t, err)

			// We want to pull the package and sure the content is the same as the local package
			layoutExpected, err := layout.LoadFromTar(ctx, tc.packageToPublish, layout.PackageLayoutOptions{})
			require.NoError(t, err)
			// This verifies that publish deletes the manifest that is auto created by oras
			require.NoFileExists(t, layoutExpected.Pkg.Metadata.Name)
			// Format url and instantiate remote
			packageRef, err := zoci.ReferenceFromMetadata(dstRegistryRef.String(), layoutExpected.Pkg)
			require.NoError(t, err)

			layoutActual := pullFromRemote(ctx, t, packageRef, tc.opts.Architecture, "")

			require.Equal(t, layoutExpected.Pkg, layoutActual.Pkg, "Uploaded package is not identical to downloaded package")
		})
	}
}
