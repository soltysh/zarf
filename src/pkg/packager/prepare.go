// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package packager contains functions for interacting with, managing and deploying Zarf packages.
package packager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zarf-dev/zarf/src/pkg/logger"

	"github.com/defenseunicorns/pkg/helpers/v2"
	"github.com/goccy/go-yaml"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/config/lang"
	"github.com/zarf-dev/zarf/src/internal/packager/helm"
	"github.com/zarf-dev/zarf/src/internal/packager/images"
	"github.com/zarf-dev/zarf/src/internal/packager/kustomize"
	"github.com/zarf-dev/zarf/src/pkg/layout"
	"github.com/zarf-dev/zarf/src/pkg/packager/creator"
	"github.com/zarf-dev/zarf/src/pkg/state"
	"github.com/zarf-dev/zarf/src/pkg/utils"
	"github.com/zarf-dev/zarf/src/types"
)

var imageCheck = regexp.MustCompile(`(?mi)"image":"((([a-z0-9._-]+)/)?([a-z0-9._-]+)(:([a-z0-9._-]+))?)"`)
var imageFuzzyCheck = regexp.MustCompile(`(?mi)["|=]([a-z0-9\-.\/:]+:[\w.\-]*[a-z\.\-][\w.\-]*)"`)

// FindImages iterates over a Zarf.yaml and attempts to parse any images.
func (p *Packager) FindImages(ctx context.Context) (map[string][]string, error) {
	l := logger.From(ctx)
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	defer func() {
		// Return to the original working directory
		if err := os.Chdir(cwd); err != nil {
			l.Warn("unable to return to the original working directory", "error", err)
		}
	}()
	if err := os.Chdir(p.cfg.CreateOpts.BaseDir); err != nil {
		return nil, fmt.Errorf("unable to access directory %q: %w", p.cfg.CreateOpts.BaseDir, err)
	}
	l.Info("using build directory", "path", p.cfg.CreateOpts.BaseDir)

	c := creator.NewPackageCreator(p.cfg.CreateOpts, cwd)

	if err := helpers.CreatePathAndCopy(layout.ZarfYAML, p.layout.ZarfYAML); err != nil {
		return nil, err
	}

	pkg, warnings, err := c.LoadPackageDefinition(ctx, p.layout)
	if err != nil {
		return nil, err
	}
	for _, warning := range warnings {
		l.Warn(warning)
	}
	p.cfg.Pkg = pkg

	return p.findImages(ctx)
}

// TODO: Refactor to return output string instead of printing inside of function.
func (p *Packager) findImages(ctx context.Context) (map[string][]string, error) {
	l := logger.From(ctx)
	for _, component := range p.cfg.Pkg.Components {
		if len(component.Repos) > 0 && p.cfg.FindImagesOpts.RepoHelmChartPath == "" {
			msg := "This Zarf package contains git repositories, " +
				"if any repos contain helm charts you want to template and " +
				"search for images, make sure to specify the helm chart path " +
				"via the --repo-chart-path flag"
			l.Info(msg)
			break
		}
	}

	if err := p.populatePackageVariableConfig(); err != nil {
		return nil, fmt.Errorf("unable to set the active variables: %w", err)
	}

	// Set default builtin values so they exist in case any helm charts rely on them
	registryInfo := types.RegistryInfo{Address: p.cfg.FindImagesOpts.RegistryURL}
	err := registryInfo.FillInEmptyValues()
	if err != nil {
		return nil, err
	}
	gitServer := types.GitServerInfo{}
	err = gitServer.FillInEmptyValues()
	if err != nil {
		return nil, err
	}
	artifactServer := types.ArtifactServerInfo{}
	artifactServer.FillInEmptyValues()
	p.state = &state.State{
		RegistryInfo:   registryInfo,
		GitServer:      gitServer,
		ArtifactServer: artifactServer,
	}

	componentDefinition := "\ncomponents:\n"
	imagesMap := map[string][]string{}
	whyResources := []string{}
	for _, component := range p.cfg.Pkg.Components {
		if len(component.Charts)+len(component.Manifests)+len(component.Repos) < 1 {
			// Skip if it doesn't have what we need
			continue
		}

		if p.cfg.FindImagesOpts.RepoHelmChartPath != "" {
			// Also process git repos that have helm charts
			for _, repo := range component.Repos {
				matches := strings.Split(repo, "@")
				if len(matches) < 2 {
					return nil, fmt.Errorf("cannot convert the Git repository %s to a Helm chart without a version tag", repo)
				}

				// If a repo helm chart path is specified,
				component.Charts = append(component.Charts, v1alpha1.ZarfChart{
					Name:    repo,
					URL:     matches[0],
					Version: matches[1],
					// Trim the first char to match how the packager expects it, this is messy,need to clean up better
					GitPath: strings.TrimPrefix(p.cfg.FindImagesOpts.RepoHelmChartPath, "/"),
				})
			}
		}

		componentPaths, err := p.layout.Components.Create(component)
		if err != nil {
			return nil, err
		}
		err = p.populateComponentAndStateTemplates(ctx, component.Name)
		if err != nil {
			return nil, err
		}

		resources := []*unstructured.Unstructured{}
		matchedImages := map[string]bool{}
		maybeImages := map[string]bool{}
		for _, zarfChart := range component.Charts {
			// Generate helm templates for this chart
			err = helm.PackageChart(ctx, zarfChart, componentPaths.Charts, componentPaths.Values)
			if err != nil {
				return nil, fmt.Errorf("unable to package the chart %s: %w", zarfChart.Name, err)
			}

			valuesFilePaths, err := helpers.RecursiveFileList(componentPaths.Values, nil, false)
			// TODO: The values path should exist if the path is set, otherwise it should be empty.
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			for _, valueFilePath := range valuesFilePaths {
				err := p.variableConfig.ReplaceTextTemplate(valueFilePath)
				if err != nil {
					return nil, err
				}
			}

			chart, values, err := helm.LoadChartData(zarfChart, componentPaths.Charts, componentPaths.Values, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to load chart data: %w", err)
			}
			chartTemplate, err := helm.TemplateChart(ctx, zarfChart, chart, values, p.cfg.FindImagesOpts.KubeVersionOverride, p.variableConfig)
			if err != nil {
				return nil, fmt.Errorf("could not render the Helm template for chart %s: %w", zarfChart.Name, err)
			}

			// Break the template into separate resources
			yamls, err := utils.SplitYAML([]byte(chartTemplate))
			if err != nil {
				return nil, err
			}
			resources = append(resources, yamls...)

			chartTarball := helm.StandardName(componentPaths.Charts, zarfChart) + ".tgz"
			annotatedImages, err := helm.FindAnnotatedImagesForChart(chartTarball, values)
			if err != nil {
				return nil, fmt.Errorf("could not look up image annotations for chart URL %s: %w", zarfChart.URL, err)
			}
			for _, image := range annotatedImages {
				matchedImages[image] = true
			}

			// Check if the --why flag is set
			if p.cfg.FindImagesOpts.Why != "" {
				whyResourcesChart, err := findWhyResources(yamls, p.cfg.FindImagesOpts.Why, component.Name, zarfChart.Name, true)
				if err != nil {
					return nil, fmt.Errorf("could not determine why resource for the chart %s: %w", zarfChart.Name, err)
				}
				whyResources = append(whyResources, whyResourcesChart...)
			}
		}

		for _, manifest := range component.Manifests {
			for idx, k := range manifest.Kustomizations {
				// Generate manifests from kustomizations and place in the package
				kname := fmt.Sprintf("kustomization-%s-%d.yaml", manifest.Name, idx)
				// Use the temp folder because if "helpers.CreatePathAndCopy" is provided with the same path it will result in the file being empty
				destination := filepath.Join(componentPaths.Temp, kname)
				if err := kustomize.Build(k, destination, manifest.KustomizeAllowAnyDirectory); err != nil {
					return nil, fmt.Errorf("unable to build the kustomization for %s: %w", k, err)
				}
				manifest.Files = append(manifest.Files, destination)
			}
			// Get all manifest files
			for idx, f := range manifest.Files {
				if helpers.IsURL(f) {
					mname := fmt.Sprintf("manifest-%s-%d.yaml", manifest.Name, idx)
					destination := filepath.Join(componentPaths.Manifests, mname)
					if err := utils.DownloadToFile(ctx, f, destination, component.DeprecatedCosignKeyPath); err != nil {
						return nil, fmt.Errorf(lang.ErrDownloading, f, err.Error())
					}
					f = destination
				} else {
					filename := filepath.Base(f)
					newDestination := filepath.Join(componentPaths.Manifests, filename)
					if err := helpers.CreatePathAndCopy(f, newDestination); err != nil {
						return nil, fmt.Errorf("unable to copy manifest %s: %w", f, err)
					}
					f = newDestination
				}

				if err := p.variableConfig.ReplaceTextTemplate(f); err != nil {
					return nil, err
				}
				// Read the contents of each file
				contents, err := os.ReadFile(f)
				if err != nil {
					return nil, fmt.Errorf("could not read the file %s: %w", f, err)
				}

				// Break the manifest into separate resources
				yamls, err := utils.SplitYAML(contents)
				if err != nil {
					return nil, err
				}
				resources = append(resources, yamls...)

				// Check if the --why flag is set and if it is process the manifests
				if p.cfg.FindImagesOpts.Why != "" {
					whyResourcesManifest, err := findWhyResources(yamls, p.cfg.FindImagesOpts.Why, component.Name, manifest.Name, false)
					if err != nil {
						return nil, fmt.Errorf("could not find why resources for manifest %s: %w", manifest.Name, err)
					}
					whyResources = append(whyResources, whyResourcesManifest...)
				}
			}
		}

		imgCompStart := time.Now()
		l.Info("looking for images in component", "name", component.Name, "resourcesCount", len(resources))

		for _, resource := range resources {
			if matchedImages, maybeImages, err = processUnstructuredImages(ctx, resource, matchedImages, maybeImages); err != nil {
				return nil, fmt.Errorf("could not process the Kubernetes resource %s: %w", resource.GetName(), err)
			}
		}

		sortedMatchedImages, sortedExpectedImages := getSortedImages(matchedImages, maybeImages)

		if len(sortedMatchedImages) > 0 {
			// Log the header comment
			componentDefinition += fmt.Sprintf("\n  - name: %s\n    images:\n", component.Name)
			for _, image := range sortedMatchedImages {
				// Use print because we want this dumped to stdout
				imagesMap[component.Name] = append(imagesMap[component.Name], image)
				componentDefinition += fmt.Sprintf("      - %s\n", image)
			}
		}

		// Handle the "maybes"
		if len(sortedExpectedImages) > 0 {
			var validImages []string
			for _, image := range sortedExpectedImages {
				if descriptor, err := crane.Head(image, images.WithGlobalInsecureFlag()...); err != nil {
					// Test if this is a real image, if not just quiet log to debug, this is normal
					l.Debug("suspected image does not appear to be valid", "error", err)
				} else {
					// Otherwise, add to the list of images
					l.Debug("imaged digest found", "digest", descriptor.Digest)
					validImages = append(validImages, image)
				}
			}

			if len(validImages) > 0 {
				componentDefinition += fmt.Sprintf("      # Possible images - %s - %s\n", p.cfg.Pkg.Metadata.Name, component.Name)
				for _, image := range validImages {
					imagesMap[component.Name] = append(imagesMap[component.Name], image)
					componentDefinition += fmt.Sprintf("      - %s\n", image)
				}
			}
		}

		l.Debug("done looking for images in component",
			"name", component.Name,
			"resourcesCount", len(resources),
			"duration", time.Since(imgCompStart))

		if !p.cfg.FindImagesOpts.SkipCosign {
			// Handle cosign artifact lookups
			if len(imagesMap[component.Name]) > 0 {
				var cosignArtifactList []string
				imgStart := time.Now()
				l.Info("looking up cosign artifacts for discovered images", "count", len(imagesMap[component.Name]))

				for _, image := range imagesMap[component.Name] {
					l.Debug("looking up cosign artifacts for image", "name", imagesMap[component.Name])
					cosignArtifacts, err := utils.GetCosignArtifacts(image)
					if err != nil {
						return nil, fmt.Errorf("could not lookup the cosing artifacts for image %s: %w", image, err)
					}
					cosignArtifactList = append(cosignArtifactList, cosignArtifacts...)
				}

				l.Debug("done looking up cosign artifacts for discovered images", "count", len(imagesMap[component.Name]), "duration", time.Since(imgStart))

				if len(cosignArtifactList) > 0 {
					imagesMap[component.Name] = append(imagesMap[component.Name], cosignArtifactList...)
					componentDefinition += fmt.Sprintf("      # Cosign artifacts for images - %s - %s\n", p.cfg.Pkg.Metadata.Name, component.Name)
					for _, cosignArtifact := range cosignArtifactList {
						componentDefinition += fmt.Sprintf("      - %s\n", cosignArtifact)
					}
				}
			}
		}
	}

	if p.cfg.FindImagesOpts.Why != "" {
		if len(whyResources) == 0 {
			return nil, fmt.Errorf("image %s not found in any charts or manifests", p.cfg.FindImagesOpts.Why)
		}
		return nil, nil
	}

	fmt.Println(componentDefinition)

	return imagesMap, nil
}

func processUnstructuredImages(ctx context.Context, resource *unstructured.Unstructured, matchedImages, maybeImages map[string]bool) (map[string]bool, map[string]bool, error) {
	l := logger.From(ctx)
	contents := resource.UnstructuredContent()
	b, err := resource.MarshalJSON()
	if err != nil {
		return nil, nil, err
	}

	switch resource.GetKind() {
	case "Pod":
		var pod corev1.Pod
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &pod); err != nil {
			return nil, nil, fmt.Errorf("could not parse pod: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, pod.Spec)

	case "CronJob":
		var cronJob batchv1.CronJob
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &cronJob); err != nil {
			return nil, nil, fmt.Errorf("could not parse cronjob: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, cronJob.Spec.JobTemplate.Spec.Template.Spec)

	case "ReplicationController":
		var rc corev1.ReplicationController
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &rc); err != nil {
			return nil, nil, fmt.Errorf("could not parse replicationcontroller: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, rc.Spec.Template.Spec)

	case "Deployment":
		var deployment v1.Deployment
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &deployment); err != nil {
			return nil, nil, fmt.Errorf("could not parse deployment: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, deployment.Spec.Template.Spec)

	case "DaemonSet":
		var daemonSet v1.DaemonSet
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &daemonSet); err != nil {
			return nil, nil, fmt.Errorf("could not parse daemonset: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, daemonSet.Spec.Template.Spec)

	case "StatefulSet":
		var statefulSet v1.StatefulSet
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &statefulSet); err != nil {
			return nil, nil, fmt.Errorf("could not parse statefulset: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, statefulSet.Spec.Template.Spec)

	case "ReplicaSet":
		var replicaSet v1.ReplicaSet
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &replicaSet); err != nil {
			return nil, nil, fmt.Errorf("could not parse replicaset: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, replicaSet.Spec.Template.Spec)

	case "Job":
		var job batchv1.Job
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(contents, &job); err != nil {
			return nil, nil, fmt.Errorf("could not parse job: %w", err)
		}
		matchedImages = appendToImageMap(matchedImages, job.Spec.Template.Spec)

	default:
		// Capture any custom images
		matches := imageCheck.FindAllStringSubmatch(string(b), -1)
		for _, group := range matches {
			l.Debug("found unknown match", "kind", resource.GetKind(), "value", group[1])
			matchedImages[group[1]] = true
		}
	}

	// Capture "maybe images" too for all kinds because they might be in unexpected places.... 👀
	matches := imageFuzzyCheck.FindAllStringSubmatch(string(b), -1)
	for _, group := range matches {
		l.Debug("found possible fuzzy match", "kind", resource.GetKind(), "value", group[1])
		maybeImages[group[1]] = true
	}

	return matchedImages, maybeImages, nil
}

func findWhyResources(resources []*unstructured.Unstructured, whyImage, componentName, resourceName string, isChart bool) ([]string, error) {
	foundWhyResources := []string{}
	for _, resource := range resources {
		b, err := yaml.Marshal(resource.Object)
		if err != nil {
			return nil, err
		}
		yaml := string(b)
		resourceTypeKey := "manifest"
		if isChart {
			resourceTypeKey = "chart"
		}

		if strings.Contains(yaml, whyImage) {
			fmt.Printf("component: %s\n%s: %s\nresource:\n\n%s\n", componentName, resourceTypeKey, resourceName, yaml)
			foundWhyResources = append(foundWhyResources, resourceName)
		}
	}
	return foundWhyResources, nil
}

func appendToImageMap(imgMap map[string]bool, pod corev1.PodSpec) map[string]bool {
	for _, container := range pod.InitContainers {
		if ReferenceRegexp.MatchString(container.Image) {
			imgMap[container.Image] = true
		}
	}
	for _, container := range pod.Containers {
		if ReferenceRegexp.MatchString(container.Image) {
			imgMap[container.Image] = true
		}
	}
	for _, container := range pod.EphemeralContainers {
		if ReferenceRegexp.MatchString(container.Image) {
			imgMap[container.Image] = true
		}
	}
	return imgMap
}

func getSortedImages(matchedImages map[string]bool, maybeImages map[string]bool) ([]string, []string) {
	sortedMatchedImages := sort.StringSlice{}
	for image := range matchedImages {
		sortedMatchedImages = append(sortedMatchedImages, image)
	}
	sort.Sort(sortedMatchedImages)

	sortedMaybeImages := sort.StringSlice{}
	for image := range maybeImages {
		if matchedImages[image] {
			continue
		}
		sortedMaybeImages = append(sortedMaybeImages, image)
	}
	sort.Sort(sortedMaybeImages)

	return sortedMatchedImages, sortedMaybeImages
}
