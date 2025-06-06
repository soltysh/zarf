// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2021-Present The Zarf Authors

// Package pkgcfg loads and applies schema migrations to zarf.yaml files.
package pkgcfg

import (
	"context"
	"fmt"
	"math"
	"slices"

	goyaml "github.com/goccy/go-yaml"
	"github.com/zarf-dev/zarf/src/api/v1alpha1"
	"github.com/zarf-dev/zarf/src/pkg/logger"
)

// Parse parses the yaml passed as a byte slice and applies schema migrations.
func Parse(ctx context.Context, b []byte) (v1alpha1.ZarfPackage, error) {
	var pkg v1alpha1.ZarfPackage
	err := goyaml.Unmarshal(b, &pkg)
	if err != nil {
		return v1alpha1.ZarfPackage{}, err
	}
	pkg, warnings := migrateDeprecated(pkg)
	for _, warning := range warnings {
		logger.From(ctx).Warn(warning)
	}
	return pkg, nil
}

// List of migrations tracked in the zarf.yaml build data.
const (
	// This should be updated when a breaking change is introduced to the Zarf package structure.  See: https://github.com/zarf-dev/zarf/releases/tag/v0.27.0
	LastNonBreakingVersion   = "v0.27.0"
	ScriptsToActionsMigrated = "scripts-to-actions"
	PluralizeSetVariable     = "pluralize-set-variable"
)

func migrateDeprecated(pkg v1alpha1.ZarfPackage) (v1alpha1.ZarfPackage, []string) {
	warnings := []string{}

	migratedComponents := []v1alpha1.ZarfComponent{}
	for _, comp := range pkg.Components {
		if slices.Contains(pkg.Build.Migrations, ScriptsToActionsMigrated) {
			comp.DeprecatedScripts = v1alpha1.DeprecatedZarfComponentScripts{}
		} else {
			var warning string
			if comp, warning = migrateScriptsToActions(comp); warning != "" {
				warnings = append(warnings, warning)
			}
		}

		if slices.Contains(pkg.Build.Migrations, PluralizeSetVariable) {
			comp = clearSetVariables(comp)
		} else {
			var warning string
			if comp, warning = migrateSetVariableToSetVariables(comp); warning != "" {
				warnings = append(warnings, warning)
			}
		}

		// Show a warning if the component contains a group as that has been deprecated and will be removed.
		if comp.DeprecatedGroup != "" {
			warnings = append(warnings, fmt.Sprintf("Component %s is using group which has been deprecated and will be removed in v1.0.0.  Please migrate to another solution.", comp.Name))
		}

		migratedComponents = append(migratedComponents, comp)
	}
	pkg.Components = migratedComponents

	// Record the migrations that have been run on the package.
	pkg.Build.Migrations = []string{
		ScriptsToActionsMigrated,
		PluralizeSetVariable,
	}

	// Record the latest version of Zarf without breaking changes to the package structure.
	pkg.Build.LastNonBreakingVersion = LastNonBreakingVersion

	return pkg, warnings
}

// migrateScriptsToActions coverts the deprecated scripts to the new actions
// The following have no migration:
// - Actions.Create.After
// - Actions.Remove.*
// - Actions.*.OnSuccess
// - Actions.*.OnFailure
// - Actions.*.*.Env
func migrateScriptsToActions(c v1alpha1.ZarfComponent) (v1alpha1.ZarfComponent, string) {
	var hasScripts bool

	// Convert a script configs to action defaults.
	defaults := v1alpha1.ZarfComponentActionDefaults{
		// ShowOutput (default false) -> Mute (default false)
		Mute: !c.DeprecatedScripts.ShowOutput,
		// TimeoutSeconds -> MaxSeconds
		MaxTotalSeconds: c.DeprecatedScripts.TimeoutSeconds,
	}

	// Retry is now an integer vs a boolean (implicit infinite retries), so set to an absurdly high number
	if c.DeprecatedScripts.Retry {
		defaults.MaxRetries = math.MaxInt
	}

	// Scripts.Prepare -> Actions.Create.Before
	if len(c.DeprecatedScripts.Prepare) > 0 {
		hasScripts = true
		c.Actions.OnCreate.Defaults = defaults
		for _, s := range c.DeprecatedScripts.Prepare {
			c.Actions.OnCreate.Before = append(c.Actions.OnCreate.Before, v1alpha1.ZarfComponentAction{Cmd: s})
		}
	}

	// Scripts.Before -> Actions.Deploy.Before
	if len(c.DeprecatedScripts.Before) > 0 {
		hasScripts = true
		c.Actions.OnDeploy.Defaults = defaults
		for _, s := range c.DeprecatedScripts.Before {
			c.Actions.OnDeploy.Before = append(c.Actions.OnDeploy.Before, v1alpha1.ZarfComponentAction{Cmd: s})
		}
	}

	// Scripts.After -> Actions.Deploy.After
	if len(c.DeprecatedScripts.After) > 0 {
		hasScripts = true
		c.Actions.OnDeploy.Defaults = defaults
		for _, s := range c.DeprecatedScripts.After {
			c.Actions.OnDeploy.After = append(c.Actions.OnDeploy.After, v1alpha1.ZarfComponentAction{Cmd: s})
		}
	}

	// Leave deprecated scripts in place, but warn users
	if hasScripts {
		return c, fmt.Sprintf("Component '%s' is using scripts which will be removed in Zarf v1.0.0. Please migrate to actions.", c.Name)
	}

	return c, ""
}

func migrateSetVariableToSetVariables(c v1alpha1.ZarfComponent) (v1alpha1.ZarfComponent, string) {
	hasSetVariable := false

	migrate := func(actions []v1alpha1.ZarfComponentAction) []v1alpha1.ZarfComponentAction {
		for i := range actions {
			if actions[i].DeprecatedSetVariable != "" && len(actions[i].SetVariables) < 1 {
				hasSetVariable = true
				actions[i].SetVariables = []v1alpha1.Variable{
					{
						Name:      actions[i].DeprecatedSetVariable,
						Sensitive: false,
					},
				}
			}
		}

		return actions
	}

	// Migrate OnCreate SetVariables
	c.Actions.OnCreate.After = migrate(c.Actions.OnCreate.After)
	c.Actions.OnCreate.Before = migrate(c.Actions.OnCreate.Before)
	c.Actions.OnCreate.OnSuccess = migrate(c.Actions.OnCreate.OnSuccess)
	c.Actions.OnCreate.OnFailure = migrate(c.Actions.OnCreate.OnFailure)

	// Migrate OnDeploy SetVariables
	c.Actions.OnDeploy.After = migrate(c.Actions.OnDeploy.After)
	c.Actions.OnDeploy.Before = migrate(c.Actions.OnDeploy.Before)
	c.Actions.OnDeploy.OnSuccess = migrate(c.Actions.OnDeploy.OnSuccess)
	c.Actions.OnDeploy.OnFailure = migrate(c.Actions.OnDeploy.OnFailure)

	// Migrate OnRemove SetVariables
	c.Actions.OnRemove.After = migrate(c.Actions.OnRemove.After)
	c.Actions.OnRemove.Before = migrate(c.Actions.OnRemove.Before)
	c.Actions.OnRemove.OnSuccess = migrate(c.Actions.OnRemove.OnSuccess)
	c.Actions.OnRemove.OnFailure = migrate(c.Actions.OnRemove.OnFailure)

	// Leave deprecated setVariable in place, but warn users
	if hasSetVariable {
		return c, fmt.Sprintf("Component '%s' is using setVariable in actions which will be removed in Zarf v1.0.0. Please migrate to the list form of setVariables.", c.Name)
	}

	return c, ""
}

func clearSetVariables(c v1alpha1.ZarfComponent) v1alpha1.ZarfComponent {
	clearVar := func(actions []v1alpha1.ZarfComponentAction) []v1alpha1.ZarfComponentAction {
		for i := range actions {
			actions[i].DeprecatedSetVariable = ""
		}

		return actions
	}

	// Clear OnCreate SetVariables
	c.Actions.OnCreate.After = clearVar(c.Actions.OnCreate.After)
	c.Actions.OnCreate.Before = clearVar(c.Actions.OnCreate.Before)
	c.Actions.OnCreate.OnSuccess = clearVar(c.Actions.OnCreate.OnSuccess)
	c.Actions.OnCreate.OnFailure = clearVar(c.Actions.OnCreate.OnFailure)

	// Clear OnDeploy SetVariables
	c.Actions.OnDeploy.After = clearVar(c.Actions.OnDeploy.After)
	c.Actions.OnDeploy.Before = clearVar(c.Actions.OnDeploy.Before)
	c.Actions.OnDeploy.OnSuccess = clearVar(c.Actions.OnDeploy.OnSuccess)
	c.Actions.OnDeploy.OnFailure = clearVar(c.Actions.OnDeploy.OnFailure)

	// Clear OnRemove SetVariables
	c.Actions.OnRemove.After = clearVar(c.Actions.OnRemove.After)
	c.Actions.OnRemove.Before = clearVar(c.Actions.OnRemove.Before)
	c.Actions.OnRemove.OnSuccess = clearVar(c.Actions.OnRemove.OnSuccess)
	c.Actions.OnRemove.OnFailure = clearVar(c.Actions.OnRemove.OnFailure)

	return c
}
