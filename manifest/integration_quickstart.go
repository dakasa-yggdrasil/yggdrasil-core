package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ParseIntegrationQuickstartSpec decodes the raw spec into the typed
// integration_quickstart manifest. Validation is performed separately so the
// caller can also use the parsed form for inspection (e.g. the CLI's `dry-run`
// path).
func ParseIntegrationQuickstartSpec(raw json.RawMessage) (model.IntegrationQuickstartManifestSpec, error) {
	var spec model.IntegrationQuickstartManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return model.IntegrationQuickstartManifestSpec{}, fmt.Errorf("parse integration_quickstart spec: %w", err)
	}
	return spec, nil
}

var (
	quickstartIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	quickstartInputPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// validInputTypes lists the QuickstartInput.Type values the engine knows how
// to render and validate. Empty defaults to "string".
var validInputTypes = map[string]struct{}{
	"string":  {},
	"integer": {},
	"boolean": {},
	"select":  {},
}

// validRequirementKinds enumerates accepted QuickstartRequirement.Kind values.
var validRequirementKinds = map[string]struct{}{
	"integration_family":  {},
	"integration_type":    {},
	"cluster_capability":  {},
}

// ValidateIntegrationQuickstartSpec walks the manifest and ensures every
// provider/input/step/smoke_test is internally consistent BEFORE the
// processor compiles it into a workflow. Errors here are surfaced to the
// adopter at install time with file-level context.
func ValidateIntegrationQuickstartSpec(spec model.IntegrationQuickstartManifestSpec) error {
	if len(spec.Providers) == 0 {
		return fmt.Errorf("integration_quickstart must declare at least one provider")
	}

	seenProvider := map[string]struct{}{}
	for i, p := range spec.Providers {
		ctx := fmt.Sprintf("providers[%d]", i)
		if p.ID == "" {
			return fmt.Errorf("%s: id is required", ctx)
		}
		if !quickstartIDPattern.MatchString(p.ID) {
			return fmt.Errorf("%s: id %q must match %s", ctx, p.ID, quickstartIDPattern.String())
		}
		if _, dup := seenProvider[p.ID]; dup {
			return fmt.Errorf("%s: provider id %q is duplicated", ctx, p.ID)
		}
		seenProvider[p.ID] = struct{}{}

		if err := validateRequirements(ctx+".requires", p.Requires); err != nil {
			return err
		}
		if err := validateInputs(ctx+".inputs", p.Inputs); err != nil {
			return err
		}
		if err := validateSteps(ctx+".steps", p.ID, p.Steps); err != nil {
			return err
		}
		if p.SmokeTest != nil {
			if len(p.SmokeTest.Uses) == 0 {
				return fmt.Errorf("%s.smoke_test: uses is required", ctx)
			}
		}
	}
	return nil
}

func validateRequirements(ctx string, reqs []model.QuickstartRequirement) error {
	for i, r := range reqs {
		c := fmt.Sprintf("%s[%d]", ctx, i)
		if _, ok := validRequirementKinds[r.Kind]; !ok {
			return fmt.Errorf("%s: kind %q must be one of integration_family|integration_type|cluster_capability", c, r.Kind)
		}
		switch r.Kind {
		case "integration_family", "integration_type":
			if r.Name == "" {
				return fmt.Errorf("%s: name is required for kind=%s", c, r.Kind)
			}
		case "cluster_capability":
			if r.Capability == "" {
				return fmt.Errorf("%s: capability is required for kind=cluster_capability", c)
			}
		}
	}
	return nil
}

func validateInputs(ctx string, inputs []model.QuickstartInput) error {
	seen := map[string]struct{}{}
	for i, in := range inputs {
		c := fmt.Sprintf("%s[%d]", ctx, i)
		if in.ID == "" {
			return fmt.Errorf("%s: id is required", c)
		}
		if !quickstartInputPattern.MatchString(in.ID) {
			return fmt.Errorf("%s: id %q must match %s", c, in.ID, quickstartInputPattern.String())
		}
		if _, dup := seen[in.ID]; dup {
			return fmt.Errorf("%s: input id %q is duplicated", c, in.ID)
		}
		seen[in.ID] = struct{}{}
		if in.Label == "" {
			return fmt.Errorf("%s: label is required", c)
		}
		typ := strings.ToLower(strings.TrimSpace(in.Type))
		if typ == "" {
			typ = "string"
		}
		if _, ok := validInputTypes[typ]; !ok {
			return fmt.Errorf("%s: type %q must be one of string|integer|boolean|select", c, in.Type)
		}
		if typ == "select" && len(in.Choices) == 0 {
			return fmt.Errorf("%s: type=select requires at least one choice", c)
		}
		if in.Validate != nil && in.Validate.Regex != "" {
			if _, err := regexp.Compile(in.Validate.Regex); err != nil {
				return fmt.Errorf("%s: validate.regex is invalid: %w", c, err)
			}
		}
	}
	return nil
}

func validateSteps(ctx, providerID string, steps []model.QuickstartStep) error {
	if len(steps) == 0 {
		return fmt.Errorf("%s: provider %q must declare at least one step", ctx, providerID)
	}
	seen := map[string]struct{}{}
	for i, s := range steps {
		c := fmt.Sprintf("%s[%d]", ctx, i)
		if s.ID == "" {
			return fmt.Errorf("%s: id is required", c)
		}
		if !quickstartIDPattern.MatchString(s.ID) {
			return fmt.Errorf("%s: id %q must match %s", c, s.ID, quickstartIDPattern.String())
		}
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("%s: step id %q is duplicated", c, s.ID)
		}
		seen[s.ID] = struct{}{}
		if len(s.Uses) == 0 {
			return fmt.Errorf("%s: uses is required", c)
		}
	}
	return nil
}
