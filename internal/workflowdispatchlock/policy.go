// Package workflowdispatchlock implements the process wide emergency workflow
// dispatch policy. It is deliberately independent from HTTP authentication so
// in-process callers and queue consumers enforce the same policy.
package workflowdispatchlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const EnvName = "YGGDRASIL_WORKFLOW_DISPATCH_LOCK_JSON"

const (
	modeOff     = "off"
	modeEnforce = "enforce"
)

// ErrLocked identifies an intentional workflow dispatch refusal. Callers may
// map it to a stable transport error without parsing the diagnostic string.
var ErrLocked = errors.New("workflow dispatch locked")

// WorkflowRef is one exact workflow catalog key. Wildcards are never valid.
type WorkflowRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type config struct {
	Mode             string        `json:"mode"`
	AllowedWorkflows []WorkflowRef `json:"allowed_workflows"`
}

// Policy is the parsed dispatch policy. Its zero value is off so existing
// library callers remain compatible when the environment variable is unset.
type Policy struct {
	mode    string
	allowed map[WorkflowRef]struct{}
}

// Parse converts one environment value into an immutable policy. A missing
// variable preserves the historical open posture. A present value is strict:
// blank JSON, unknown fields, trailing data, wildcards, duplicates, and an
// empty enforce allowlist are refused.
func Parse(raw string, present bool) (Policy, error) {
	if !present {
		return Policy{mode: modeOff}, nil
	}
	if strings.TrimSpace(raw) == "" {
		return Policy{}, fmt.Errorf("%s is set but blank", EnvName)
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return Policy{}, fmt.Errorf("parse %s: %w", EnvName, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("unexpected trailing JSON value")
		}
		return Policy{}, fmt.Errorf("parse %s: %w", EnvName, err)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case modeOff:
		if len(cfg.AllowedWorkflows) != 0 {
			return Policy{}, fmt.Errorf("%s mode off requires an empty allowed_workflows list", EnvName)
		}
		return Policy{mode: modeOff}, nil
	case modeEnforce:
		if len(cfg.AllowedWorkflows) == 0 {
			return Policy{}, fmt.Errorf("%s mode enforce requires at least one exact allowed_workflows item", EnvName)
		}
	default:
		return Policy{}, fmt.Errorf("%s mode must be off or enforce", EnvName)
	}

	allowed := make(map[WorkflowRef]struct{}, len(cfg.AllowedWorkflows))
	for index, rawRef := range cfg.AllowedWorkflows {
		ref := WorkflowRef{
			Namespace: strings.TrimSpace(rawRef.Namespace),
			Name:      strings.TrimSpace(rawRef.Name),
		}
		if ref.Namespace == "" || ref.Name == "" {
			return Policy{}, fmt.Errorf("%s allowed_workflows item %d requires namespace and name", EnvName, index)
		}
		if ref.Namespace != rawRef.Namespace || ref.Name != rawRef.Name {
			return Policy{}, fmt.Errorf("%s allowed_workflows item %d must not contain surrounding whitespace", EnvName, index)
		}
		if strings.ContainsAny(ref.Namespace, "*?[") || strings.ContainsAny(ref.Name, "*?[") {
			return Policy{}, fmt.Errorf("%s allowed_workflows item %d must be exact and cannot contain wildcards", EnvName, index)
		}
		if _, duplicate := allowed[ref]; duplicate {
			return Policy{}, fmt.Errorf("%s duplicates allowed_workflows item %d", EnvName, index)
		}
		allowed[ref] = struct{}{}
	}

	return Policy{mode: modeEnforce, allowed: allowed}, nil
}

// LoadFromEnvironment reads and parses the process environment. Kubernetes
// changes environment variables only by replacing the pod, so every process
// observes one stable value for its lifetime.
func LoadFromEnvironment() (Policy, error) {
	raw, present := os.LookupEnv(EnvName)
	return Parse(raw, present)
}

// Enforced reports whether this policy restricts workflow dispatch.
func (p Policy) Enforced() bool {
	return p.mode == modeEnforce
}

// Check permits only an exact namespace and name pair while enforcement is
// active. It never grants authentication, RBAC, policy, or input authority.
func (p Policy) Check(namespace, name string) error {
	if !p.Enforced() {
		return nil
	}
	ref := WorkflowRef{Namespace: namespace, Name: name}
	if _, ok := p.allowed[ref]; ok {
		return nil
	}
	return fmt.Errorf("%w: workflow %s/%s is not in the emergency allowlist", ErrLocked, ref.Namespace, ref.Name)
}

// CheckEnvironment applies the one canonical parser and checker. Invalid
// configured JSON denies dispatch in every environment.
func CheckEnvironment(namespace, name string) error {
	policy, err := LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("%w: emergency lock configuration is invalid", ErrLocked)
	}
	return policy.Check(namespace, name)
}

// CheckUnboundEnvironment refuses a dispatch surface that has no
// unforgeable link to a stored workflow manifest. Caller supplied metadata is
// not an authority for recovering that identity.
func CheckUnboundEnvironment() error {
	policy, err := LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("%w: emergency lock configuration is invalid", ErrLocked)
	}
	if policy.Enforced() {
		return fmt.Errorf("%w: unbound workflow dispatch is disabled", ErrLocked)
	}
	return nil
}

// CheckRepositoryBindingDispatchEnvironment refuses GitHub webhook dispatch
// through repository_binding manifests while the emergency lock is active.
// A repository binding selects a stored workflow but does not authenticate a
// caller or satisfy that workflow's authorization policy, so an allowlisted
// name cannot make this ingress trusted.
func CheckRepositoryBindingDispatchEnvironment() error {
	policy, err := LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("%w: emergency lock configuration is invalid", ErrLocked)
	}
	if policy.Enforced() {
		return fmt.Errorf("%w: repository-binding workflow dispatch is disabled", ErrLocked)
	}
	return nil
}

// CheckManifestMutationEnvironment refuses external manifest mutation while
// the emergency lock is active. Keeping the catalog fixed prevents an
// authorized writer from replacing an allowlisted workflow, its RBAC policy,
// or an integration instance and using the stable name as a trampoline.
func CheckManifestMutationEnvironment() error {
	policy, err := LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("%w: emergency lock configuration is invalid", ErrLocked)
	}
	if policy.Enforced() {
		return fmt.Errorf("%w: external manifest mutation is disabled", ErrLocked)
	}
	return nil
}

// CheckControlPlaneMutationEnvironment refuses direct provider, Kubernetes,
// and managed-secret mutation that does not carry an allowed stored workflow
// identity. It keeps emergency workflow execution as the only external
// mutation path during enforcement.
func CheckControlPlaneMutationEnvironment() error {
	policy, err := LoadFromEnvironment()
	if err != nil {
		return fmt.Errorf("%w: emergency lock configuration is invalid", ErrLocked)
	}
	if policy.Enforced() {
		return fmt.Errorf("%w: direct control-plane mutation is disabled", ErrLocked)
	}
	return nil
}
