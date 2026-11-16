// Package coreprocess defines the immutable startup boundary between the
// protected control authority and ordinary HTTP workflow workers. No request,
// workflow metadata or callback can choose a different process role.
package coreprocess

import (
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"
)

type Role string

const (
	RoleEnv                       = "YGGDRASIL_CORE_PROCESS_ROLE"
	APIWorkerExecutable           = "/app/yggdrasil-api-worker"
	Authority                Role = "authority"
	APIWorker                Role = "api_worker"
	OriginalWorkflowMaximum       = 30 * time.Minute
	DependencyShutdownBudget      = 10 * time.Second
)

func FromEnvironment() (Role, error) {
	return ParseRole(os.Getenv(RoleEnv))
}

// The deployment must select a path absent from predecessor images. An old
// executable silently ignoring the role environment cannot become a worker.
// The new image uses one ELF through this dedicated symlink, not a second build.
func ValidateExecutable(role Role, argv0 string) error {
	if (role == APIWorker && argv0 != APIWorkerExecutable) || (argv0 == APIWorkerExecutable && role != APIWorker) {
		return errors.New("Core worker executable and process role disagree")
	}
	return nil
}

func ParseRole(value string) (Role, error) {
	switch value {
	case "", string(Authority):
		return Authority, nil
	case string(APIWorker):
		return APIWorker, nil
	default:
		return "", errors.New("invalid Core process role")
	}
}

// AllowedAddon is a closed allowlist, not a blacklist of known mutation loops.
// RabbitMQ and HTTP additionally omit their nested authority-only work.
func AllowedAddon(role Role, name string) bool {
	if role == Authority {
		return true
	}
	if role != APIWorker {
		return false
	}
	switch name {
	case "observability", "boot-validation", "postgres", "rabbitmq", "integration_surface_sync", "http":
		return true
	}
	return false
}

// Workers require the shared material rather than generating per-pod fallbacks.
// Equality to the authority's values is established by the deployment's exact
// shared Secret references, never by exposing or emitting their values here.
func ValidateWorkerEnvironment() error {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("YGGDRASIL_AUTH_KEK_BASE64"))
	brokerRaw := os.Getenv("BROKER_URL")
	broker, brokerErr := url.Parse(brokerRaw)
	validBroker := brokerErr == nil && brokerRaw == strings.TrimSpace(brokerRaw) && broker.Hostname() != "" && (broker.Scheme == "amqp" || broker.Scheme == "amqps") && broker.Fragment == ""
	if err != nil || len(key) != 32 || len(strings.TrimSpace(os.Getenv("AUTH_THIRD_PARTY_STATE_SECRET"))) < 32 || len(strings.TrimSpace(os.Getenv("YGGDRASIL_CSRF_HMAC_SECRET"))) < 32 || !validBroker || os.Getenv("NATIVE_ADMISSION_ENABLED") != "true" {
		return errors.New("API worker shared configuration or native admission unavailable")
	}
	return nil
}

func ShutdownBudget(role Role) time.Duration {
	if role == APIWorker {
		return OriginalWorkflowMaximum + DependencyShutdownBudget
	}
	return DependencyShutdownBudget
}
