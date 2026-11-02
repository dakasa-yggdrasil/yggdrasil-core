package reconciler

import (
	"context"
	"errors"

	"go.uber.org/zap"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// These fixed enums and names are the complete diagnostic vocabulary. Never
// add error messages, resource identifiers, API responses, or secret metadata.
type reconcileStage uint8

const (
	stageList reconcileStage = iota
	stageGet
	stageCreate
	stageUpdate
	stageApply
	stageCount
)

type reconcileErrorClass uint8

const (
	classForbidden reconcileErrorClass = iota
	classNotFound
	classInvalid
	classConflict
	classTimeout
	classUnavailable
	classOther
	classCount
)

var stageNames = [...]string{"list", "get", "create", "update", "apply"}
var classNames = [...]string{"forbidden", "not_found", "invalid", "conflict", "timeout", "unavailable", "other"}

type reconcileDiagnostics [stageCount][classCount]int

func (r *ReconcileResult) recordError(stage reconcileStage, err error) {
	r.Errors++
	r.diagnostics[stage][classifyReconcileError(err)]++
}

func classifyReconcileError(err error) reconcileErrorClass {
	switch {
	case k8serrors.IsForbidden(err), k8serrors.IsUnauthorized(err):
		return classForbidden
	case k8serrors.IsNotFound(err):
		return classNotFound
	case k8serrors.IsInvalid(err), k8serrors.IsBadRequest(err):
		return classInvalid
	case k8serrors.IsConflict(err), k8serrors.IsAlreadyExists(err):
		return classConflict
	case errors.Is(err, context.DeadlineExceeded), k8serrors.IsTimeout(err), k8serrors.IsServerTimeout(err):
		return classTimeout
	case k8serrors.IsServiceUnavailable(err), k8serrors.IsTooManyRequests(err):
		return classUnavailable
	default:
		return classOther
	}
}

func (d reconcileDiagnostics) fields() []zap.Field {
	var fields []zap.Field
	for stage, counts := range d {
		for class, count := range counts {
			if count != 0 {
				fields = append(fields, zap.Int("error_"+stageNames[stage]+"_"+classNames[class], count))
			}
		}
	}
	return fields
}
