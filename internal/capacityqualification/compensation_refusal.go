//go:build nativequalification

package capacityqualification

// IsCompensationPlanNotEnabledDestroy recognizes the planner refusal when
// the binding is disabled OR the plan is not destroy. Callers must separately
// establish which precondition caused it. Disabled policy/process is distinct.
func IsCompensationPlanNotEnabledDestroy(err error) bool {
	return err != nil && err.Error() == "capacity compensation requires an explicitly enabled destroy binding"
}
