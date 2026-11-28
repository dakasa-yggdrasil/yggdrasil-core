package capacity

import (
	"strings"
	"testing"
)

func TestNativeWorkerRPCRoleSeparatesPrincipalsAndExactCapabilities(t *testing.T) {
	valid := [][]string{
		{"ensure_native_worker"},
		{"destroy_native_worker"},
		{"ensure_native_worker", "destroy_native_worker"},
		{"destroy_native_worker", "ensure_native_worker"},
		{"observe_native_worker"},
		{"ensure_native_worker_pool"},
		{"observe_native_worker_pool"},
		{"observe_native_worker_phase"},
	}
	for _, capabilities := range valid {
		t.Run("allow/"+strings.Join(capabilities, "+"), func(t *testing.T) {
			allowed, ok := nativeWorkerRPCRole(capabilities)
			if !ok || len(allowed) != len(capabilities) {
				t.Fatal("legitimate narrowed role refused")
			}
			for _, capability := range capabilities {
				if !allowed[capability] {
					t.Fatal("exact declared capability lost")
				}
			}
			if allowed["unknown"] {
				t.Fatal("role invented authority")
			}
		})
	}
	all := []string{"ensure_native_worker", "destroy_native_worker", "observe_native_worker", "ensure_native_worker_pool", "observe_native_worker_pool", "observe_native_worker_phase"}
	for _, a := range all {
		for _, b := range all {
			if a != b && ((a == "ensure_native_worker" && b == "destroy_native_worker") || (a == "destroy_native_worker" && b == "ensure_native_worker")) {
				continue
			}
			t.Run("refuse_pair/"+a+"+"+b, func(t *testing.T) {
				allowed, ok := nativeWorkerRPCRole([]string{a, b})
				if ok || allowed != nil {
					t.Fatal("duplicate or cross-principal role acquired authority")
				}
			})
		}
	}
	for _, capability := range all {
		for _, bad := range []string{strings.ToUpper(capability), capability + " ", " " + capability, capability + "\n", "unknown", ""} {
			t.Run("refuse_exact/"+capability+"/"+bad, func(t *testing.T) {
				if allowed, ok := nativeWorkerRPCRole([]string{bad}); ok || allowed != nil {
					t.Fatal("case/alias/unknown capability accepted")
				}
			})
		}
	}
	for _, invalid := range [][]string{nil, {}, {"ensure_native_worker", "destroy_native_worker", "observe_native_worker"}, {"ensure_native_worker", "destroy_native_worker", "ensure_native_worker"}, {"unknown", "ensure_native_worker"}} {
		if allowed, ok := nativeWorkerRPCRole(invalid); ok || allowed != nil {
			t.Fatal("empty, oversized or partially accepted role acquired authority")
		}
	}
}
