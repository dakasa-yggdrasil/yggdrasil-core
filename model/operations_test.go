package model

import "testing"

func TestOperationOnSurfaceQuery_StableValue(t *testing.T) {
	if OperationOnSurfaceQuery != "on_surface_query" {
		t.Errorf("constant value = %q", OperationOnSurfaceQuery)
	}
}
