package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func ParseCapacityPolicySpec(raw json.RawMessage) (model.CapacityPolicySpec, error) {
	var spec model.CapacityPolicySpec
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return spec, fmt.Errorf("parse capacity policy: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return spec, fmt.Errorf("capacity policy must contain one JSON object")
	}
	return spec, nil
}

func ValidateCapacityPolicySpec(spec model.CapacityPolicySpec) error {
	return capacity.ValidatePolicy(spec)
}
