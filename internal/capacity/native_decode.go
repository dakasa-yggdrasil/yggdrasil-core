package capacity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// All new native inputs use literal canonical JSON member names. Go's
// case-insensitive tagged-field matching is not authority normalization.
func DecodeNativeCapacity(value any, out any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2<<20 {
		return fmt.Errorf("native capacity input exceeds bound")
	}
	if err := nativeCapacityClosedJSON(raw, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func nativeCapacityClosedJSON(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Slice {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return fmt.Errorf("native input requires array")
		}
		for _, value := range values {
			if err := nativeCapacityClosedJSON(value, typ.Elem()); err != nil {
				return err
			}
		}
		return nil
	}
	if typ.Kind() != reflect.Struct || typ.PkgPath() == "time" {
		return nil
	}
	fields := map[string]reflect.Type{}
	var collect func(reflect.Type)
	collect = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if f.Anonymous && tag == "" {
				collect(f.Type)
				continue
			}
			if tag != "" {
				fields[tag] = f.Type
			}
		}
	}
	collect(typ)
	allowed := map[string]bool{}
	for name := range fields {
		allowed[name] = true
	}
	members, err := NativeCanonicalObject(raw, allowed)
	if err != nil {
		return err
	}
	for name, value := range members {
		if err := nativeCapacityClosedJSON(value, fields[name]); err != nil {
			return err
		}
	}
	return nil
}

func NativeCanonicalObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, fmt.Errorf("closed native object required")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || fields[name] != nil {
			return nil, fmt.Errorf("noncanonical or duplicate native field")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, fmt.Errorf("incomplete native field")
		}
		fields[name] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("incomplete or trailing native object")
	}
	return fields, nil
}
