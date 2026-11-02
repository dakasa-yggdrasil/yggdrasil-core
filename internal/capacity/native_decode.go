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
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return fmt.Errorf("native capacity output requires nonnil pointer")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 2<<20 {
		return fmt.Errorf("native capacity input exceeds bound")
	}
	// RawMessage and byte slices have their original Go JSON encodings, not
	// the array encoding of ordinary slices. Check duplicate members even in
	// raw subtrees before typed fields and their owning validators are decoded.
	if err := nativeCapacityUniqueJSON(raw); err != nil {
		return err
	}
	if err := nativeCapacityClosedJSON(raw, typ.Elem()); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
func nativeCapacityClosedJSON(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			// Optional native facts stay absent. Completion and permission
			// validators independently require the relevant facts to exist.
			return nil
		}
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		// The original JSON value remains raw. Its owning typed decoder still
		// checks its schema; this is not an object/permission certificate.
		return nil
	}
	if typ.Kind() == reflect.Slice {
		if typ.Elem().Kind() == reflect.Uint8 {
			var value []byte
			if json.Unmarshal(raw, &value) != nil {
				return fmt.Errorf("native byte input requires original base64 encoding")
			}
			canonical, err := json.Marshal(value)
			if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
				return fmt.Errorf("native byte input requires original base64 encoding")
			}
			return nil
		}
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

// UseNumber preserves original numeric values without float conversion. Raw
// keys may be application data; only exact duplicates are rejected here.
// Literal typed field names are checked separately by NativeCanonicalObject.
func nativeCapacityUniqueJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("incomplete native JSON value")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, err := decoder.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return fmt.Errorf("duplicate or incomplete native JSON member")
					}
					seen[name] = true
					if err := walk(); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return fmt.Errorf("incomplete native JSON object")
				}
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return fmt.Errorf("incomplete native JSON array")
				}
			default:
				return fmt.Errorf("unexpected native JSON delimiter")
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing native JSON value")
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
