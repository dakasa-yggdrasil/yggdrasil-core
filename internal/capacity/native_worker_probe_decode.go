package capacity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
)

var errNativeProbeResourceTemplate = errors.New("protected Native probe resource unavailable")

// Unlike the legacy pool codec, raw native objects legitimately use camelCase
// and map keys such as config.json. Preserve those keys while rejecting duplicate
// framing and case/Unicode aliases of every typed protocol field recursively.
func DecodeNativeProbeResourceJSON(raw []byte, out any) error {
	return decodeNativeProbeResourceJSONBound(raw, out, 2<<20)
}

// Readiness custody has at most thirteen fixed effects, each independently
// bounded before encryption. Nested base64 of private originals legitimately
// exceeds a single RPC body's limit. This fixed Go-only archive codec does not
// enlarge any provider, callback, SDK or workflow input boundary.
func DecodeNativeReadinessJournalJSON(raw []byte, out any) error {
	return decodeNativeProbeResourceJSONBound(raw, out, 48<<20)
}

func decodeNativeProbeResourceJSONBound(raw []byte, out any, limit int) error {
	t := reflect.TypeOf(out)
	if len(raw) == 0 || len(raw) > limit || t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return errNativeProbeResourceTemplate
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 48 {
			return errNativeProbeResourceTemplate
		}
		token, err := d.Token()
		if err != nil {
			return errNativeProbeResourceTemplate
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errNativeProbeResourceTemplate
					}
					seen[name] = true
					if err = walk(depth + 1); err != nil {
						return err
					}
				}
				if close, err := d.Token(); err != nil || close != json.Delim('}') {
					return errNativeProbeResourceTemplate
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				if close, err := d.Token(); err != nil || close != json.Delim(']') {
					return errNativeProbeResourceTemplate
				}
			default:
				return errNativeProbeResourceTemplate
			}
		}
		return nil
	}
	if walk(0) != nil {
		return errNativeProbeResourceTemplate
	}
	if _, err := d.Token(); err != io.EOF {
		return errNativeProbeResourceTemplate
	}
	if nativeProbeClosedFields(raw, t.Elem()) != nil {
		return errNativeProbeResourceTemplate
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return errNativeProbeResourceTemplate
	}
	return nil
}

func nativeProbeClosedFields(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		t = t.Elem()
	}
	if t == reflect.TypeOf(json.RawMessage{}) || t == reflect.TypeOf(time.Time{}) {
		return nil
	}
	if reflect.PointerTo(t).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			return errNativeProbeResourceTemplate
		}
		fields := map[string]reflect.Type{}
		var collect func(reflect.Type)
		collect = func(st reflect.Type) {
			for i := 0; i < st.NumField(); i++ {
				f := st.Field(i)
				if !f.IsExported() {
					continue
				}
				tag := strings.Split(f.Tag.Get("json"), ",")[0]
				if tag == "-" {
					continue
				}
				if f.Anonymous && tag == "" {
					ft := f.Type
					for ft.Kind() == reflect.Pointer {
						ft = ft.Elem()
					}
					if ft.Kind() == reflect.Struct {
						collect(ft)
						continue
					}
				}
				if tag == "" {
					tag = f.Name
				}
				fields[tag] = f.Type
			}
		}
		collect(t)
		for name, value := range members {
			ft, ok := fields[name]
			if !ok || nativeProbeClosedFields(value, ft) != nil {
				return errNativeProbeResourceTemplate
			}
		}
	case reflect.Map:
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return errNativeProbeResourceTemplate
		}
		for _, v := range members {
			if nativeProbeClosedFields(v, t.Elem()) != nil {
				return errNativeProbeResourceTemplate
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		var members []json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return errNativeProbeResourceTemplate
		}
		for _, v := range members {
			if nativeProbeClosedFields(v, t.Elem()) != nil {
				return errNativeProbeResourceTemplate
			}
		}
	}
	return nil
}
