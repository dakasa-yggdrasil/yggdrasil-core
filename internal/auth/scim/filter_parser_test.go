package scim

import (
	"errors"
	"testing"
)

func TestParseFilter_EmptyReturnsNil(t *testing.T) {
	f, err := ParseFilter("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if f != nil {
		t.Fatalf("expected nil filter, got %+v", f)
	}
}

func TestParseFilter_Simple(t *testing.T) {
	cases := []struct {
		in        string
		attribute string
		op        string
		value     string
	}{
		{`userName eq "alice@dakasa.me"`, "username", "eq", "alice@dakasa.me"},
		{`emails co dakasa.me`, "emails", "co", "dakasa.me"},
		{`displayName sw Alice`, "displayname", "sw", "Alice"},
		{`active eq "true"`, "active", "eq", "true"},
	}
	for _, tc := range cases {
		f, err := ParseFilter(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if f.Attribute != tc.attribute || f.Operator != tc.op || f.Value != tc.value {
			t.Fatalf("%q: got %+v", tc.in, f)
		}
	}
}

func TestParseFilter_Presence(t *testing.T) {
	f, err := ParseFilter("emails pr")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if f.Attribute != "emails" || f.Operator != "pr" || f.Value != "" {
		t.Fatalf("got %+v", f)
	}
}

func TestParseFilter_AND(t *testing.T) {
	f, err := ParseFilter(`userName eq "alice" and active eq "true"`)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if f.Attribute != "username" || f.Value != "alice" {
		t.Fatalf("left wrong: %+v", f)
	}
	if f.And == nil || f.And.Attribute != "active" || f.And.Value != "true" {
		t.Fatalf("right wrong: %+v", f.And)
	}
}

func TestParseFilter_RejectsUnsupported(t *testing.T) {
	for _, in := range []string{
		`(userName eq "alice")`,
		`userName lt "alice"`,
		`emails[primary eq true].value eq "alice"`,
	} {
		if _, err := ParseFilter(in); !errors.Is(err, ErrUnsupportedFilter) {
			t.Fatalf("%q: expected ErrUnsupportedFilter, got %v", in, err)
		}
	}
}
