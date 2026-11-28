package model

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestNativeMemberPermitIsOpaqueAndUsesCanonicalPrivateToken(t *testing.T) {
	context := CapacityNativeWorkerMemberContext{Schema: CapacityNativeWorkerMemberContextSchema, PermitID: "d18736e5-d804-4350-9afe-93bce5dd8ef1", Node: &CapacityNativeWorkerMemberNode{Name: "nw-test", UID: "7b20ad61-859a-4eb6-a130-9fbafdc28e4b"}}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))
	permit, e := NewCapacityNativeWorkerMemberPermit(context, token)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []any{permit, &permit} {
		if strings.Contains(fmt.Sprintf("%v|%+v|%#v", v, v, v), token) {
			t.Fatal("ordinary formatting exposed private token")
		}
		if raw, e := json.Marshal(v); e == nil || bytes.Contains(raw, []byte(token)) {
			t.Fatal("ordinary JSON exposed private permit")
		}
	}
	if e = permit.WritePrivateJSON(nil); e == nil {
		t.Fatal("nil private writer accepted")
	}
	var wire bytes.Buffer
	if e = permit.WritePrivateJSON(&wire); e != nil || !bytes.Contains(wire.Bytes(), []byte(token)) {
		t.Fatal("explicit private writer lost canonical token", e)
	}
	var out struct {
		Schema            string `json:"schema"`
		State             string `json:"state"`
		MutationPermitted bool   `json:"mutation_permitted"`
		SettlementToken   string `json:"settlement_token"`
	}
	if json.Unmarshal(wire.Bytes(), &out) != nil || out.Schema != CapacityNativeWorkerMemberPermitSchema || out.State != "redeemed" || !out.MutationPermitted || out.SettlementToken != token {
		t.Fatal("private permit framing differs")
	}
	original, e := permit.PublicContext()
	if e != nil {
		t.Fatal(e)
	}
	context.Node.Name = "mutated-input"
	original.Node.Name = "mutated-copy"
	copy, e := permit.PublicContext()
	if e != nil || copy.Node.Name != "nw-test" {
		t.Fatal("context aliases changed private permit")
	}
	for _, bad := range []string{"", strings.Repeat("!", 43), strings.Repeat("a", 43) + "=", strings.Repeat("a", 42), strings.Repeat("a", 42) + "B", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))} {
		if _, e = NewCapacityNativeWorkerMemberPermit(copy, bad); e == nil {
			t.Fatal("noncanonical private token accepted")
		}
	}
	var zero CapacityNativeWorkerMemberPermit
	if zero.WritePrivateJSON(&wire) == nil {
		t.Fatal("zero private handle serialized")
	}
	if _, e = zero.PublicContext(); e == nil {
		t.Fatal("zero context exposed")
	}
}
