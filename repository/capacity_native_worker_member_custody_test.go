package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeMemberSealDoesNotWaitForOriginalBorrowOrWipeReceivingKey(t *testing.T) {
	key := bytes.Repeat([]byte{41}, 32)
	st := &nativeMemberStoreState{key: append([]byte(nil), key...)}
	s := &CapacityNativeWorkerMemberStore{state: st}
	// An original callback can hold this read borrow while its DB operation is
	// blocked. Sealing must reach the finite join/cancel path without waiting.
	st.mu.RLock()
	held := true
	defer func() {
		if held {
			st.mu.RUnlock()
		}
	}()
	sealed := make(chan struct{})
	go func() { s.Seal(); close(sealed) }()
	select {
	case <-sealed:
	case <-time.After(time.Second):
		t.Fatal("Seal blocked behind an original callback before finite join")
	}
	if !st.sealed.Load() || !bytes.Equal(st.key, key) || st.closed {
		t.Fatal("admission seal wiped original receiving ownership")
	}
	borrow, e := s.acquire()
	if e != nil {
		t.Fatal("historical custody borrow closed before join", e)
	}
	borrow.mu.RUnlock()
	r := nativeMemberRecord{State: "issued", Context: model.CapacityNativeWorkerMemberContext{PlanID: uuid.NewString(), NotAfter: time.Now().Add(time.Minute)}, Facts: &capacity.NativeWorkerMemberFacts{}}
	if e = st.grantCurrentTx(context.Background(), nil, model.CapacityPolicySpec{}, model.CapacityNativeWorkerAttempt{}, r, time.Now()); e == nil {
		t.Fatal("sealed owner admitted a new grant")
	}
	st.mu.RUnlock()
	held = false
	if e = s.Close(); e != nil || len(st.key) != 0 {
		t.Fatal("joined close retained private key", e)
	}
}

func TestNativeMemberPrivateCustodyBindsContextPurposeAndFirstOriginal(t *testing.T) {
	st := &nativeMemberStoreState{key: bytes.Repeat([]byte{37}, 32)}
	c := model.CapacityNativeWorkerMemberContext{Schema: model.CapacityNativeWorkerMemberContextSchema, CoreSourceCommit: strings.Repeat("a", 40), PermitID: uuid.NewString(), PlanID: uuid.NewString(), AttemptID: uuid.NewString(), Action: "cordon", NotAfter: time.Now().UTC()}
	body := []byte(`{"fixture_private_secret":"not-public","exact":"original bytes"}`)
	wire, _ := json.Marshal(map[string]any{"original_return": body, "capture_complete": false, "error_class": "ORIGINAL_TRANSPORT_UNCERTAIN"})
	packed, e := nativeMemberPackOriginal(wire, body)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(packed)
	first, e := st.capture(c, "read/fixed-read-id", nil, packed)
	if e != nil || bytes.Contains(first.Ciphertext, body) || bytes.Contains(first.Ciphertext, []byte("not-public")) {
		t.Fatal("private original was not encrypted", e)
	}
	_, plain, e := st.crypt(c, "read/fixed-read-id", first, nil)
	defer clear(plain)
	var envelope nativeMemberPrivateOriginal
	if e != nil || nativeMemberDecode(plain, &envelope) != nil || !bytes.Equal(envelope.Wire, wire) || envelope.BodySHA256 != nativeMemberRawSHA(body) {
		t.Fatal("custody lost exact original bytes/digest", e)
	}
	if _, e = json.Marshal(envelope); e == nil || strings.Contains(fmt.Sprintf("%+v %#v", envelope, envelope), "not-public") {
		t.Fatal("private envelope escaped display boundary")
	}
	same, e := st.capture(c, "read/fixed-read-id", first, packed)
	if e != nil || same != first {
		t.Fatal("identical retry replaced randomized original ciphertext", e)
	}
	changed := append([]byte(nil), packed...)
	changed[len(changed)-2] ^= 1
	if _, e = st.capture(c, "read/fixed-read-id", first, changed); e == nil {
		t.Fatal("different duplicate original replaced first custody")
	}
	for _, fault := range []string{"Source", "permit", "plan", "attempt", "action", "expiry", "purpose", "key", "ciphertext"} {
		t.Run(fault, func(t *testing.T) {
			bad := c
			purpose := "read/fixed-read-id"
			own := &nativeMemberStoreState{key: append([]byte(nil), st.key...)}
			cipher := &nativeMemberCipher{Nonce: append([]byte(nil), first.Nonce...), Ciphertext: append([]byte(nil), first.Ciphertext...)}
			switch fault {
			case "Source":
				bad.CoreSourceCommit = strings.Repeat("b", 40)
			case "permit":
				bad.PermitID = uuid.NewString()
			case "plan":
				bad.PlanID = uuid.NewString()
			case "attempt":
				bad.AttemptID = uuid.NewString()
			case "action":
				bad.Action = "delete_node"
			case "expiry":
				bad.NotAfter = bad.NotAfter.Add(time.Second)
			case "purpose":
				purpose = "writer-original/token-hash"
			case "key":
				own.key[0] ^= 1
			case "ciphertext":
				cipher.Ciphertext[len(cipher.Ciphertext)-1] ^= 1
			}
			_, opened, e := own.crypt(bad, purpose, cipher, nil)
			clear(opened)
			clear(own.key)
			if e == nil {
				t.Fatal("private original opened for substituted identity", fault)
			}
		})
	}
	clear(st.key)
	if _, _, e = st.crypt(c, "read/fixed-read-id", first, nil); e == nil {
		t.Fatal("wiped owner key still opened custody")
	}
}

func TestNativeMemberPrivateArchiveBoundDoesNotExpandPublicDecoder(t *testing.T) {
	// A nested encrypted original may legitimately exceed a public RPC limit;
	// only the separately bounded private journal decoder accepts this record.
	value := struct {
		Payload string `json:"payload"`
	}{Payload: strings.Repeat("x", (2<<20)+100)}
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var decoded struct {
		Payload string `json:"payload"`
	}
	if nativeMemberDecode(raw, &decoded) != nil || decoded.Payload != value.Payload {
		t.Fatal("valid bounded private archive refused")
	}
	if capacity.DecodeNativeProbeResourceJSON(raw, &decoded) == nil {
		t.Fatal("private archive size expanded public transport decoder")
	}
	for _, invalid := range [][]byte{[]byte(`{"Payload":"alias"}`), []byte(`{"payload":"a","payload":"b"}`), []byte(`{"payload":"a"}{}`), []byte(`{"payload":"a","unknown":true}`)} {
		if nativeMemberDecode(invalid, &decoded) == nil {
			t.Fatal("private archive lost canonical framing")
		}
	}
	oversize, _ := json.Marshal(struct {
		Payload string `json:"payload"`
	}{Payload: strings.Repeat("x", 8<<20)})
	if nativeMemberDecode(oversize, &decoded) == nil {
		t.Fatal("private archive bound ignored")
	}
}
