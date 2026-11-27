package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNativeWorkerPrivateBootstrapHasOneExplicitPrivateSerializationPort(t *testing.T) {
	now := time.Now().UTC()
	command := CapacityNativeWorkerCommand{Schema: CapacityNativeWorkerCommandSchema, AttemptID: uuid.New(), BindingName: "ci-execution", AttemptState: "reserved", Redeemable: true, ExpiresAt: now.Add(time.Minute), SDKSourceCommit: strings.Repeat("a", 40), ExecutionScopeSHA256: strings.Repeat("b", 64)}
	launch := []byte(`{"schema":1,"reservation_id":"actual-stored-id"}`)
	cloud := []byte("#cloud-config\nprivate-ci-agent-material\n")
	p, err := NewCapacityNativeWorkerPrivateBootstrap(command, launch, cloud, now)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err = json.Marshal(p); err == nil {
		t.Fatal("private bootstrap entered ordinary JSON")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", p, p), "private-ci-agent") {
		t.Fatal("private bootstrap entered ordinary formatting")
	}
	var out bytes.Buffer
	if err = p.WritePrivateJSON(&out); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Schema    string          `json:"schema"`
		AttemptID uuid.UUID       `json:"attempt_id"`
		Launch    json.RawMessage `json:"public_launch_json"`
		Body      []byte          `json:"cloud_init_base64"`
		LaunchSHA string          `json:"launch_sha256"`
		BodySHA   string          `json:"cloud_init_sha256"`
		BodyBytes int             `json:"cloud_init_bytes"`
	}
	if json.Unmarshal(out.Bytes(), &wire) != nil || wire.Schema != "native_worker_private_bootstrap_v1" || wire.AttemptID != command.AttemptID || !bytes.Equal(wire.Launch, launch) || !bytes.Equal(wire.Body, cloud) || wire.BodyBytes != len(cloud) || wire.BodySHA != fmt.Sprintf("%x", sha256.Sum256(cloud)) || wire.LaunchSHA != fmt.Sprintf("%x", sha256.Sum256(launch)) {
		t.Fatal("private wire lost exact source operands")
	}
	if err = p.WritePrivateJSON(nativeBootstrapShortWriter{}); err != io.ErrShortWrite {
		t.Fatal("partial private write reported success")
	}
	p.Close()
	if err = p.WritePrivateJSON(&out); err == nil {
		t.Fatal("closed private response reused")
	}
	for _, mode := range []string{"consumed", "expired", "no-read-authority", "mutation", "empty", "oversized", "wrong-prefix", "bad-launch"} {
		t.Run(mode, func(t *testing.T) {
			c, l, b := command, launch, cloud
			switch mode {
			case "consumed":
				c.AttemptState = "send_started"
			case "expired":
				c.ExpiresAt = now
			case "no-read-authority":
				c.Redeemable = false
			case "mutation":
				c.MutationPermitted = true
			case "empty":
				b = nil
			case "oversized":
				b = append([]byte("#cloud-config\n"), bytes.Repeat([]byte("x"), 16384)...)
			case "wrong-prefix":
				b = []byte("caller-script")
			case "bad-launch":
				l = []byte("invalid")
			}
			got, e := NewCapacityNativeWorkerPrivateBootstrap(c, l, b, now)
			defer got.Close()
			if e == nil {
				t.Fatal("invalid private serialization authority accepted")
			}
		})
	}
}

type nativeBootstrapShortWriter struct{}

func (nativeBootstrapShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
