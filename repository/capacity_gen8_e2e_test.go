package repository

// LAB-only seed service for the separate real HTTP-handler integration test.
// Every history and native observation is declared synthetic. This file is
// test-only and cannot provide production or provider authority.
import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestLABGen8SeedAndReadonlyObserver(t *testing.T) {
	dir := os.Getenv("LAB_GEN8_FIXTURE_DIR")
	if dir == "" {
		t.Skip("explicit disposable LAB fixture only")
	}
	db := originalDispositionPG(t) // verifies Unix socket, DB name and schema82
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture directory required")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private fixture directory required", err)
	}
	base, err := url.Parse(os.Getenv("LAB_GEN8_CREATOR_URL"))
	if err != nil || base.Scheme != "http" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" {
		t.Fatal("creator must be isolated loopback")
	}
	typRaw, err := os.ReadFile("testdata/capacity_aws_denied_source_expected_1655_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	typeID := uuid.New()
	typeChecksum := strings.Repeat("5", 64)
	instanceChecksum := strings.Repeat("6", 64)
	labGen8FixtureSetup = func(f *dispositionPGFixture) {
		f.record.Binding.IntegrationTypeID = typeID.String()
		f.record.Binding.IntegrationTypeChecksum = typeChecksum
		f.record.Binding.IntegrationChecksum = instanceChecksum
		ns := f.policy.Metadata.Namespace
		instance := model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typeID.String()}, Status: "active", Config: map[string]any{"base_url": base.String(), "original_capacity": map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": enrolledFailedAWSCreator}}}
		raw, e := json.Marshal(instance)
		if e != nil {
			t.Fatal(e)
		}
		for _, row := range []struct{ id, kind, name, checksum, spec string }{{typeID.String(), "integration_type", "lab-type", typeChecksum, string(typRaw)}, {f.record.Binding.IntegrationInstanceID, "integration_instance", "lab-instance", instanceChecksum, string(raw)}} {
			if _, e = db.Exec(`INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb,true)`, row.id, row.kind, ns, row.name, row.checksum, row.spec); e != nil {
				t.Fatal(e)
			}
		}
	}
	f := enrolledFailedAWSOriginalPGFixture(t, db, "", "")
	labGen8FixtureSetup = nil
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secret := uuid.NewString()
	mux := http.NewServeMux()
	done := make(chan struct{}, 1)
	mux.HandleFunc("/observation/"+secret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method", 405)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		owner, e := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
		if e != nil {
			http.Error(w, "fixture candidate", 500)
			return
		}
		o := witnessedUnenrolledAWSObservation(t, owner.Candidate())
		start := time.Now().UTC()
		o.ObservationStartedAt = start
		for i := range o.NativeReads {
			o.NativeReads[i].CalledAt = start.Add(time.Duration(i) * time.Millisecond)
			o.NativeReads[i].ReturnedAt = start.Add(time.Duration(i)*time.Millisecond + time.Microsecond)
		}
		o.ObservedAt = start.Add(time.Duration(len(o.NativeReads)+1) * time.Millisecond)
		for i := range o.AuxiliaryResources {
			o.AuxiliaryResources[i].ObservedAt = o.ObservedAt.Format(time.RFC3339Nano)
		}
		time.Sleep(time.Duration(len(o.NativeReads)+3) * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o)
	})
	mux.HandleFunc("/shutdown/"+secret, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		done <- struct{}{}
		w.WriteHeader(204)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	metadata := map[string]string{"grant": f.pre.OriginalCreateGrantID, "job": f.jobID.String(), "run": f.runID.String(), "pre": f.pre.PreregistrationID, "namespace": f.policy.Metadata.Namespace, "seed_url": "http://" + ln.Addr().String(), "seed_token": secret}
	raw, _ := json.Marshal(metadata)
	path := filepath.Join(dir, "seed.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Println("LAB_GEN8_SEEDED_NO_PROVIDER_AUTHORITY")
	select {
	case <-done:
	case <-time.After(120 * time.Second):
		t.Error("fixture timed out")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = srv.Shutdown(ctx); err != nil {
		t.Error(err)
	}
}
