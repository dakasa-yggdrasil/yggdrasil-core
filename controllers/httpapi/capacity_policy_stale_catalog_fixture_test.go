package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// declaredStaleCapacityPolicyVersion preserves coverage of obsolete catalog
// pins that the public publication guard now prevents. Only these isolated
// fixtures use the pre-guard writer shape; this is not a production writer.
func declaredStaleCapacityPolicyVersion(t *testing.T, f dispatchHTTPFixture, old repository.CapacityDispatchJob, spec model.CapacityPolicySpec) model.Manifest {
	t.Helper()
	ctx := t.Context()
	catalog := func() string {
		var raw string
		if err := f.db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb)::text FROM public.manifests m WHERE kind='capacity_policy' AND namespace=$1 AND name=$2`, f.policy.Metadata.Namespace, f.policy.Metadata.Name).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	original := func() string {
		var raw string
		if err := f.db.QueryRowContext(ctx, `SELECT jsonb_build_object('job',to_jsonb(j),'run',to_jsonb(w))::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1 AND j.run_id=$2 AND j.realm=$3 AND j.state IN ('queued','started','unknown')`, old.JobID, old.RunID, f.policy.Metadata.Namespace).Scan(&raw); err != nil {
			t.Fatal("declared stale catalog fixture requires its real busy original", err)
		}
		return raw
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256(raw))
	doc := model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name}, Spec: raw}
	beforeCatalog, beforeOriginal := catalog(), original()
	if _, err = repository.CreateManifestVersion(ctx, f.db, doc, checksum); !errors.Is(err, repository.ErrCapacityPolicyPublicationConflict) {
		t.Fatal("ordinary publication must refuse the busy original", err)
	}
	if catalog() != beforeCatalog || original() != beforeOriginal {
		t.Fatal("refused publication changed catalog or original job/run")
	}

	// DECLARED hostile/pre-guard catalog fault, after proving the real writer
	// refuses. Copy its version/default/active transition and entire Spec/SHA;
	// never alter the original job, run, ACK, lease, source tick or intent.
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var nextVersion int
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2`, doc.Metadata.Namespace, doc.Metadata.Name).Scan(&nextVersion); err != nil {
		t.Fatal(err)
	}
	var previousRows string
	if err = tx.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(m)-'active'-'updated_at' ORDER BY id)::text FROM public.manifests m WHERE kind='capacity_policy' AND namespace=$1 AND name=$2`, doc.Metadata.Namespace, doc.Metadata.Name).Scan(&previousRows); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND active`, doc.Metadata.Namespace, doc.Metadata.Name); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err = tx.QueryRowContext(ctx, `INSERT INTO public.manifests (api_version,kind,namespace,name,version,active,description,labels,spec,checksum) VALUES ($1,'capacity_policy',$2,$3,$4,true,'','{}'::jsonb,$5::jsonb,$6) RETURNING id`, doc.APIVersion, doc.Metadata.Namespace, doc.Metadata.Name, nextVersion, raw, checksum).Scan(&id); err != nil {
		t.Fatal(err)
	}
	var afterRows string
	var exactSpec, oldInactive bool
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT jsonb_agg(to_jsonb(m)-'active'-'updated_at' ORDER BY id)::text FROM public.manifests m WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND id<>$3),(SELECT spec=$4::jsonb AND checksum=$5 AND active AND version=$6 FROM public.manifests WHERE id=$3),NOT EXISTS(SELECT 1 FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND id<>$3 AND active)`, doc.Metadata.Namespace, doc.Metadata.Name, id, raw, checksum, nextVersion).Scan(&afterRows, &exactSpec, &oldInactive); err != nil || afterRows != previousRows || !exactSpec || !oldInactive {
		t.Fatal("declared catalog fault changed more than the original writer's version/active transition", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if original() != beforeOriginal {
		t.Fatal("declared catalog fault changed original job/run")
	}
	next, err := repository.GetManifestByID(ctx, f.db, id)
	if err != nil || next.ID == old.Policy.ID || next.Version != nextVersion || next.Checksum != checksum || !next.Metadata.Active {
		t.Fatal("declared replacement catalog fixture unavailable", err)
	}
	return next
}
