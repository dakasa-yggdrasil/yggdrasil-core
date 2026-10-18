//go:build linux && nativequalification

package main

import (
 "context"
 "bytes"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "net/http"
 "path/filepath"
 "time"

 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Runs inside the SAME original fixture, never a provider or production API.
// It preserves accepted/uncertain create transport and never fabricates a
// positive enrollment for an uncertain reply. The frontend owns its actual
// child, original Wait and pipe owners; signed source authority is durable
// BEFORE any separately labelled host cleanup action.
func (f *fixture) finishOriginalSourceCompensation(ctx context.Context,p model.CapacityPolicySpec,baseline,burst model.WorkflowRunRecord,runIDs []string,returns []originalPublicReturn) error {
 if !q.SourceCompensationCase(f.request.NativeCase) || baseline.Status!="succeeded" || burst.Status!="failed" || p.Ceiling!=2 || p.Floor<1 || p.Floor>2 {return q.ErrOriginalUnknown}
 pre,err:=f.realm.OriginalPreregistration(2);if err!=nil{return err}
 store:=repository.CapacityStore{DB:f.db,WorkflowID:f.workflow.ID}
 failureSHA,enrollmentSHA:="",""
 if !q.SourceLostCreateCase(f.request.NativeCase) {
  var witness model.CapacityGuestOriginalCreateWitness;var wire []byte
  if err=f.db.QueryRowContext(ctx,`SELECT original_wire FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`,pre.PreregistrationID).Scan(&wire);err!=nil || capacity.DecodeGuestLifecycle(wire,&witness)!=nil{return q.ErrOriginalUnknown}
  client,err:=f.sourceClient(2);if err!=nil{return err};defer client.Close()
  for {
   read,cancel:=context.WithTimeout(ctx,5*time.Second);returned,callErr:=client.Original(read,http.MethodGet,"/v1/qualification-source-refusal",[]byte("{}"));cancel()
   if callErr==nil && returned.Status==200 {
    var failed q.QualificationFailureRecord
    if capacity.GuestOriginalHTTPDecode(returned,&failed)!=nil || f.realm.ValidateOriginalFailure(failed,pre,witness,f.binding.ProvisionerPublicKey,returned.DriverReturnedAt)!=nil{return q.ErrOriginalUnknown}
    if err=store.RecordGuestQualificationSourceReturn(ctx,pre.PreregistrationID,"source_refusal",returned.Body);err!=nil{return err}
    failureSHA=capacity.BusinessCreationSHA256(returned.Body)
    if _,err=q.PublishBytes(ctx,filepath.Join(q.SlotDirectory(f.private,2),"core-original-failed-owner-diagnostic.json"),returned.Body);err!=nil{return err};break
   }
   if ctx.Err()!=nil || (callErr==nil && returned.Status!=409){return q.ErrOriginalUnknown}
   select {case<-ctx.Done():return q.ErrOriginalUnknown;case<-time.After(20*time.Millisecond):}
  }
  if err=f.db.QueryRowContext(ctx,`SELECT enrollment_sha256 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`,pre.PreregistrationID).Scan(&enrollmentSHA);err!=nil{return err}
 } else {
  var enrolled int
  if err=f.db.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1`,pre.PreregistrationID).Scan(&enrolled);err!=nil || enrolled!=0{return q.ErrOriginalUnknown}
 }
 baselineClient,err:=f.sourceClient(1);if err!=nil{return err};defer baselineClient.Close()
 useful,err:=f.realm.DiagnosticProbe(ctx,store,1,f.corePrivate,baselineClient);if err!=nil{return err}
 authority,body,err:=f.realm.PrepareSourceFailureCleanup(ctx,store,f.policy,pre,failureSHA,enrollmentSHA,f.corePrivate);if err!=nil{return err}
 // Source-scoped table is constructed by this exact nativequalification
 // fixture only. Ordinary production grants/registry are not modified.
 _,err=f.db.ExecContext(ctx,`CREATE TABLE public.capacity_source_failure_cleanup_originals(parent_grant_id uuid PRIMARY KEY,authority_id uuid UNIQUE NOT NULL,namespace text NOT NULL,authority_wire bytea NOT NULL,authority_sha256 text NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_physical(parent_grant_id uuid PRIMARY KEY REFERENCES public.capacity_source_failure_cleanup_originals(parent_grant_id),physical_wire bytea NOT NULL,physical_sha256 text NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_terminals(parent_grant_id uuid PRIMARY KEY REFERENCES public.capacity_source_failure_cleanup_physical(parent_grant_id),terminal_wire bytea NOT NULL); CREATE TABLE public.capacity_source_failure_cleanup_reads(read_id uuid PRIMARY KEY,parent_grant_id uuid NOT NULL REFERENCES public.capacity_source_failure_cleanup_terminals(parent_grant_id),generation bigint NOT NULL,fencing_token bigint NOT NULL,read_wire bytea NOT NULL,read_sha256 text NOT NULL UNIQUE,UNIQUE(parent_grant_id,generation,fencing_token)); CREATE FUNCTION public.source_cleanup_original_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable source cleanup original'; END $$; CREATE TRIGGER immutable_source_cleanup_authority BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_originals FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_physical BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_physical FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_reads BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_reads FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable(); CREATE TRIGGER immutable_source_cleanup_terminal BEFORE UPDATE OR DELETE ON public.capacity_source_failure_cleanup_terminals FOR EACH ROW EXECUTE FUNCTION public.source_cleanup_original_immutable()`);if err!=nil{return err}
 authorityWire,err:=json.Marshal(authority);if err!=nil{return err}
 inserted,err:=f.db.ExecContext(ctx,`INSERT INTO public.capacity_source_failure_cleanup_originals(parent_grant_id,authority_id,namespace,authority_wire,authority_sha256) VALUES($1,$2,$3,$4,$5)`,pre.OriginalCreateGrantID,body.AuthorityID,f.namespace,authorityWire,capacity.BusinessCreationSHA256(authorityWire));if err!=nil{return err};n,err:=inserted.RowsAffected();if err!=nil || n!=1{return q.ErrOriginalUnknown}
 var authorityReadback []byte
 if err=f.db.QueryRowContext(ctx,`SELECT authority_wire FROM public.capacity_source_failure_cleanup_originals WHERE parent_grant_id=$1`,pre.OriginalCreateGrantID).Scan(&authorityReadback);err!=nil || !bytes.Equal(authorityReadback,authorityWire){return q.ErrOriginalUnknown}
 if err=store.CheckSourceFailureCleanupLease(ctx,f.policy,pre.OriginalCreateGrantID);err!=nil{return err}
 if _,err=q.PublishBytes(ctx,filepath.Join(q.SlotDirectory(f.private,2),"source-failure-cleanup-authority.json"),authorityWire);err!=nil{return err}
 physical,err:=f.realm.ReadSourceFailureCleanup(ctx,authority,body);if err!=nil{return err}
 var retainedPhysical q.SourceFailureCleanupPhysical
 physicalWire,err:=q.Await(ctx,filepath.Join(q.SlotDirectory(f.private,2),"source-failure-cleanup-physical.json"),&retainedPhysical);if err!=nil || capacity.GuestRetirementSHA(retainedPhysical)!=capacity.GuestRetirementSHA(physical){return q.ErrOriginalUnknown}
 insertedPhysical,err:=f.db.ExecContext(ctx,`INSERT INTO public.capacity_source_failure_cleanup_physical(parent_grant_id,physical_wire,physical_sha256) VALUES($1,$2,$3)`,pre.OriginalCreateGrantID,physicalWire,capacity.BusinessCreationSHA256(physicalWire));if err!=nil{return err};n,err=insertedPhysical.RowsAffected();if err!=nil || n!=1{return q.ErrOriginalUnknown}
 parent,err:=f.realm.OriginalMutationReceipt(ctx,pre.OriginalCreateGrantID);if err!=nil || capacity.GuestRetirementSHA(parent)!=body.OriginalReceiptSHA256{return q.ErrOriginalUnknown}
 var members,failed,events int
 if err=f.db.QueryRowContext(ctx,`SELECT count(*) FILTER(WHERE resource_id<>''),count(*) FILTER(WHERE slot=2 AND resource_id<>'') FROM public.capacity_resource_slots WHERE namespace=$1`,f.namespace).Scan(&members,&failed);err!=nil || members!=1 || failed!=0{return q.ErrOriginalUnknown}
 if err=f.db.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`,"capacity-mutation/"+pre.OriginalCreateGrantID).Scan(&events);err!=nil || events!=0{return q.ErrOriginalUnknown}
 if err=store.CheckSourceFailureCleanupLease(ctx,f.policy,pre.OriginalCreateGrantID);err!=nil{return err}
 var parentRaw []byte
 if err=f.db.QueryRowContext(ctx,`SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`,pre.OriginalCreateGrantID).Scan(&parentRaw);err!=nil{return err}
 var ownerLease struct {Generation int64 `json:"generation"`;FencingToken int64 `json:"fencing_token"`;LeaseOwner string `json:"lease_owner"`;ExecutorID string `json:"executor_id"`}
 if err=json.Unmarshal(parentRaw,&ownerLease);err!=nil || ownerLease.Generation<=0 || ownerLease.FencingToken<=0 || ownerLease.LeaseOwner=="" || ownerLease.ExecutorID==""{return q.ErrOriginalUnknown}
 terminal:=repository.SourceFailureCleanupTerminal{Schema:"original_source_failure_cleanup_terminal_v1",OriginalGeneration:ownerLease.Generation,OriginalFencingToken:ownerLease.FencingToken,OriginalLeaseOwner:ownerLease.LeaseOwner,OriginalExecutorID:ownerLease.ExecutorID,ParentGrantID:pre.OriginalCreateGrantID,AuthoritySHA256:capacity.GuestRetirementSHA(authority),PhysicalSHA256:capacity.BusinessCreationSHA256(physicalWire),OriginalReceiptSHA256:capacity.GuestRetirementSHA(parent),CoreSource:body.CoreSource,GuestSource:body.GuestSource,SourceTerminal:true,CanonicalParentTerminal:false,ProductionQualified:false,ReturnedAt:time.Now().UTC()}
 terminalBody,err:=json.Marshal(terminal);if err!=nil{return err}
 signedTerminal:=q.SourceFailureCleanupAuthority{Body:terminalBody,Signature:base64.StdEncoding.EncodeToString(ed25519.Sign(f.corePrivate,terminalBody))}
 terminalWire,err:=json.Marshal(signedTerminal);if err!=nil{return err}
 if _,err=f.db.ExecContext(ctx,`INSERT INTO public.capacity_source_failure_cleanup_terminals(parent_grant_id,terminal_wire) VALUES($1,$2)`,pre.OriginalCreateGrantID,terminalWire);err!=nil{return err}
 tx,err:=f.db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
 var currentWire []byte;var current model.CapacityIntent;var checkedAt time.Time
 if err=tx.QueryRowContext(ctx,`SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE`,f.namespace,p.Environment,p.Domain,p.Dimension).Scan(&currentWire);err!=nil || capacity.DecodeGuestLifecycle(currentWire,&current)!=nil{return q.ErrOriginalUnknown}
 if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&checkedAt);err!=nil{return err}
 store.ExecutorID=ownerLease.ExecutorID
 verifiedTerminal,err:=store.ValidateSourceFailureCleanupTerminalTx(ctx,tx,f.policy,p,current,pre.OriginalCreateGrantID,checkedAt);if err!=nil{return err}
 if err=tx.Commit();err!=nil{return err};terminal=verifiedTerminal
 if _,err=q.PublishBytes(ctx,filepath.Join(f.private,"source-failure-cleanup-current-read.json"),terminal.FreshReadWire);err!=nil{return err}
 if _,err=q.PublishBytes(ctx,filepath.Join(f.private,"source-failure-cleanup-terminal.json"),terminalWire);err!=nil{return err}
 result:=struct {
  Schema string `json:"schema"`;NativeCase string `json:"native_case"`;CoreSource string `json:"core_source"`;GuestSource string `json:"guest_source"`;PolicyID string `json:"policy_id"`;PolicyChecksum string `json:"policy_checksum"`;OriginalRunIDs []string `json:"original_run_ids"`;Parent model.CapacityMutationReceipt `json:"original_parent_receipt"`;Authority q.SourceFailureCleanupAuthority `json:"source_cleanup_authority"`;Physical q.SourceFailureCleanupPhysical `json:"physical_cleanup"`;BaselineProbeSHA256 string `json:"baseline_probe_sha256"`;CanonicalParentTerminal bool `json:"canonical_parent_terminal"`;SourceTerminal repository.SourceFailureCleanupTerminal `json:"source_terminal"`;ProductionQualified bool `json:"production_qualified"`;PositiveRetirement bool `json:"positive_retirement"`
 }{"original_source_compensation_corpus_v1",f.request.NativeCase,capacity.CurrentGuestCoreSource(),f.request.SourceCommit,f.policy.ID.String(),f.policy.Checksum,runIDs,parent,authority,physical,capacity.GuestRetirementSHA(useful),false,terminal,false,false}
 wire,err:=q.Publish(ctx,filepath.Join(f.private,"source-original-compensation-result.json"),result);if err!=nil{return err}
 if _,err=q.Publish(ctx,filepath.Join(f.private,"core-original-public-caller-returns.json"),returns);err!=nil{return err}
 f.completed=q.SourceCaseStage{Schema:q.FixtureSchema,Stage:"original-native-caller-completed.json",NativeCase:f.request.NativeCase,CaseOutcome:"SOURCE_FAILURE_CLEANUP_ORIGINALS_COMPLETE_NO_POSITIVE_RETIREMENT",NativeCorpusReceiptSHA256:capacity.BusinessCreationSHA256(wire)}
 return nil
}

