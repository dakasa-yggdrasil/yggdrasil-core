//go:build linux && nativequalification

package capacitynativeqemu

import (
 "context"
 "database/sql"
 "encoding/json"

 "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
 "github.com/dakasa-yggdrasil/yggdrasil-core/repository"
 "github.com/google/uuid"
)

// These values are read only from the actual provider invocation's SQL store.
// This struct is not an input, authority factory, artifact or public protocol.
type originalReplaySQLSnapshot struct {
 State string
 GrantID string
 AttemptID string
 RequestSHA256 string
 PolicyID string
 PolicyChecksum string
 WorkflowID string
 ExecutorID string
 SettlementTokenSHA256 string
 GrantWireSHA256 string
 PreregistrationWireSHA256 string
 Preregistrations int
 Members int
 EnsuredEvents int
}

func originalReplaySQLSnapshotOwned(v originalReplaySQLSnapshot, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, attempt, nonce string) bool {
 return store.DB!=nil && store.WorkflowID!=uuid.Nil && store.ExecutorID!="" && v.State=="redeemed" && grant.CompensationOf=="" && v.GrantID==grant.GrantID && v.AttemptID==attempt && v.RequestSHA256==grant.RequestSHA256 && v.PolicyID==policy.ID.String() && v.PolicyChecksum==policy.Checksum && v.WorkflowID==store.WorkflowID.String() && v.ExecutorID==store.ExecutorID && v.SettlementTokenSHA256==capacity.BusinessCreationSHA256([]byte(nonce)) && capacity.ValidDigest(v.GrantWireSHA256) && capacity.ValidDigest(v.PreregistrationWireSHA256) && v.Preregistrations==1 && v.Members==0 && v.EnsuredEvents==0
}

// The winning nonce remains memory-only. This read creates no permission,
// profile, context, lease, provider action, mutation callback or native send.
func readOriginalReplaySQLSnapshot(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, attempt, nonce string)(originalReplaySQLSnapshot,error){
 var out originalReplaySQLSnapshot
 if store.DB==nil || ctx.Err()!=nil || attempt=="" || nonce=="" {return out,ErrOriginalUnknown}
 tx,err:=store.DB.BeginTx(ctx,&sql.TxOptions{ReadOnly:true,Isolation:sql.LevelRepeatableRead});if err!=nil{return out,err};defer tx.Rollback()
 var grantWire,preWire []byte
 if err=tx.QueryRowContext(ctx,`SELECT state,grant_record::text FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`,grant.GrantID,policy.Metadata.Namespace).Scan(&out.State,&grantWire);err!=nil{return out,err}
 var actual struct {
  Grant model.CapacityMutationGrant `json:"grant"`
  AttemptID string `json:"attempt_id"`
  PolicyID uuid.UUID `json:"policy_id"`
  PolicyChecksum string `json:"policy_checksum"`
  WorkflowID uuid.UUID `json:"workflow_id"`
  ExecutorID string `json:"executor_id"`
  SettlementTokenSHA256 string `json:"settlement_token_sha256"`
 }
 if json.Unmarshal(grantWire,&actual)!=nil{return out,ErrOriginalUnknown}
 out.GrantID=actual.Grant.GrantID;out.AttemptID=actual.AttemptID;out.RequestSHA256=actual.Grant.RequestSHA256;out.PolicyID=actual.PolicyID.String();out.PolicyChecksum=actual.PolicyChecksum;out.WorkflowID=actual.WorkflowID.String();out.ExecutorID=actual.ExecutorID;out.SettlementTokenSHA256=actual.SettlementTokenSHA256
 if actual.Grant.State!="redeemed" || actual.Grant.Slot!=grant.Slot || actual.Grant.BindingName!=grant.BindingName || actual.Grant.CompensationOf!="" {return out,ErrOriginalUnknown}
 if err=tx.QueryRowContext(ctx,`SELECT count(*),COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.id),'[]'::jsonb)::text FROM public.capacity_vm_provisioning_preregistrations p WHERE create_grant_id=$1`,grant.GrantID).Scan(&out.Preregistrations,&preWire);err!=nil{return out,err}
 if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5 AND resource_id<>''`,policy.Metadata.Namespace,grant.IntegrationInstanceID,grant.ScopeChecksum,grant.ProfileName,grant.Slot).Scan(&out.Members);err!=nil{return out,err}
 if err=tx.QueryRowContext(ctx,`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`,"capacity-mutation/"+grant.GrantID).Scan(&out.EnsuredEvents);err!=nil{return out,err}
 out.GrantWireSHA256=capacity.BusinessCreationSHA256(grantWire);out.PreregistrationWireSHA256=capacity.BusinessCreationSHA256(preWire)
 if !originalReplaySQLSnapshotOwned(out,store,policy,grant,attempt,nonce){return out,ErrOriginalUnknown}
 if err=tx.Commit();err!=nil{return out,err};return out,nil
}

func originalReplaySQLUnchanged(before,after originalReplaySQLSnapshot)bool{
 return before==after && before.State=="redeemed" && before.Preregistrations==1 && before.Members==0 && before.EnsuredEvents==0 && capacity.ValidDigest(before.GrantWireSHA256) && capacity.ValidDigest(before.PreregistrationWireSHA256)
}
