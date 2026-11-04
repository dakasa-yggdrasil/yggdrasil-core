//go:build linux && nativequalification

package capacitynativeqemu

import (
 "context"
 "time"
 "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type SourceTerminalContract struct {
 Schema string `json:"schema"`
 Case string `json:"case"`
 Scope string `json:"scope"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 PolicyID string `json:"policy_id"`
 GrantID string `json:"grant_id"`
 Generation int64 `json:"generation"`
 RecoveryFence int64 `json:"recovery_fence"`
 GrantState string `json:"grant_state"`
 Terminal string `json:"terminal"`
 TerminalRefused bool `json:"terminal_refused"`
 ProbeSHA256 string `json:"probe_sha256"`
 PhysicalSHA256 string `json:"physical_sha256"`
 ProofSHA256 string `json:"proof_sha256"`
 ReplaySHA256 string `json:"replay_sha256"`
 FirstSHA256 string `json:"first_sha256"`
 RefusalSHA256 string `json:"refusal_sha256"`
 CallbackRepresentation string `json:"callback_representation"`
 CallbackAttemptID string `json:"callback_attempt_id"`
 CallbackRequestSHA256 string `json:"callback_request_sha256"`
 LeaseExpiredObservedAt time.Time `json:"lease_expired_observed_at"`
 CheckedAt time.Time `json:"checked_at"`
 OriginalDeadline time.Time `json:"original_deadline"`
 NativeQualified bool `json:"native_qualified"`
}

// Reuses the original authenticated bounded HTTP Read/EOF/Close owner. This
// callback never reaches Create and does not expose the live settlement nonce.
func(r *Realm) TerminalRedeem(ctx context.Context,request model.CapacityMutationRedeemRequest)(model.CapacityMutationRedeemResponse,error){
 var result model.CapacityMutationRedeemResponse
 if !SourceTerminalCase(r.Request.NativeCase) || request.Slot!=2{return result,ErrOriginalUnknown}
 if err:=r.api(ctx,"/api/v1/capacity/mutations/redeem","",request,&result);err!=nil{return result,err}
 if result.GrantID!=request.GrantID || result.AttemptID!=request.AttemptID || result.RequestSHA256!=request.RequestSHA256 || (result.Mode!="write_once" && result.Mode!="read_only"){return result,ErrOriginalUnknown}
 return result,nil
}

// Facts are derived from the exact actually returned internal error. The error
// message itself is not retained, and this is not a raw HTTP response body.
type SourceTerminalRefusal struct {
 Schema string `json:"schema"`
 Representation string `json:"representation"`
 ErrorClass string `json:"error_class"`
 Predicate string `json:"predicate"`
 ReturnCount int `json:"return_count"`
 ErrorBytes int `json:"error_bytes"`
 ErrorSHA256 string `json:"error_sha256"`
}
