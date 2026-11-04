//go:build !linux || !nativequalification

package repository

import("context";"database/sql";"time";"github.com/dakasa-yggdrasil/yggdrasil-core/model")
// Production has no canonical Source failure authority/registration.
func(s CapacityStore)canonicalSourceFailedCleanupTx(context.Context,*sql.Tx,model.CapacityPolicySpec,capacityMutationRecord,model.CapacityMutationProof,time.Time,string)(bool,error){return false,nil}
func(s CapacityStore)canonicalSourceBindCompensationTx(context.Context,*sql.Tx,capacityMutationRecord,capacityMutationRecord,time.Time)(bool,error){return false,nil}
func(s CapacityStore)canonicalSourceConfirmedCleanupTx(context.Context,*sql.Tx,model.CapacityPolicySpec,capacityMutationRecord,model.CapacityMutationProof,time.Time)(bool,error){return false,nil}
