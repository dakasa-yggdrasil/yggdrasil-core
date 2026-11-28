package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Read context issuance must finish before the owner snapshots expected raw
// originals. This short mutex never covers DB/WAN work; Seal itself is atomic.
func (st *nativeMemberStoreState) enterReadContext() (func(), error) {
	st.readMu.Lock()
	if st.sealed.Load() {
		st.readMu.Unlock()
		return nil, ErrCapacityDisabled
	}
	if st.readActive == 0 {
		st.readIdle = make(chan struct{})
	}
	st.readActive++
	st.readMu.Unlock()
	return func() {
		st.readMu.Lock()
		defer st.readMu.Unlock()
		st.readActive--
		if st.readActive == 0 {
			close(st.readIdle)
			st.readIdle = nil
		}
	}, nil
}

// ReceivingOriginalsJoined is a protected DB-only shutdown check, not a proof
// of provider acceptance, effect, billing or retirement. Local HTTP cancellation
// does not establish remote SDK EOF. Missing/uncertain originals keep the owner,
// receiving listeners, keys and lower dependencies held. History is not expired
// or removed to make this check pass.
func (s *CapacityNativeWorkerMemberStore) ReceivingOriginalsJoined(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrCapacityNativeReturnPending
	}
	st, e := s.acquire()
	if e != nil {
		return e
	}
	defer st.mu.RUnlock()
	if !st.sealed.Load() || st.workers.Capacity.DB == nil {
		return ErrCapacityNativeReturnPending
	}
	st.readMu.Lock()
	idle := st.readIdle
	st.readMu.Unlock()
	if idle != nil {
		select {
		case <-idle:
		case <-ctx.Done():
			return ErrCapacityNativeReturnPending
		}
	}
	now := time.Now().UTC()
	if e = st.memberOriginalJoins(ctx, now); e != nil {
		return ErrCapacityNativeReturnPending
	}
	if e = st.readOriginalJoins(ctx, now); e != nil {
		return ErrCapacityNativeReturnPending
	}
	if e = st.providerOriginalJoins(ctx); e != nil {
		return ErrCapacityNativeReturnPending
	}
	if e = st.networkOriginalJoins(ctx, now); e != nil {
		return ErrCapacityNativeReturnPending
	}
	if ctx.Err() != nil {
		return ErrCapacityNativeReturnPending
	}
	return nil
}

func nativeMemberRowsEnd(rows *sql.Rows, count int) error {
	if count > 100000 || rows.Err() != nil {
		return errNativeMember
	}
	return rows.Close()
}
func (st *nativeMemberStoreState) memberOriginalJoins(ctx context.Context, now time.Time) error {
	rows, e := st.workers.Capacity.DB.QueryContext(ctx, `SELECT id,CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE policy_id=$1 AND namespace=$2 AND (record ? 'dispatch_started_at' OR COALESCE(record->>'settlement_token_sha256','')<>'') AND NOT(state='no_effect' AND COALESCE(record->>'settlement_token_sha256','')='') ORDER BY id LIMIT 100001`, st.policy.ID, st.policy.Metadata.Namespace)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return errNativeMember
		}
		var id uuid.UUID
		var raw []byte
		var r nativeMemberRecord
		if rows.Scan(&id, &raw) != nil || nativeMemberDecode(raw, &r) != nil || r.Context.PermitID != id.String() || r.Context.PolicyID != st.policy.ID.String() || r.Context.Actor.BindingName == "" {
			return errNativeMember
		}
		original, e := st.original(r)
		if e != nil || original.Schema != model.CapacityNativeWorkerMemberReceiveSchema || original.PermitID != id.String() || original.BindingName != r.Context.Actor.BindingName || !nativeMemberOriginalCompleted(r, original, now) {
			return errNativeMember
		}
		hash, ok := nativeReadinessTokenSHA(original.SettlementToken)
		if !ok || hash != r.SettlementTokenSHA256 {
			return errNativeMember
		}
	}
	return nativeMemberRowsEnd(rows, count)
}
func (st *nativeMemberStoreState) readOriginalJoins(ctx context.Context, now time.Time) error {
	rows, e := st.workers.Capacity.DB.QueryContext(ctx, `SELECT r.id,CASE WHEN octet_length(r.record::text)<=8388608 THEN r.record END,CASE WHEN octet_length(p.record::text)<=8388608 THEN p.record END FROM public.capacity_native_worker_member_reads r JOIN public.capacity_native_worker_member_permits p ON p.id=r.permit_id WHERE r.policy_id=$1 AND r.namespace=$2 AND r.endpoint_kind='kubelet_configz' ORDER BY r.id LIMIT 100001`, st.policy.ID, st.policy.Metadata.Namespace)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return errNativeMember
		}
		var id uuid.UUID
		var raw, parent []byte
		var r nativeMemberReadRecord
		var p nativeMemberRecord
		if rows.Scan(&id, &raw, &parent) != nil || nativeMemberDecode(raw, &r) != nil || nativeMemberDecode(parent, &p) != nil || r.ReadID != id || r.PermitID.String() != p.Context.PermitID || r.Kind != "kubelet_configz" || r.PrivateOriginal == nil || p.Context.Node == nil || r.SubjectNodeUID != p.Context.Node.UID || r.SDKSourceCommit != p.Context.Observer.SourceCommit || r.ScopeSHA256 != p.Context.Observer.ScopeSHA256 || r.ContextSHA256 != capacity.NativeWorkerMemberContextSHA(p.Context) {
			return errNativeMember
		}
		_, plain, e := st.crypt(p.Context, "read/"+id.String(), r.PrivateOriginal, nil)
		var envelope nativeMemberPrivateOriginal
		var original model.CapacityNativeWorkerMemberReadOriginal
		if e == nil {
			e = nativeMemberDecode(plain, &envelope)
		}
		if e == nil {
			e = nativeMemberDecode(envelope.Wire, &original)
		}
		clear(plain)
		if e != nil || envelope.BodySHA256 != nativeMemberRawSHA(original.OriginalReturn) || original.Schema != model.CapacityNativeWorkerMemberReadOriginalSchema || original.ReadID != id.String() || original.PermitID != r.PermitID.String() || original.BindingName != p.Context.Observer.BindingName || original.Kind != r.Kind || !original.CaptureComplete || !original.TransportCompleted || original.ErrorClass != "" || original.CompletedAt.IsZero() || original.CompletedAt.Before(r.CreatedAt) || original.CompletedAt.After(now) {
			return errNativeMember
		}
	}
	return nativeMemberRowsEnd(rows, count)
}
func (st *nativeMemberStoreState) providerOriginalJoins(ctx context.Context) error {
	rows, e := st.workers.Capacity.DB.QueryContext(ctx, `SELECT p.record->>'provider_permit_id',CASE WHEN octet_length(a.record::text)<=8388608 THEN a.record END FROM public.capacity_native_worker_member_plans p LEFT JOIN public.capacity_native_worker_abort_permits a ON a.id::text=p.record->>'provider_permit_id' AND a.attempt_id=p.attempt_id AND a.policy_id=p.policy_id AND a.namespace=p.namespace WHERE p.policy_id=$1 AND p.namespace=$2 AND p.record ? 'provider_dispatch_started_at' ORDER BY p.id LIMIT 100001`, st.policy.ID, st.policy.Metadata.Namespace)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return errNativeMember
		}
		var id string
		var raw []byte
		var r nativeWorkerAbortRecord
		if rows.Scan(&id, &raw) != nil || nativeMemberDecode(raw, &r) != nil || r.Context.PermitID.String() != id || r.Attempt.PolicyID != st.policy.ID || !nativeMemberProviderOriginalComplete(r) {
			return errNativeMember
		}
	}
	return nativeMemberRowsEnd(rows, count)
}
func (st *nativeMemberStoreState) networkOriginalJoins(ctx context.Context, now time.Time) error {
	rows, e := st.workers.Capacity.DB.QueryContext(ctx, `SELECT p.record->>'network_permit_id',CASE WHEN octet_length(n.record::text)<=8388608 THEN n.record END FROM public.capacity_native_worker_member_plans p LEFT JOIN public.capacity_native_worker_network_permits n ON n.id::text=p.record->>'network_permit_id' AND n.attempt_id=p.attempt_id AND n.policy_id=p.policy_id AND n.namespace=p.namespace WHERE p.policy_id=$1 AND p.namespace=$2 AND p.record ? 'network_dispatch_started_at' ORDER BY p.id LIMIT 100001`, st.policy.ID, st.policy.Metadata.Namespace)
	if e != nil {
		return e
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return errNativeMember
		}
		var id string
		var raw []byte
		var r nativeWorkerNetworkRecord
		if rows.Scan(&id, &raw) != nil || nativeMemberDecode(raw, &r) != nil || r.Context.PermitID != id || r.Attempt.PolicyID != st.policy.ID || r.SourceCommit != r.Attempt.SourceCommit || r.Context.AttemptID != r.Attempt.ID.String() || r.Context.PolicyID != r.Attempt.PolicyID.String() || r.Context.LaunchSHA256 != r.Attempt.LaunchSHA256 || r.Context.CreationProofSHA256 != r.Attempt.BirthSHA256 || r.Context.SystemSourceCommit != r.Binding.Writer.SystemSourceCommit || r.Context.WriterScopeSHA256 != r.Binding.Writer.ScopeSHA256 || r.Context.BindingName != r.Binding.Writer.BindingName || r.Original == nil || !r.OriginalCallerClosed || r.Original.Schema != "native_worker_network_receive_v1" || !r.Original.CaptureComplete || r.Original.ErrorClass != "" || r.Original.PermitID != id || r.Original.BindingName != r.Context.BindingName || !nativeNetworkOriginalCallerClosed(r.Context, *r.Original, now) {
			return errNativeMember
		}
	}
	return nativeMemberRowsEnd(rows, count)
}
