//go:build !linux

package capacityhostfactory

import (
	"context"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"net/http"
	"time"
)

// Source assembly input: assembled9/internal/capacityhostfactory/owner_unsupported.go
// Unsupported platforms expose the same compile-time API, with no registry,
// context authority, OS calls, descriptors, network, SQL or native effects.
type OriginalFactoryRealm struct{}
type OriginalIOCollection struct{}
type OrdinaryOriginalCreate struct{}
type originalLedger struct{}
type originalChild struct{}

func unavailable() error       { return capacity.ErrHostFactorySourceUnavailable }
func RefusalCode(error) string { return "source_registry_refused" }
func NewOriginalFactoryRealm(context.Context, string) (*OriginalFactoryRealm, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) Context(context.Context) (context.Context, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) RootID(context.Context) (string, error) { return "", unavailable() }
func (*OriginalFactoryRealm) Approval(context.Context) (model.HostFactorySourceApproval, error) {
	return model.HostFactorySourceApproval{}, unavailable()
}
func (*OriginalFactoryRealm) VerifyLive(context.Context) error { return unavailable() }
func (*OriginalFactoryRealm) InitialObservation(context.Context) (model.HostFactoryInitialEmptyRealmRead, []byte, error) {
	return model.HostFactoryInitialEmptyRealmRead{}, nil, unavailable()
}
func (*OriginalFactoryRealm) InitialAssessment(context.Context) (model.CapacityAssessment, error) {
	return model.CapacityAssessment{}, unavailable()
}
func (*OriginalFactoryRealm) OriginalRootStages(context.Context) (map[string][]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) BindOriginalInvocation(context.Context, string, model.Manifest, model.Manifest, model.WorkflowStepSpec, model.WorkflowStepSpec, model.WorkflowStepSpec, model.CapacityAssessment) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalClaimTransactionBinding(context.Context, string) (string, []byte, []byte, []byte, error) {
	return "", nil, nil, nil, unavailable()
}
func (*OriginalFactoryRealm) CheckOriginalClaimTransaction(context.Context, string, model.CapacityIntent, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalClaimReturn(context.Context, string, model.CapacityIntent, []byte, time.Time, time.Time) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalLeaseProvenance(context.Context, string) (model.HostFactoryOriginalLeaseProvenance, []byte, error) {
	return model.HostFactoryOriginalLeaseProvenance{}, nil, unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalCurrentLeaseRead(context.Context, string, model.CapacityIntent, time.Time, time.Time) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalRootIdentity(context.Context) (string, string, string, error) {
	return "", "", "", unavailable()
}
func (*OriginalFactoryRealm) CheckOriginalAwaitingOwnerTransaction(context.Context, string, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalAwaitingOwnerReturn(context.Context, string, []byte, time.Time, time.Time) error {
	return unavailable()
}
func VerifyOriginalHistoricalStage(context.Context, string, []byte) error { return unavailable() }
func VerifyOriginalHistoricalPolicyInput(context.Context, model.Manifest, model.Manifest, model.WorkflowStepSpec, model.WorkflowStepSpec, model.WorkflowStepSpec) error {
	return unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalPolicyInput(context.Context, model.Manifest, model.Manifest, model.WorkflowStepSpec, model.WorkflowStepSpec, model.WorkflowStepSpec) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalSourceAudits(context.Context) ([]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) OriginalPolicyAuditCallReferences(context.Context) ([]string, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) OriginalClosingIO(context.Context) (map[string][]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) FinalizeOriginalRootCompletion(context.Context) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalFinalCorpus(context.Context) ([]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalStage(context.Context, string, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) SignOriginalAuthority(context.Context, string, []byte) ([]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) OriginalAuthorityBody(context.Context, string) ([]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) PrepareOriginalSealed(context.Context, string, model.Manifest, model.Manifest, model.WorkflowStepSpec, model.CapacityMutationBinding, string, int, string) (model.HostFactoryPreAuthorityScope, []byte, map[string][]byte, error) {
	return model.HostFactoryPreAuthorityScope{}, nil, nil, unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalGrantBinding(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, []byte, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) SealOriginal(context.Context, []byte) (map[string][]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalOrdinaryGuard(context.Context, model.FactoryOrdinaryGuardRead, []byte, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalOrdinaryRedeem(context.Context, string, model.CapacityMutationRedeemRequest, []byte, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalOrdinarySettle(context.Context, string, model.CapacityMutationSettleRequest, string, []byte, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) VerifyOriginalOrdinaryCreateReturn(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityMutationProof, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalOrdinaryWitnessed(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalCreateWitness) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalOrdinaryEnrolled(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalOrdinaryGrantBinding(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, []byte, []byte) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalOrdinaryIssueReturn(context.Context, model.CapacityMutationGrant, time.Time, time.Time) error {
	return unavailable()
}
func (*OriginalFactoryRealm) OriginalOrdinaryGuardEnvelope(context.Context, string, string, string, string) ([]byte, error) {
	return nil, unavailable()
}
func (*OriginalFactoryRealm) ReserveOriginalOrdinaryGuardRead(context.Context, string, string, string, string) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalOrdinaryGuardRead(context.Context, string, string, []byte, []byte, []byte, []byte, []byte, time.Time, time.Time) (model.FactoryOrdinaryGuardRead, []byte, error) {
	return model.FactoryOrdinaryGuardRead{}, nil, unavailable()
}
func (*OriginalFactoryRealm) CaptureOriginalOrdinaryGuardFailure(context.Context, string, string, []byte, []byte, []byte, []byte, []byte, time.Time, time.Time, error) error {
	return unavailable()
}
func (*OriginalFactoryRealm) CloseAndJoin(context.Context) error { return unavailable() }
func (*OriginalIOCollection) Resolve(string) ([]byte, error)     { return nil, unavailable() }
func (*OriginalIOCollection) Predecessor(string, uint32) ([]byte, uint32, error) {
	return nil, 0, unavailable()
}
func (*OriginalIOCollection) OriginalBodies() map[string][]byte { return map[string][]byte{} }
func (*OrdinaryOriginalCreate) CreateOriginal(context.Context, *originalLedger, *http.Client, string) (*originalChild, error) {
	return nil, unavailable()
}
func RunOriginalWorker(context.Context, []string) error { return unavailable() }
func RunOriginalRegistrar(context.Context) error        { return unavailable() }
func ParseChildDeadline(string) (time.Time, error)      { return time.Time{}, unavailable() }

func (*OriginalFactoryRealm) String() string                 { return "original factory realm (opaque)" }
func (r *OriginalFactoryRealm) GoString() string             { return r.String() }
func (r *OriginalFactoryRealm) Format(s fmt.State, _ rune)   { _, _ = fmt.Fprint(s, r.String()) }
func (*OrdinaryOriginalCreate) String() string               { return "ordinary original create (opaque)" }
func (c *OrdinaryOriginalCreate) GoString() string           { return c.String() }
func (c *OrdinaryOriginalCreate) Format(s fmt.State, _ rune) { _, _ = fmt.Fprint(s, c.String()) }

// Source assembly input: native_unsupported_fragment.go
// ISOLATED parity patch, not active model adoption. No OS/network/SQL/native
// operation, installation, key or healthy registry on unsupported platforms.
func ResolveOriginalHistoricalNativeAggregate(ctx context.Context, value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originalAggregateEnvelopeSHA256 string,
	resolveOriginal func(string, string) ([]byte, []byte, error), resolveIO func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error),
	originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error), originalPhase func(string, string) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func (r *OriginalFactoryRealm) ResolveOriginalNativeAggregate(ctx context.Context, value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originalAggregateEnvelopeSHA256 string,
	resolveOriginal func(string, string) ([]byte, []byte, error), resolveIO func(string) ([]byte, error), predecessor func(string, uint32) ([]byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, error),
	originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error), originalPhase func(string, string) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func (r *OriginalFactoryRealm) OriginalGetdentsBuffer(ctx context.Context, originalCallID string) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func (r *OriginalFactoryRealm) OriginalGetdentsSourceAuditCustody(ctx context.Context, originalCallID string) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func (r *OriginalFactoryRealm) OriginalNativeInventoryRelations(ctx context.Context, observationID string) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func (r *OriginalFactoryRealm) OriginalNativePhaseContext(ctx context.Context, aggregateBodySHA256 string) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

// Fixed Source51/private custody APIs remain unavailable on unsupported OSes.
func (r *OriginalFactoryRealm) ValidateOriginalSourceCallVector(ctx context.Context, factoryRootID string, reference model.HostFactoryCallVectorReference,
	originalIO func(string) ([]byte, []byte, error), originalPredecessor func(string, uint32) ([]byte, []byte, uint32, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error)) error {
	return capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) ValidateOriginalSourceHandleInventory(ctx context.Context, factoryRootID string, value model.HostFactoryHandleCallInventory,
	originalIO func(string) ([]byte, []byte, error), originalPredecessor func(string, uint32) ([]byte, []byte, uint32, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error)) error {
	return capacity.ErrHostFactorySourceUnavailable
}

func ValidateOriginalHistoricalSourceCallVector(ctx context.Context, sourceApprovalRaw, sourceApprovalEnvelope []byte, factoryRootID string, reference model.HostFactoryCallVectorReference,
	originalIO func(string) ([]byte, []byte, error), originalPredecessor func(string, uint32) ([]byte, []byte, uint32, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error)) error {
	return capacity.ErrHostFactorySourceUnavailable
}

func ValidateOriginalHistoricalSourceHandleInventory(ctx context.Context, sourceApprovalRaw, sourceApprovalEnvelope []byte, factoryRootID string, value model.HostFactoryHandleCallInventory,
	originalIO func(string) ([]byte, []byte, error), originalPredecessor func(string, uint32) ([]byte, []byte, uint32, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error)) error {
	return capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) ResolveOriginalSourceNativeAggregate(ctx context.Context, value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originalAggregateEnvelopeSHA256 string,
	resolveOriginal func(string, string) ([]byte, []byte, error), resolveIO func(string) ([]byte, []byte, error), predecessor func(string, uint32) ([]byte, []byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, []byte, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error), originalPhase func(string, string) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func ResolveOriginalHistoricalSourceNativeAggregate(ctx context.Context, sourceApprovalRaw, sourceApprovalEnvelope []byte, value any, factoryRootID, bindingSchema, bindingSHA256 string, originalDeadline time.Time, originalAggregateEnvelopeSHA256 string,
	resolveOriginal func(string, string) ([]byte, []byte, error), resolveIO func(string) ([]byte, []byte, error), predecessor func(string, uint32) ([]byte, []byte, uint32, error), getdentsOriginal func(string) ([]byte, error), resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, []byte, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error), originalPhase func(string, string) ([]byte, error)) ([]model.HostFactoryNativeObservationRecord, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) OriginalSourceProfile(ctx context.Context) (*capacity.HostFactorySourceProfile, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func VerifyOriginalHistoricalSourceProfile(ctx context.Context, sourceApprovalRaw, sourceApprovalEnvelope []byte) (*capacity.HostFactorySourceProfile, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) OriginalParentHeldRootAnchor(ctx context.Context) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) OriginalPostStartLedgerCustody(ctx context.Context, aggregateBodySHA string) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

func (r *OriginalFactoryRealm) OriginalFinalSourceAuditCustody(ctx context.Context) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}
func VerifyOriginalHistoricalFinalSourceAuditCustody(ctx context.Context, sourceApprovalRaw, sourceApprovalEnvelope, rootPreparationRaw, rootPreparationEnvelope, custodyRaw []byte,
	originalIO func(string) ([]byte, []byte, error), originalPredecessor func(string, uint32) ([]byte, []byte, uint32, error), originalBasis func(string, string, string, string, string) ([]byte, []byte, []byte, error)) ([]byte, error) {
	return nil, capacity.ErrHostFactorySourceUnavailable
}

// Source-owned ordinary wait remains unavailable on unsupported platforms.
func (*OriginalFactoryRealm) WaitOriginalOrdinarySettle(context.Context, string, model.CapacityMutationSettleRequest) error {
	return capacity.ErrHostFactorySourceUnavailable
}
func (*OriginalFactoryRealm) PrepareOriginalOrdinary(context.Context, string, model.Manifest, model.Manifest, model.WorkflowStepSpec, model.CapacityMutationBinding, string, int) (model.FactoryOrdinarySourceBinding, []byte, map[string][]byte, error) {
	return model.FactoryOrdinarySourceBinding{}, nil, nil, capacity.ErrHostFactorySourceUnavailable
}
func (*OriginalFactoryRealm) ContinueOriginalOrdinary(context.Context) (model.CapacityMutationProof, []byte, error) {
	return model.CapacityMutationProof{}, nil, capacity.ErrHostFactorySourceUnavailable
}
