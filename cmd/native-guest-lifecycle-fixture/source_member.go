//go:build linux && nativequalification

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These locally owned shapes preserve the Guest source's exact JSON ordering.
// Static boot config contains no promised native tuple, preregistration ID or
// nonce. The scoped source gateway binds the original native identity later.
type provisioningSourceConfig struct {
	Schema                       string                                      `json:"schema"`
	Enabled                      bool                                        `json:"enabled"`
	CoreOrigin                   string                                      `json:"core_origin"`
	CoreWitnessPublicKey         string                                      `json:"core_witness_public_key"`
	EnrollmentAuthorityPublicKey string                                      `json:"enrollment_authority_public_key"`
	ProducerPublicKey            string                                      `json:"producer_public_key"`
	ObservationPublicKey         string                                      `json:"observation_public_key"`
	CoreIntentPublicKey          string                                      `json:"core_intent_public_key"`
	BindingName                  string                                      `json:"binding_name"`
	MemberName                   string                                      `json:"member_name"`
	Slot                         int                                         `json:"slot"`
	Profile                      model.CapacityGuestProtectedProfileManifest `json:"profile_manifest"`
}
type retirementSourceConfig struct {
	Schema                       string                                   `json:"schema"`
	Enabled                      bool                                     `json:"enabled"`
	CoreAuthorityOrigin          string                                   `json:"core_authority_origin"`
	CoreClientCommonName         string                                   `json:"core_client_common_name"`
	EnrollmentAuthorityPublicKey string                                   `json:"enrollment_authority_public_key"`
	SystemCtlSHA256              string                                   `json:"systemctl_sha256"`
	Enrollment                   *model.CapacityGuestRetirementEnrollment `json:"enrollment,omitempty"`
}

func (f *fixture) prepareMember(ctx context.Context, slot q.SlotRequest) (model.CapacityGuestRetirementMemberBinding, error) {
	var member model.CapacityGuestRetirementMemberBinding
	directory := q.SlotDirectory(f.private, slot.Slot)
	if directory == "" {
		return member, q.ErrOriginalUnknown
	}
	for _, path := range []string{directory, filepath.Join(directory, "source-bundle"), filepath.Join(directory, "source-bundle", "provisioning"), filepath.Join(directory, "source-bundle", "retirement")} {
		if err := os.Mkdir(path, 0700); err != nil {
			return member, err
		}
	}
	serverCertificate, serverKey, err := f.issueCertificate("original-guest-slot-"+fmt.Sprint(slot.Slot), true)
	if err != nil {
		return member, err
	}
	producerToken, err := randomToken()
	if err != nil {
		return member, err
	}
	actorToken, err := randomToken()
	if err != nil {
		return member, err
	}
	observationPublic, observationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return member, err
	}
	caRef, err := f.secret(ctx, "slot-"+fmt.Sprint(slot.Slot)+"-server-ca", f.caPEM)
	if err != nil {
		return member, err
	}
	certRef, err := f.secret(ctx, "slot-"+fmt.Sprint(slot.Slot)+"-caller-certificate", f.callerCertificate)
	if err != nil {
		return member, err
	}
	keyRef, err := f.secret(ctx, "slot-"+fmt.Sprint(slot.Slot)+"-caller-key", f.callerKey)
	if err != nil {
		return member, err
	}
	member = model.CapacityGuestRetirementMemberBinding{Name: "original-qemu-slot-" + fmt.Sprint(slot.Slot), Slot: slot.Slot, Origin: slot.ActorOrigin, ServerCARef: caRef, ClientCertificateRef: certRef, ClientKeyRef: keyRef, ActorClientPrincipal: "original-qemu-slot-" + fmt.Sprint(slot.Slot) + "-actor", ProvisionerClientPrincipal: "original-qemu-slot-" + fmt.Sprint(slot.Slot) + "-producer"}
	pub := func(value ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(value) }
	provisioning := provisioningSourceConfig{"original_guest_provisioning_config_v1", true, f.request.GatewayOrigin, pub(f.corePublic), pub(f.issuerPublic), pub(f.producerPublic), pub(observationPublic), pub(f.corePublic), member.Name, member.Name, member.Slot, f.profile}
	retirement := retirementSourceConfig{Schema: capacity.GuestRetirementSchema, Enabled: true, CoreAuthorityOrigin: f.request.GatewayOrigin, CoreClientCommonName: "original-core-private-caller", EnrollmentAuthorityPublicKey: pub(f.issuerPublic), SystemCtlSHA256: f.profile.PoweroffCommandSHA256}
	provisioningDir := filepath.Join(directory, "source-bundle", "provisioning")
	retirementDir := filepath.Join(directory, "source-bundle", "retirement")
	for path, value := range map[string]any{filepath.Join(provisioningDir, "config.json"): provisioning, filepath.Join(retirementDir, "config.json"): retirement, filepath.Join(directory, "guest-provisioning.json"): provisioning} {
		if _, err = q.Publish(ctx, path, value); err != nil {
			return member, err
		}
	}
	for path, raw := range map[string][]byte{
		filepath.Join(provisioningDir, "core-ca.crt"): f.caPEM, filepath.Join(provisioningDir, "client.crt"): f.callerCertificate, filepath.Join(provisioningDir, "client.key"): f.callerKey, filepath.Join(provisioningDir, "core-service-token"): []byte(producerToken), filepath.Join(provisioningDir, "producer-private-key"): []byte(base64.StdEncoding.EncodeToString(f.producerPrivate)), filepath.Join(provisioningDir, "observation-public-key"): []byte(pub(observationPublic)),
		filepath.Join(retirementDir, "server.crt"): serverCertificate, filepath.Join(retirementDir, "server.key"): serverKey, filepath.Join(retirementDir, "caller-ca.crt"): f.caPEM, filepath.Join(retirementDir, "core-ca.crt"): f.caPEM, filepath.Join(retirementDir, "client.crt"): f.callerCertificate, filepath.Join(retirementDir, "client.key"): f.callerKey, filepath.Join(retirementDir, "core-service-token"): []byte(actorToken), filepath.Join(retirementDir, "observation-private-key"): []byte(base64.StdEncoding.EncodeToString(observationPrivate)),
		filepath.Join(directory, "guest-server.crt"): serverCertificate, filepath.Join(directory, "guest-server.key"): serverKey, filepath.Join(directory, "producer.token"): []byte(producerToken), filepath.Join(directory, "actor.token"): []byte(actorToken),
	} {
		if _, err = q.PublishBytes(ctx, path, raw); err != nil {
			return member, err
		}
	}
	for _, principal := range []struct{ ID, Token, Role string }{{member.ProvisionerClientPrincipal, producerToken, "provisioner"}, {member.ActorClientPrincipal, actorToken, "actor"}} {
		f.guestPrincipals = append(f.guestPrincipals, map[string]any{"principal_id": principal.ID, "status": "active", "expires_at": f.request.OriginalContextDeadline, "rotation_id": uuid.NewString(), "rotated_at": time.Now().UTC(), "token_sha256": capacity.BusinessCreationSHA256([]byte(principal.Token)), "role": principal.Role, "binding_name": member.Name, "slot": member.Slot, "profile_manifest_sha256": capacity.GuestRetirementSHA(f.profile)})
	}
	return member, nil
}
