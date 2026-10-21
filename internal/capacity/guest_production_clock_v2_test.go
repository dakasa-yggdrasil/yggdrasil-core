package capacity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Synthetic signature/content arithmetic only. No registry entry, SQL current
// authority, native process, provider create or production qualification.
func productionClockFixture(t *testing.T, offset time.Duration) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, model.CapacityGuestProductionProvisioningClockV2, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	p, b, _, source := guestProductionRegistryFixture(t)
	key := func(ch byte) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(ch), 32)))
	}
	core, producer, issuer := key('c'), key('p'), key('i')
	public := func(k ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	b.ProvisionerPublicKey, b.EnrollmentIssuerPublicKey = public(producer), public(issuer)
	p.Profiles[0].Provider = "hetzner"
	p.MutationBindings[0].OriginalProviderSourceCommit = source
	p.GuestRetirementBinding = &b
	uid := "10000000-0000-4000-8000-000000000001"
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: GuestPreregistrationSchema, PreregistrationID: uid, BindingName: b.Members[0].Name, OriginalCreateGrantID: uid, OriginalCreateRequestSHA256: strings.Repeat("a", 64), NonceSHA256: strings.Repeat("b", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, PolicyID: uid, PolicyChecksum: strings.Repeat("c", 64), WorkflowID: uid, WorkflowChecksum: strings.Repeat("d", 64), OriginalWorkflowStepID: b.ProfileManifest.OriginalProvisioningStepID, OriginalWorkflowStepTimeoutSeconds: 420, OriginalWorkflowContextDeadline: now.Add(420 * time.Second), CoreSourceCommit: b.CoreAuthoritySourceCommit, Generation: 1, Fence: 1, LeaseOwner: uid, ExecutorID: uid, Slot: 1, ReservedAt: now, OriginalDeadline: now.Add(420 * time.Second)}
	w := model.CapacityGuestOriginalCreateWitness{Schema: GuestCreateWitnessSchema, BindingName: pre.BindingName, PreregistrationID: uid, PreregistrationNonceSHA256: pre.NonceSHA256, OriginalCreateGrantID: uid, OriginalCreateAttemptID: uid, OriginalCreateRequestSHA256: pre.OriginalCreateRequestSHA256, OriginalCreateSettlementSHA256: strings.Repeat("e", 64), ProfileManifestSHA256: b.ProfileManifestSHA256, BootstrapSHA256: b.ProfileManifest.BootstrapSHA256, CoreSourceCommit: b.CoreAuthoritySourceCommit, OriginalCreateReturnedAt: now.Add(time.Second), ObservedAt: now.Add(2 * time.Second), OriginalDeadline: pre.OriginalDeadline, Tuple: model.CapacityGuestNativeTuple{Provider: "hetzner", Profile: b.ProfileManifest.Profile, Slot: 1, ResourceID: "123", CreatedAt: now.Format(time.RFC3339Nano)}}
	w.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: "123", ResourceCreatedAt: w.Tuple.CreatedAt, Region: "us-east", Location: "ash", TypeID: "22", ImageID: "33", Hostname: "unit-guest", ObservedAt: w.ObservedAt, AdapterSourceCommit: source}
	w.Signature, _ = GuestLifecycleSignature(core, w)
	a := model.CapacityGuestOriginalProfileAuthorityV2{Schema: GuestProfileAuthorityV2Schema, BindingName: pre.BindingName, Slot: 1, GuestBootID: uid, RequestNonceSHA256: strings.Repeat("f", 64), Profile: b.ProfileManifest, Preregistration: pre, CreateWitness: w, RemainingNS: int64(417 * time.Second), ObservedAt: now.Add(3 * time.Second)}
	a.Signature, _ = GuestLifecycleSignature(core, a)
	guest := now.Add(offset)
	c := model.CapacityGuestProductionProvisioningClockV2{Schema: GuestProvisioningClockV2Schema, Authority: a, BootstrapOwnerPID: 123, BootstrapOwnerStartTicks: 456, AcquisitionStartedMonotonicNS: int64(100 * time.Second), AcquisitionExpiresMonotonicNS: int64(520 * time.Second), OriginalReadStartedAt: guest, OriginalReadReturnedAt: guest.Add(time.Second), OriginalReadStartedMonotonicNS: int64(101 * time.Second), OriginalReadReturnedMonotonicNS: int64(102 * time.Second), AcceptedExpiresMonotonicNS: int64(518 * time.Second), OriginalResultReturnedMonotonicNS: int64(110 * time.Second)}
	if err := GuestProductionProvisioningClockV2(p, b, b.Members[0], c, public(core), now.Add(5*time.Second)); err != nil {
		t.Fatal("synthetic clock content invalid", err)
	}
	if GuestOriginalProfileEnabled(p, b, "hetzner") {
		t.Fatal("fixture must not install a production approval")
	}
	return p, b, c, core, producer
}

func TestGuestProductionClockV2SameDomainAndSignature(t *testing.T) {
	for _, offset := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, mode := range []string{"valid", "authority_signature", "witness_signature", "remaining", "authority_future", "expired_core", "boot_shape", "owner", "read_over5", "read_reverse", "acquisition_over420", "expiry_reset", "result_at_expiry", "result_before_read", "guest_wall_reverse", "foreign_profile"} {
			t.Run(offset.String()+"/"+mode, func(t *testing.T) {
				p, b, c, core, _ := productionClockFixture(t, offset)
				now := c.Authority.ObservedAt.Add(time.Second)
				switch mode {
				case "authority_signature":
					c.Authority.Signature = "bad"
				case "witness_signature":
					c.Authority.CreateWitness.Signature = "bad"
				case "remaining":
					c.Authority.RemainingNS++
				case "authority_future":
					now = c.Authority.ObservedAt.Add(-time.Nanosecond)
				case "expired_core":
					c.Authority.ObservedAt = c.Authority.Preregistration.OriginalDeadline
				case "boot_shape":
					c.Authority.GuestBootID = "bad"
				case "owner":
					c.BootstrapOwnerStartTicks = 0
				case "read_over5":
					c.OriginalReadReturnedMonotonicNS = c.OriginalReadStartedMonotonicNS + int64(5*time.Second) + 1
				case "read_reverse":
					c.OriginalReadReturnedMonotonicNS = c.OriginalReadStartedMonotonicNS - 1
				case "acquisition_over420":
					c.AcquisitionExpiresMonotonicNS = c.AcquisitionStartedMonotonicNS + int64(420*time.Second) + 1
				case "expiry_reset":
					c.AcceptedExpiresMonotonicNS++
				case "result_at_expiry":
					c.OriginalResultReturnedMonotonicNS = c.AcceptedExpiresMonotonicNS
				case "result_before_read":
					c.OriginalResultReturnedMonotonicNS = c.OriginalReadReturnedMonotonicNS - 1
				case "guest_wall_reverse":
					c.OriginalReadReturnedAt = c.OriginalReadStartedAt.Add(-time.Nanosecond)
				case "foreign_profile":
					c.Authority.Profile.Profile = "foreign"
				}
				if mode != "authority_signature" {
					c.Authority.Signature = ""
					c.Authority.Signature, _ = GuestLifecycleSignature(core, c.Authority)
				}
				public := base64.StdEncoding.EncodeToString(core.Public().(ed25519.PublicKey))
				if (GuestProductionProvisioningClockV2(p, b, b.Members[0], c, public, now) == nil) != (mode == "valid") {
					t.Fatal("clock ownership or signature changed")
				}
			})
		}
	}
}

func TestGuestProductionClockV2ConservativeWholeExchange(t *testing.T) {
	for _, x := range []struct {
		name                          string
		owner, start, remaining, want int64
		valid                         bool
	}{
		{"request_start", 100, 10, 20, 30, true}, {"original_clips", 25, 10, 20, 25, true}, {"late_start", 25, 24, 20, 25, true}, {"no_time", 10, 10, 20, 0, false}, {"overflow", math.MaxInt64, math.MaxInt64 - 1, 20, 0, false}, {"zero", 100, 10, 0, 0, false}, {"negative", 100, -1, 20, 0, false}, {"over420", math.MaxInt64, 10, int64(420*time.Second) + 1, 0, false},
	} {
		t.Run(x.name, func(t *testing.T) {
			got, e := GuestConservativeProductionExpiry(x.owner, x.start, x.remaining)
			if (e == nil) != x.valid || got != x.want {
				t.Fatal(got, e)
			}
		})
	}
}

func TestGuestProductionClockV2InstallationOriginalReceipt(t *testing.T) {
	for _, offset := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, mode := range []string{"valid", "before_receipt", "late_read", "before_install", "expired", "wrong_clock", "wrong_receipt", "old_schema", "signature", "core_receipt_future", "core_expired"} {
			t.Run(offset.String()+"/"+mode, func(t *testing.T) {
				_, _, original, _, producer := productionClockFixture(t, offset)
				pre := original.Authority.Preregistration
				guest := original.OriginalReadReturnedAt.Add(10 * time.Second)
				receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: pre.PreregistrationID, RecordedAt: original.Authority.ObservedAt.Add(time.Second), Enrollment: model.CapacityGuestRetirementEnrollment{Statement: model.CapacityGuestRetirementEnrollmentStatement{IssuedAt: guest.Add(-time.Second), OriginalProvisioningClockSHA256: GuestRetirementSHA(original)}}}
				x := &model.CapacityGuestProductionInstallationClockV2{Schema: GuestInstallationClockV2Schema, OriginalProvisioningClockSHA256: GuestRetirementSHA(original), OriginalReceiptReadStartedMonotonicNS: int64(111 * time.Second), OriginalReceiptReadReturnedMonotonicNS: int64(112 * time.Second), OriginalReceiptReadReturnedAt: guest, InstalledMonotonicNS: int64(113 * time.Second), AdmittedMonotonicNS: int64(114 * time.Second), OriginalConfirmationPreparedMonotonicNS: int64(115 * time.Second)}
				c := model.CapacityGuestOriginalInstallationConfirmation{Schema: GuestInstallationV2Schema, PreregistrationID: pre.PreregistrationID, OriginalReceiptSHA256: GuestRetirementSHA(receipt), EnrollmentSHA256: GuestRetirementSHA(receipt.Enrollment), InstalledAt: guest.Add(time.Second), AdmittedAt: guest.Add(2 * time.Second), ProductionClock: x}
				now := receipt.RecordedAt.Add(time.Second)
				switch mode {
				case "before_receipt":
					x.InstalledMonotonicNS = x.OriginalReceiptReadReturnedMonotonicNS - 1
				case "late_read":
					x.OriginalReceiptReadReturnedMonotonicNS = x.OriginalReceiptReadStartedMonotonicNS + int64(5*time.Second) + 1
				case "before_install":
					x.AdmittedMonotonicNS = x.InstalledMonotonicNS - 1
				case "expired":
					x.OriginalConfirmationPreparedMonotonicNS = original.AcceptedExpiresMonotonicNS
				case "wrong_clock":
					x.OriginalProvisioningClockSHA256 = strings.Repeat("e", 64)
				case "wrong_receipt":
					c.OriginalReceiptSHA256 = strings.Repeat("e", 64)
				case "old_schema":
					c.Schema = GuestOriginalInstallationSchema
				case "core_receipt_future":
					now = receipt.RecordedAt.Add(-time.Nanosecond)
				case "core_expired":
					now = pre.OriginalDeadline
				}
				c.Signature, _ = GuestLifecycleSignature(producer, c)
				if mode == "signature" {
					c.Signature = "bad"
				}
				pub := base64.StdEncoding.EncodeToString(producer.Public().(ed25519.PublicKey))
				if (GuestOriginalInstallationV2(pre, receipt, c, pub, original, now) == nil) != (mode == "valid") {
					t.Fatal("installation crossed domains or lost original clock")
				}
				if GuestOriginalInstallation(pre, receipt, c, pub, now) == nil {
					t.Fatal("V1 accepted V2")
				}
			})
		}
	}
}

func TestGuestProductionClockV2CrossImportAndExport(t *testing.T) {
	{
		path := "testdata/guest_provisioning_clock_v2_signed_unit.json"
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Scope         string                                           `json:"scope"`
			CorePublicKey string                                           `json:"core_public_key"`
			Clock         model.CapacityGuestProductionProvisioningClockV2 `json:"clock"`
		}
		if json.Unmarshal(raw, &f) != nil || f.Scope != "declared_signed_source_unit_not_native_authority" {
			t.Fatal("foreign fixture scope")
		}
		canonical, err := json.Marshal(f)
		if err != nil || !bytes.Equal(canonical, raw) {
			t.Fatal("Guest/Core canonical DTO fields differ")
		}
		clockRaw, _ := json.Marshal(f.Clock)
		var closed model.CapacityGuestProductionProvisioningClockV2
		if DecodeGuestLifecycle(clockRaw, &closed) != nil || GuestRetirementSHA(closed) != GuestRetirementSHA(f.Clock) {
			t.Fatal("signed production clock does not retain closed original bytes")
		}
		sig := f.Clock.Authority.Signature
		f.Clock.Authority.Signature = ""
		if !guestRetirementVerify(f.CorePublicKey, sig, f.Clock.Authority) {
			t.Fatal("literal Guest DTO signature/order differs")
		}
	}
	if path := os.Getenv("CORE_PROVISIONING_CLOCK_V2_EXPORT"); path != "" {
		_, _, c, key, _ := productionClockFixture(t, 24*time.Hour)
		v := struct {
			Scope         string                                           `json:"scope"`
			CorePublicKey string                                           `json:"core_public_key"`
			Clock         model.CapacityGuestProductionProvisioningClockV2 `json:"clock"`
		}{"synthetic_signed_dto_only_no_native_or_sql_authority", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), c}
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write(raw)
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			t.Fatal(e, closeErr)
		}
	}
}

func TestGuestProductionClockV2InstallationCrossImport(t *testing.T) {
	raw, err := os.ReadFile("testdata/guest_installation_clock_v2_signed_unit.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Scope             string                                              `json:"scope"`
		ProducerPublicKey string                                              `json:"producer_public_key"`
		Clock             model.CapacityGuestProductionProvisioningClockV2    `json:"clock"`
		Receipt           model.CapacityGuestOriginalProvisioningReceipt      `json:"receipt"`
		Confirmation      model.CapacityGuestOriginalInstallationConfirmation `json:"confirmation"`
		CoreNow           time.Time                                           `json:"core_now"`
	}
	if json.Unmarshal(raw, &f) != nil || f.Scope != "declared_signed_installation_unit_not_native_or_sql_authority" {
		t.Fatal("foreign installation fixture")
	}
	canonical, err := json.Marshal(f)
	if err != nil || !bytes.Equal(raw, canonical) {
		t.Fatal("Guest/Core installation DTO field/order differs")
	}
	if GuestOriginalInstallationV2(f.Clock.Authority.Preregistration, f.Receipt, f.Confirmation, f.ProducerPublicKey, f.Clock, f.CoreNow) != nil {
		t.Fatal("actual Guest installation signature rejected")
	}
	f.Confirmation.ProductionClock.InstalledMonotonicNS++
	if GuestOriginalInstallationV2(f.Clock.Authority.Preregistration, f.Receipt, f.Confirmation, f.ProducerPublicKey, f.Clock, f.CoreNow) == nil {
		t.Fatal("signature did not cover the final production clock")
	}
}
