package capacity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
	"time"
)

func installationFixture(t *testing.T) (model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation, ed25519.PrivateKey, string, time.Time) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	pre := model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: "2a57e5da-3163-4235-9b08-e68415889fdb", OriginalDeadline: now.Add(time.Minute)}
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: pre.PreregistrationID, RecordedAt: now.Add(-time.Second)}
	c := model.CapacityGuestOriginalInstallationConfirmation{Schema: GuestOriginalInstallationSchema, PreregistrationID: pre.PreregistrationID, OriginalReceiptSHA256: GuestRetirementSHA(receipt), EnrollmentSHA256: GuestRetirementSHA(receipt.Enrollment), InstalledAt: now.Add(-time.Millisecond * 500), AdmittedAt: now.Add(-time.Millisecond * 100)}
	c.Signature, _ = GuestLifecycleSignature(key, c)
	return pre, receipt, c, key, base64.StdEncoding.EncodeToString(pub), now
}
func TestGuestOriginalInstallationAuthentication(t *testing.T) {
	for _, kind := range []string{"success", "early", "late", "duplicate", "foreign_id", "old_receipt", "old_enrollment", "wrong_key", "missing", "future", "unordered", "old_schema"} {
		t.Run(kind, func(t *testing.T) {
			pre, r, c, key, pub, now := installationFixture(t)
			valid := kind == "success" || kind == "duplicate"
			switch kind {
			case "early":
				c.InstalledAt = r.RecordedAt.Add(-time.Nanosecond)
			case "late":
				now = pre.OriginalDeadline
			case "foreign_id":
				c.PreregistrationID = "other"
			case "old_receipt":
				c.OriginalReceiptSHA256 = GuestRetirementSHA("old")
			case "old_enrollment":
				c.EnrollmentSHA256 = GuestRetirementSHA("old")
			case "wrong_key":
				other, _, _ := ed25519.GenerateKey(rand.Reader)
				pub = base64.StdEncoding.EncodeToString(other)
			case "missing":
				c.Schema = ""
			case "future":
				c.AdmittedAt = now.Add(time.Second)
			case "unordered":
				c.AdmittedAt = c.InstalledAt.Add(-time.Nanosecond)
			case "old_schema":
				c.Schema = "guest_original_registration_v1"
			}
			c.Signature = ""
			c.Signature, _ = GuestLifecycleSignature(key, c)
			if (GuestOriginalInstallation(pre, r, c, pub, now) == nil) != valid {
				t.Fatal("wrong admission")
			}
			if kind == "duplicate" && GuestOriginalInstallation(pre, r, c, pub, now) != nil {
				t.Fatal("same exact confirmation changed")
			}
		})
	}
}
func TestGuestInstallationBarrierInterleavings(t *testing.T) {
	for _, kind := range []string{"success", "install_failed", "identity_refused", "timeout", "cancel_after_read"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ticks := make(chan time.Time)
			readSeen := make(chan int, 2)
			release := make(chan struct{})
			done := make(chan error, 1)
			reads := 0
			reserved := false
			go func() {
				_, err := AwaitGuestOriginalInstallation(ctx, ticks, func(context.Context) (model.CapacityGuestOriginalProvisioningReceipt, bool, error) {
					reads++
					readSeen <- reads
					if reads == 1 {
						return model.CapacityGuestOriginalProvisioningReceipt{}, false, nil
					}
					<-release
					if kind == "identity_refused" {
						return model.CapacityGuestOriginalProvisioningReceipt{}, false, errors.New("refused")
					}
					if kind == "cancel_after_read" {
						cancel()
					}
					return model.CapacityGuestOriginalProvisioningReceipt{}, true, nil
				})
				if err == nil {
					reserved = true
				}
				done <- err
			}()
			<-readSeen
			select {
			case <-done:
				t.Fatal("probe advanced before installation")
			default:
			}
			if kind == "timeout" || kind == "install_failed" {
				cancel()
			} else {
				ticks <- time.Now()
				<-readSeen
				close(release)
			}
			err := <-done
			if kind == "success" {
				if err != nil || !reserved {
					t.Fatal("confirmed original did not pass")
				}
			} else if err == nil || reserved {
				t.Fatal("refused original reserved probe")
			}
		})
	}
}
