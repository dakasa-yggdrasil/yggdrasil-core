package nativeworkerprobe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProbeProjectionWaitPreservesParentCancellationAndOriginalExpiry(t *testing.T) {
	t.Run("missing_projection_obeys_shorter_parent", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		if waitForProbeProjection(ctx, filepath.Join(t.TempDir(), "absent")) == nil || ctx.Err() == nil {
			t.Fatal("startup wait ignored the original parent deadline")
		}
	})
	t.Run("already_canceled_parent_cannot_load_present_material", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if waitForProbeProjection(ctx, path) == nil {
			t.Fatal("present file revived a canceled startup")
		}
	})
	t.Run("late_expired_material_does_not_receive_new_lifetime", func(t *testing.T) {
		c := testConfig("floor")
		c.NotBefore = time.Now().UTC().Add(-time.Minute)
		c.HardNotAfter = time.Now().UTC().Add(-time.Second)
		hidden, _ := projectedMaterial(t, c)
		published := filepath.Join(t.TempDir(), "published")
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		entered, returned := make(chan struct{}), make(chan error, 1)
		go func() {
			close(entered)
			returned <- waitForProbeProjection(ctx, filepath.Join(published, "revision", "config.json"))
		}()
		<-entered
		if err := os.Rename(hidden, published); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-returned:
			if err != nil {
				t.Fatal("late file was not discovered", err)
			}
		case <-ctx.Done():
			t.Fatal("late projection did not return within the original parent")
		}
		if m, err := loadMaterial(published, fixtureSource, time.Now().UTC()); err == nil || m != nil {
			t.Fatal("late expired config was renewed instead of refused")
		}
		raw, err := os.ReadFile(filepath.Join(published, "revision", "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var actual Config
		if json.Unmarshal(raw, &actual) != nil || !actual.NotBefore.Equal(c.NotBefore) || !actual.HardNotAfter.Equal(c.HardNotAfter) {
			t.Fatal("startup changed immutable configuration timestamps")
		}
	})
	t.Run("present_malformed_material_is_not_a_projection_retry", func(t *testing.T) {
		c := testConfig("floor")
		dir, _ := projectedMaterial(t, c)
		path := filepath.Join(dir, "revision", "config.json")
		if err := os.WriteFile(path, []byte(`{"schema":`), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if waitForProbeProjection(ctx, path) != nil {
			t.Fatal("present malformed file was mistaken for missing projection")
		}
		if m, err := loadMaterial(dir, fixtureSource, time.Now().UTC()); err == nil || m != nil || ctx.Err() != nil {
			t.Fatal("malformed projected bytes did not refuse immediately")
		}
	})
}
