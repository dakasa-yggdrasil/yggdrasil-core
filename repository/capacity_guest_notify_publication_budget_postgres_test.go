package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0093 on real migrated PostgreSQL: the publication budget counts only
// publications with a possible-send row or still inside their own original
// window, so unsent refused attempts (including the production orphans with
// the legacy "notify-maintenance:<hex>" owner) never exhaust the hour, while
// the minimum interval still spaces every attempt. The rows are written with
// session_replication_role=replica inside one rolled-back transaction, which
// skips only FK parents (no enrollment, policy or workflow is fabricated);
// every CHECK constraint of migration 70 still applies. This exercises the
// production budget query only and grants no canary authority.
func TestGuestNotifyPublicationBudgetPostgres(t *testing.T) {
	required := os.Getenv("REQUIRE_GUEST_NOTIFY_CANARY_DB_TEST") == "true"
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if required {
			t.Fatal("required Guest canary DB_URL absent")
		}
		t.Skip("DB_URL absent; no PostgreSQL coverage claimed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal("budget fixture needs a superuser CI database", err)
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC()
	policy, workflow := uuid.NewString(), uuid.NewString()
	legacy := "notify-maintenance:" + strings.Repeat("a", 64)
	insert := func(t *testing.T, pre, phase, record, owner string, recorded, deadline time.Time, sent bool) string {
		t.Helper()
		id := uuid.NewString()
		if phase == "publish" {
			record = id
		}
		schema := capacity.GuestNotifyCanaryPublicationChallengeSchema
		if phase == "read" {
			schema = capacity.GuestNotifyCanaryChallengeSchema
		}
		digest := capacity.BusinessCreationSHA256([]byte("challenge:" + id))
		nonce := capacity.BusinessCreationSHA256([]byte("nonce:" + id))
		if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_challenges(id,preregistration_id,record_challenge_id,phase,policy_id,workflow_id,generation,fence,executor_id,lease_owner,challenge_sha256,nonce_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,10,23,$7,$8,$9,$10,'{}'::bytea,jsonb_build_object('schema',$11::text,'issued_at',$12::timestamptz,'original_deadline',$13::timestamptz),$13,$14)`, id, pre, record, phase, policy, workflow, uuid.NewString(), owner, digest, nonce, schema, deadline.Add(-time.Second), deadline, recorded); err != nil {
			t.Fatal("budget fixture challenge refused", err)
		}
		if sent {
			if _, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_sends(challenge_id,request_sha256,possible_send_at,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$3)`, id, capacity.BusinessCreationSHA256([]byte("send:"+id)), deadline.Add(-500*time.Millisecond), deadline); err != nil {
				t.Fatal("budget fixture send refused", err)
			}
		}
		return id
	}
	// An expired attempt issued at `ago` before now with its 5 s window.
	expired := func(t *testing.T, pre, owner string, ago time.Duration, sent bool) string {
		t.Helper()
		recorded := now.Add(-ago)
		return insert(t, pre, "publish", "", owner, recorded, recorded.Add(4*time.Second), sent)
	}
	binding := func(maximum, interval int) model.CapacityGuestNotifyCanaryBinding {
		return model.CapacityGuestNotifyCanaryBinding{MaximumPublicationsPerHour: maximum, MinimumPublicationIntervalSeconds: interval}
	}
	admittedAt := func(t *testing.T, pre string, b model.CapacityGuestNotifyCanaryBinding, at time.Time) bool {
		t.Helper()
		err := guestNotifyPublicationAdmittedTx(ctx, tx, pre, b, at)
		if err != nil && !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("budget query failed", err)
		}
		return err == nil
	}
	admitted := func(t *testing.T, pre string, b model.CapacityGuestNotifyCanaryBinding) bool {
		t.Helper()
		return admittedAt(t, pre, b, now)
	}

	t.Run("legacy_owner_orphans_do_not_spend_the_hour", func(t *testing.T) {
		pre := uuid.NewString()
		// Fifty refused orphans, the latest 22 minutes ago: past the 15
		// minute backoff ceiling, so only the publication count could refuse.
		for i := 0; i < 50; i++ {
			expired(t, pre, legacy, 59*time.Minute-time.Duration(i)*45*time.Second, false)
		}
		if !admitted(t, pre, binding(3, 10)) {
			t.Fatal("fifty unsent legacy-owner orphans exhausted the publication budget")
		}
	})
	t.Run("sent_publications_spend_the_hour", func(t *testing.T) {
		pre := uuid.NewString()
		expired(t, pre, uuid.NewString(), 50*time.Minute, true)
		expired(t, pre, uuid.NewString(), 40*time.Minute, true)
		if !admitted(t, pre, binding(3, 10)) {
			t.Fatal("two sent publications exhausted a budget of three")
		}
		expired(t, pre, uuid.NewString(), 30*time.Minute, true)
		if admitted(t, pre, binding(3, 10)) {
			t.Fatal("three sent publications did not exhaust a budget of three")
		}
	})
	t.Run("sent_publications_older_than_one_hour_are_free", func(t *testing.T) {
		pre := uuid.NewString()
		for _, ago := range []time.Duration{61 * time.Minute, 62 * time.Minute, 63 * time.Minute} {
			expired(t, pre, uuid.NewString(), ago, true)
		}
		if !admitted(t, pre, binding(3, 10)) {
			t.Fatal("publications older than one hour still spent the budget")
		}
	})
	t.Run("in_flight_unsent_publication_still_counts", func(t *testing.T) {
		pre := uuid.NewString()
		expired(t, pre, uuid.NewString(), 50*time.Minute, true)
		expired(t, pre, uuid.NewString(), 40*time.Minute, true)
		insert(t, pre, "publish", "", uuid.NewString(), now.Add(-time.Second), now.Add(3*time.Second), false)
		if admitted(t, pre, binding(3, 0)) {
			t.Fatal("a publication still inside its original window did not count")
		}
	})
	t.Run("minimum_interval_spaces_every_attempt", func(t *testing.T) {
		pre := uuid.NewString()
		expired(t, pre, uuid.NewString(), 6*time.Second, true)
		if admitted(t, pre, binding(120, 10)) {
			t.Fatal("a sent attempt six seconds ago did not hold a ten-second interval")
		}
		if !admitted(t, pre, binding(120, 5)) {
			t.Fatal("a sent attempt six seconds ago held a five-second interval")
		}
		refused := uuid.NewString()
		expired(t, refused, legacy, 6*time.Second, false)
		if admitted(t, refused, binding(120, 5)) {
			t.Fatal("one refused attempt six seconds ago did not double a five-second interval")
		}
	})
	t.Run("refused_attempts_back_off_exponentially", func(t *testing.T) {
		held, open := uuid.NewString(), uuid.NewString()
		for _, ago := range []time.Duration{100 * time.Second, 70 * time.Second, 30 * time.Second} {
			expired(t, held, uuid.NewString(), ago, false)
		}
		if admitted(t, held, binding(120, 5)) {
			t.Fatal("three refused attempts did not hold a 40-second gap (5 s doubled three times)")
		}
		for _, ago := range []time.Duration{100 * time.Second, 80 * time.Second, 41 * time.Second} {
			expired(t, open, uuid.NewString(), ago, false)
		}
		if !admitted(t, open, binding(120, 5)) {
			t.Fatal("three refused attempts held longer than the 40-second backoff")
		}
	})
	t.Run("a_live_publication_resets_the_refused_streak", func(t *testing.T) {
		pre := uuid.NewString()
		for _, ago := range []time.Duration{10 * time.Minute, 9 * time.Minute, 8 * time.Minute} {
			expired(t, pre, uuid.NewString(), ago, false)
		}
		expired(t, pre, uuid.NewString(), 5*time.Minute, true)
		expired(t, pre, uuid.NewString(), 20*time.Second, false)
		if !admitted(t, pre, binding(120, 5)) {
			t.Fatal("refused attempts before a sent publication still lengthened the backoff")
		}
	})
	t.Run("a_refusing_guest_costs_a_bounded_number_of_attempts_per_hour", func(t *testing.T) {
		pre := uuid.NewString()
		start := now.Add(-2 * time.Hour)
		attempts := 0
		for at := start; at.Before(start.Add(time.Hour)); at = at.Add(time.Second) {
			if admittedAt(t, pre, binding(120, 5), at) {
				attempts++
				insert(t, pre, "publish", "", uuid.NewString(), at, at.Add(4*time.Second), false)
			}
		}
		// 0,10,30,70,150,310,630,1270 s, then every 900 s: ten attempts.
		if attempts < 5 || attempts > 14 {
			t.Fatalf("a Guest refusing every attempt at the 5 s interval cost %d attempts in one hour; want 5..14 (120 before ADR-0093)", attempts)
		}
	})
	t.Run("every_attempt_stays_under_the_fixed_ceiling", func(t *testing.T) {
		pre := uuid.NewString()
		for i := 0; i < guestNotifyPublicationAttemptCeiling-1; i++ {
			expired(t, pre, uuid.NewString(), 59*time.Minute-time.Duration(i)*20*time.Second, false)
		}
		if !admitted(t, pre, binding(120, 0)) {
			t.Fatal("attempts under the fixed ceiling refused with a zero interval")
		}
		expired(t, pre, uuid.NewString(), 10*time.Second, false)
		if admitted(t, pre, binding(120, 0)) {
			t.Fatal("the fixed all-attempt ceiling did not hold")
		}
	})
	t.Run("reads_and_other_members_are_ignored", func(t *testing.T) {
		pre, other := uuid.NewString(), uuid.NewString()
		publish := expired(t, pre, uuid.NewString(), 50*time.Minute, true)
		recorded := now.Add(-49 * time.Minute)
		insert(t, pre, "read", publish, uuid.NewString(), recorded, recorded.Add(3*time.Second), true)
		insert(t, pre, "read", publish, uuid.NewString(), recorded.Add(time.Minute), recorded.Add(time.Minute+3*time.Second), true)
		for _, ago := range []time.Duration{30 * time.Minute, 20 * time.Minute, 10 * time.Minute} {
			expired(t, other, uuid.NewString(), ago, true)
		}
		if !admitted(t, pre, binding(2, 10)) {
			t.Fatal("read challenges or another member's publications spent this member's budget")
		}
		if admitted(t, other, binding(3, 10)) {
			t.Fatal("the other member's three sent publications did not exhaust its own budget")
		}
	})
}
