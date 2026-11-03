package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"io"
	"strings"
	"testing"
	"time"
)

// This deliberately tiny SQL driver exercises the real store/load functions,
// not a second implementation of their acceptance rules. It does not claim to
// test PostgreSQL scope locks, triggers, or the outer policy/auth transaction.
type installationDB struct {
	wire             []byte
	digest           string
	recorded         time.Time
	inserts, queries int
}
type installationConnector struct{ s *installationDB }

func (c installationConnector) Connect(context.Context) (driver.Conn, error) {
	return &installationConn{c.s}, nil
}
func (c installationConnector) Driver() driver.Driver { return installationDriver(c) }

type installationDriver struct{ s *installationDB }

func (d installationDriver) Open(string) (driver.Conn, error) { return &installationConn{d.s}, nil }

type installationConn struct{ s *installationDB }

func (c *installationConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *installationConn) Close() error              { return nil }
func (c *installationConn) Begin() (driver.Tx, error) { return installationTx{}, nil }
func (c *installationConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return installationTx{}, nil
}

type installationTx struct{}

func (installationTx) Commit() error   { return nil }
func (installationTx) Rollback() error { return nil }

type installationRows struct {
	cols []string
	vals []driver.Value
	read bool
}

func (r *installationRows) Columns() []string { return r.cols }
func (r *installationRows) Close() error      { return nil }
func (r *installationRows) Next(v []driver.Value) error {
	if r.read || r.vals == nil {
		return io.EOF
	}
	r.read = true
	copy(v, r.vals)
	return nil
}
func (c *installationConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(q, "FROM public.capacity_guest_original_installations") || !strings.Contains(q, "FOR SHARE") {
		return nil, errors.New("unexpected query")
	}
	c.s.queries++
	cols := []string{"original_wire"}
	vals := []driver.Value{c.s.wire}
	if strings.Contains(q, "confirmation_sha256,") {
		cols = append(cols, "confirmation_sha256", "recorded_at")
		vals = append(vals, c.s.digest, c.s.recorded)
	}
	if c.s.wire == nil {
		vals = nil
	}
	return &installationRows{cols: cols, vals: vals}, nil
}
func (c *installationConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.HasPrefix(q, "INSERT INTO public.capacity_guest_original_installations") || len(args) != 4 {
		return nil, errors.New("unexpected write")
	}
	if c.s.wire != nil {
		return nil, errors.New("duplicate SQL write")
	}
	c.s.inserts++
	c.s.wire = append([]byte{}, args[1].Value.([]byte)...)
	c.s.digest = args[2].Value.(string)
	c.s.recorded = args[3].Value.(time.Time)
	return driver.RowsAffected(1), nil
}
func TestGuestInstallationImmutableStoreAndProbeRead(t *testing.T) {
	now := time.Now().UTC()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	stored := guestOriginalStored{pre: model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID: "2a57e5da-3163-4235-9b08-e68415889fdb", OriginalDeadline: now.Add(time.Minute)}, binding: model.CapacityGuestRetirementBinding{ProvisionerPublicKey: base64.StdEncoding.EncodeToString(pub)}}
	receipt := model.CapacityGuestOriginalProvisioningReceipt{PreregistrationID: stored.pre.PreregistrationID, RecordedAt: now.Add(-time.Second)}
	confirmation := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestOriginalInstallationSchema, PreregistrationID: stored.pre.PreregistrationID, OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), InstalledAt: now.Add(-time.Millisecond * 500), AdmittedAt: now.Add(-time.Millisecond * 100)}
	confirmation.Signature, _ = capacity.GuestLifecycleSignature(key, confirmation)
	state := &installationDB{}
	db := sql.OpenDB(installationConnector{state})
	defer db.Close()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = loadGuestInstallationTx(context.Background(), tx, stored, receipt); !errors.Is(err, sql.ErrNoRows) || state.inserts != 0 {
		t.Fatal("pending state reserved or invented installation")
	}
	if _, err = storeGuestInstallationTx(context.Background(), tx, stored, receipt, confirmation, now); err != nil || state.inserts != 1 {
		t.Fatal("original confirmation failed", err)
	}
	if _, err = storeGuestInstallationTx(context.Background(), tx, stored, receipt, confirmation, now); err != nil || state.inserts != 1 {
		t.Fatal("exact duplicate mutated")
	}
	other := confirmation
	other.AdmittedAt = other.AdmittedAt.Add(time.Nanosecond)
	other.Signature = ""
	other.Signature, _ = capacity.GuestLifecycleSignature(key, other)
	if _, err = storeGuestInstallationTx(context.Background(), tx, stored, receipt, other, now); err == nil || state.inserts != 1 {
		t.Fatal("conflicting confirmation accepted")
	}
	if _, err = storeGuestInstallationTx(context.Background(), tx, stored, receipt, confirmation, stored.pre.OriginalDeadline); err == nil {
		t.Fatal("late duplicate accepted")
	}
	if _, err = loadGuestInstallationTx(context.Background(), tx, stored, receipt); err != nil {
		t.Fatal("confirmed original unavailable", err)
	}
	// A later read authenticates its original record time; it does not renew it.
	state.recorded = stored.pre.OriginalDeadline
	if _, err = loadGuestInstallationTx(context.Background(), tx, stored, receipt); err == nil {
		t.Fatal("late database record accepted")
	}
	state.recorded = now
	state.digest = capacity.GuestRetirementSHA("corrupt")
	if _, err = loadGuestInstallationTx(context.Background(), tx, stored, receipt); err == nil {
		t.Fatal("corrupt immutable record accepted")
	}
}
