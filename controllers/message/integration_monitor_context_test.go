package message

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type monitorProbeConnector struct {
	started, canceled, release chan struct{}
	queries                    atomic.Int32
}

func (c *monitorProbeConnector) Connect(context.Context) (driver.Conn, error) {
	return &monitorProbeConn{c}, nil
}
func (c *monitorProbeConnector) Driver() driver.Driver { return monitorProbeDriver{} }

type monitorProbeDriver struct{}

func (monitorProbeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type monitorProbeConn struct{ connector *monitorProbeConnector }

func (*monitorProbeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*monitorProbeConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (*monitorProbeConn) Close() error                        { return nil }
func (c *monitorProbeConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	c.connector.queries.Add(1)
	close(c.connector.started)
	<-ctx.Done()
	close(c.connector.canceled)
	// Keep the probe alive after cancellation to distinguish cancel from join.
	<-c.connector.release
	return nil, ctx.Err()
}

func TestIntegrationRuntimeMonitorStopCancelsAndJoinsActiveProbe(t *testing.T) {
	connector := &monitorProbeConnector{started: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
	db := sql.OpenDB(connector)
	defer db.Close()
	stop := StartIntegrationRuntimeMonitorWithContext(context.Background(), nil, db, nil, time.Hour)
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("monitor event not observed")
		}
	}
	wait(connector.started)
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	wait(connector.canceled)
	select {
	case <-done:
		t.Fatal("monitor stop returned while its probe still ran")
	default:
	}
	close(connector.release)
	wait(done)
	stop() // joining twice is safe and never starts another probe.
	if connector.queries.Load() != 1 {
		t.Fatalf("extra probe after stop: %d", connector.queries.Load())
	}
}
