package service

import (
	"context"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestOpsCleanupPlan(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		days         int
		wantOK       bool
		wantTruncate bool
		wantCutoff   time.Time
	}{
		{name: "negative skips", days: -1, wantOK: false},
		{name: "zero truncates", days: 0, wantOK: true, wantTruncate: true},
		{name: "positive yields past cutoff", days: 7, wantOK: true, wantCutoff: now.AddDate(0, 0, -7)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cutoff, truncate, ok := opsCleanupPlan(now, tc.days)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if truncate != tc.wantTruncate {
				t.Fatalf("truncate = %v, want %v", truncate, tc.wantTruncate)
			}
			if !tc.wantTruncate && !cutoff.Equal(tc.wantCutoff) {
				t.Fatalf("cutoff = %v, want %v", cutoff, tc.wantCutoff)
			}
		})
	}
}

func TestIsMissingRelationError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil is not missing", err: nil, want: false},
		{name: "match relation does not exist", err: fakeErr(`pq: relation "ops_error_logs" does not exist`), want: true},
		{name: "match case-insensitive", err: fakeErr(`ERROR: Relation "x" Does Not Exist`), want: true},
		{name: "non-matching error", err: fakeErr("connection refused"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMissingRelationError(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

type timeWithin struct {
	target    time.Time
	tolerance time.Duration
}

func (m timeWithin) Match(value driver.Value) bool {
	got, ok := value.(time.Time)
	if !ok {
		return false
	}
	delta := got.Sub(m.target)
	if delta < 0 {
		delta = -delta
	}
	return delta <= m.tolerance
}

func TestRunErrorPayloadCleanupOnceUsesIndependentHourlyRetention(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.ErrorPayloadRetentionHours = 72
	svc := &OpsCleanupService{db: db, cfg: cfg}
	wantCutoff := time.Now().UTC().Add(-72 * time.Hour)
	cutoff := timeWithin{target: wantCutoff, tolerance: 5 * time.Second}
	mock.ExpectExec("DELETE FROM ops_error_payload_blobs").
		WithArgs(cutoff, opsCleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec("DELETE FROM ops_error_payload_blobs").
		WithArgs(cutoff, opsCleanupBatchSize).
		WillReturnResult(sqlmock.NewResult(0, 0))

	deleted, err := svc.runErrorPayloadCleanupOnce(context.Background())
	if err != nil {
		t.Fatalf("runErrorPayloadCleanupOnce: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestApplyScheduleKeepsPayloadCleanupWhenMetadataCleanupDisabled(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.ErrorPayloadRetentionHours = 72
	cfg.Ops.Cleanup.Enabled = false
	svc := &OpsCleanupService{db: db, cfg: cfg}

	if err := svc.applyScheduleLocked(context.Background()); err != nil {
		t.Fatalf("applyScheduleLocked: %v", err)
	}
	defer svc.stopCronLocked()
	if svc.cron == nil {
		t.Fatal("payload cleanup cron was not created")
	}
	entries := svc.cron.Entries()
	if len(entries) != 1 {
		t.Fatalf("cron entries = %d, want payload-only entry", len(entries))
	}
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
