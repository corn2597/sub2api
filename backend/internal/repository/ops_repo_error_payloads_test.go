package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func testPayloadSHA(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func TestInsertErrorPayloadCapturePreservesFullBytesAndDeduplicatesBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &opsRepository{db: db}

	httpPayload := make([]byte, 2*1024*1024+17)
	for i := range httpPayload {
		httpPayload[i] = byte(i % 251)
	}
	wsPayload := append([]byte(`{"type":"response.create","input":"`), httpPayload...)
	wsPayload = append(wsPayload, []byte(`"}`)...)
	httpSHA := testPayloadSHA(httpPayload)
	wsSHA := testPayloadSHA(wsPayload)
	createdAt := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	capture := &service.OpsErrorPayloadCaptureSnapshot{
		HTTPPayload: httpPayload,
		HTTPSHA256:  httpSHA,
		CreatedAt:   createdAt,
		WSPayloads:  map[string][]byte{wsSHA: wsPayload},
		WSAttempts: []*service.OpsErrorWSPayloadAttempt{
			{SequenceNo: 1, PayloadSHA256: wsSHA, AttemptNo: 1, AccountID: 23, ConnID: "oa_ws_1", WriteSucceeded: true, CreatedAt: createdAt},
			{SequenceNo: 2, PayloadSHA256: wsSHA, AttemptNo: 2, AccountID: 23, ConnID: "oa_ws_1", ConnectionReused: true, WriteError: "write failed", CreatedAt: createdAt.Add(time.Second)},
		},
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO ops_error_payload_blobs (")).
		WithArgs("rid-full", "http", httpSHA, int64(len(httpPayload)), httpPayload, createdAt).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(101))
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO ops_error_payload_blobs (")).
		WithArgs("rid-full", "ws", wsSHA, int64(len(wsPayload)), wsPayload, createdAt).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(102))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO ops_error_payload_attempts (")).
		WithArgs("rid-full", 1, int64(102), 1, int64(23), "oa_ws_1", false, true, nil, createdAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO ops_error_payload_attempts (")).
		WithArgs("rid-full", 2, int64(102), 2, int64(23), "oa_ws_1", true, false, "write failed", createdAt.Add(time.Second)).
		WillReturnResult(sqlmock.NewResult(2, 1))
	mock.ExpectCommit()

	require.NoError(t, repo.InsertErrorPayloadCapture(context.Background(), "rid-full", capture))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetErrorPayloadContentRequiresMatchingErrorRequest(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	repo := &opsRepository{db: db}
	payload := []byte(`{"type":"response.create","input":"exact"}`)
	sha := testPayloadSHA(payload)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT p.id, p.payload_kind, p.payload_sha256, p.payload_bytes, p.payload_data")).
		WithArgs(int64(9), int64(12)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "payload_kind", "payload_sha256", "payload_bytes", "payload_data"}).
			AddRow(12, "ws", sha, len(payload), payload))

	got, err := repo.GetErrorPayloadContent(context.Background(), 9, 12)
	require.NoError(t, err)
	require.Equal(t, payload, got.Data)
	require.Equal(t, int64(len(payload)), got.PayloadBytes)
	require.Equal(t, sha, got.SHA256)
	require.NoError(t, mock.ExpectationsWereMet())
}
