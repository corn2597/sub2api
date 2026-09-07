package repository

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *opsRepository) InsertErrorPayloadCapture(
	ctx context.Context,
	requestID string,
	capture *service.OpsErrorPayloadCaptureSnapshot,
) (err error) {
	if r == nil || r.db == nil {
		return fmt.Errorf("nil ops repository")
	}
	requestID = strings.TrimSpace(requestID)
	if requestID == "" || capture == nil || len(capture.HTTPPayload) == 0 {
		return fmt.Errorf("invalid error payload capture")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	createdAt := capture.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	if _, err = upsertOpsErrorPayloadBlob(
		ctx, tx, requestID, "http", capture.HTTPSHA256, capture.HTTPPayload, createdAt,
	); err != nil {
		return err
	}

	shaValues := make([]string, 0, len(capture.WSPayloads))
	for sha := range capture.WSPayloads {
		shaValues = append(shaValues, sha)
	}
	sort.Strings(shaValues)
	payloadIDs := make(map[string]int64, len(shaValues))
	for _, sha := range shaValues {
		payload := capture.WSPayloads[sha]
		if len(payload) == 0 {
			continue
		}
		payloadID, insertErr := upsertOpsErrorPayloadBlob(ctx, tx, requestID, "ws", sha, payload, createdAt)
		if insertErr != nil {
			return insertErr
		}
		payloadIDs[sha] = payloadID
	}

	const insertAttemptSQL = `
INSERT INTO ops_error_payload_attempts (
  request_id, sequence_no, payload_id, attempt_no, account_id, conn_id,
  connection_reused, write_succeeded, write_error, created_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (request_id, sequence_no) DO NOTHING`
	for _, attempt := range capture.WSAttempts {
		if attempt == nil || attempt.SequenceNo <= 0 || attempt.AttemptNo <= 0 {
			continue
		}
		payloadID := payloadIDs[attempt.PayloadSHA256]
		if payloadID <= 0 {
			return fmt.Errorf("missing ws payload for attempt sequence %d", attempt.SequenceNo)
		}
		attemptAt := attempt.CreatedAt
		if attemptAt.IsZero() {
			attemptAt = createdAt
		}
		if _, err = tx.ExecContext(
			ctx,
			insertAttemptSQL,
			requestID,
			attempt.SequenceNo,
			payloadID,
			attempt.AttemptNo,
			opsNullablePositiveInt64(attempt.AccountID),
			opsNullString(attempt.ConnID),
			attempt.ConnectionReused,
			attempt.WriteSucceeded,
			opsNullString(attempt.WriteError),
			attemptAt,
		); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func upsertOpsErrorPayloadBlob(
	ctx context.Context,
	tx *sql.Tx,
	requestID, kind, sha string,
	payload []byte,
	createdAt time.Time,
) (int64, error) {
	if tx == nil || requestID == "" || kind == "" || sha == "" {
		return 0, fmt.Errorf("invalid ops error payload blob")
	}
	const query = `
INSERT INTO ops_error_payload_blobs (
  request_id, payload_kind, payload_sha256, payload_bytes, payload_data, created_at
) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (request_id, payload_kind, payload_sha256)
DO UPDATE SET payload_bytes = EXCLUDED.payload_bytes,
              payload_data = EXCLUDED.payload_data
RETURNING id`
	var id int64
	if err := tx.QueryRowContext(
		ctx, query, requestID, kind, sha, int64(len(payload)), payload, createdAt,
	).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func opsNullablePositiveInt64(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func (r *opsRepository) listErrorPayloadMetadata(
	ctx context.Context,
	requestID string,
) ([]*service.OpsErrorPayloadMetadata, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT id, payload_kind, payload_sha256, payload_bytes, created_at
FROM ops_error_payload_blobs
WHERE request_id = $1
ORDER BY CASE payload_kind WHEN 'http' THEN 0 ELSE 1 END, id`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*service.OpsErrorPayloadMetadata, 0, 4)
	byID := make(map[int64]*service.OpsErrorPayloadMetadata)
	for rows.Next() {
		item := &service.OpsErrorPayloadMetadata{}
		if err := rows.Scan(&item.ID, &item.Kind, &item.SHA256, &item.PayloadBytes, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
		byID[item.ID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return items, nil
	}

	attemptRows, err := r.db.QueryContext(ctx, `
SELECT payload_id, sequence_no, attempt_no, account_id, COALESCE(conn_id, ''),
       connection_reused, write_succeeded, COALESCE(write_error, ''), created_at
FROM ops_error_payload_attempts
WHERE request_id = $1
ORDER BY sequence_no`, requestID)
	if err != nil {
		return nil, err
	}
	defer attemptRows.Close()
	for attemptRows.Next() {
		var payloadID int64
		var accountID sql.NullInt64
		attempt := &service.OpsErrorPayloadAttemptMetadata{}
		if err := attemptRows.Scan(
			&payloadID,
			&attempt.SequenceNo,
			&attempt.AttemptNo,
			&accountID,
			&attempt.ConnID,
			&attempt.ConnectionReused,
			&attempt.WriteSucceeded,
			&attempt.WriteError,
			&attempt.CreatedAt,
		); err != nil {
			return nil, err
		}
		if accountID.Valid {
			value := accountID.Int64
			attempt.AccountID = &value
		}
		if item := byID[payloadID]; item != nil {
			item.Attempts = append(item.Attempts, attempt)
		}
	}
	if err := attemptRows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *opsRepository) GetErrorPayloadContent(
	ctx context.Context,
	errorID, payloadID int64,
) (*service.OpsErrorPayloadContent, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("nil ops repository")
	}
	if errorID <= 0 || payloadID <= 0 {
		return nil, fmt.Errorf("invalid error payload id")
	}
	const query = `
SELECT p.id, p.payload_kind, p.payload_sha256, p.payload_bytes, p.payload_data
FROM ops_error_payload_blobs p
JOIN ops_error_logs e ON e.request_id = p.request_id
WHERE e.id = $1 AND p.id = $2
LIMIT 1`
	out := &service.OpsErrorPayloadContent{}
	if err := r.db.QueryRowContext(ctx, query, errorID, payloadID).Scan(
		&out.ID, &out.Kind, &out.SHA256, &out.PayloadBytes, &out.Data,
	); err != nil {
		return nil, err
	}
	return out, nil
}
