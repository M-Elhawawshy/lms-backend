-- name: InsertEvent :one
INSERT INTO outbox(id, event_type, aggregate_type, aggregate_id, payload)
VALUES($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUnpublishedEvents :many
SELECT * FROM outbox
WHERE published IS FALSE
ORDER BY created_at
LIMIT 100;

-- name: SetEventAsPublished :exec
UPDATE outbox
SET published = TRUE, published_at = NOW()
WHERE id = $1;