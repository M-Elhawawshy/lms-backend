-- name: CreateEducator :one
INSERT INTO educator(educator_id, educator_type)
VALUES ($1, $2)
RETURNING *;