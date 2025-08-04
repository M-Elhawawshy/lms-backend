-- name: CreateAssistant :one
INSERT INTO assistant(assistant_id)
VALUES ($1)
returning *;