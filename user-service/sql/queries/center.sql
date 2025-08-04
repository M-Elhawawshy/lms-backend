-- name: CreateCenter :one
INSERT INTO center(center_id, owner_name, logo_url, location)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: CreateEmptyCenter :one
INSERT INTO center(center_id)
VALUES ($1)
RETURNING *;