-- name: CreateTeacher :one
INSERT INTO teacher(teacher_id)
VALUES ($1)
RETURNING *;