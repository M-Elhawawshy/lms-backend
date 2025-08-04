-- name: CreateStudent :one
INSERT INTO student(student_id, parent_phone)
VALUES($1, $2)
RETURNING *;
