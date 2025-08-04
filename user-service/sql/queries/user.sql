-- name: CreateUser :one
INSERT INTO "user"(user_id, password_hash, user_type)
VALUES ($1, $2, $3)
RETURNING *;

-- name: CreatePhone :one
INSERT INTO phone_number(phone_number, user_id)
VALUES ($1, $2)
RETURNING *;

-- name: PhoneExists :one
SELECT TRUE
FROM phone_number
WHERE phone_number = $1;

-- name: GetUserIDByPhone :one
SELECT user_id
FROM phone_number
WHERE phone_number.phone_number = $1;

-- name: CreateName :one
INSERT INTO name(user_id, first_name, middle_name, last_name)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUser :one
SELECT * from "user"
WHERE user_id = $1;