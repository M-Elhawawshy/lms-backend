-- +goose up
CREATE TABLE IF NOT EXISTS student (
    student_id UUID PRIMARY KEY REFERENCES "user"(user_id) ON DELETE CASCADE,
    parent_phone varchar(20) NOT NULL UNIQUE
);

-- +goose down
DROP TABLE student;