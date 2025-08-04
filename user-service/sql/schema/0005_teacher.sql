-- +goose up
CREATE TABLE IF NOT EXISTS teacher (
    teacher_id UUID PRIMARY KEY REFERENCES "educator"(educator_id) ON DELETE CASCADE
);

-- +goose down
DROP TABLE teacher;