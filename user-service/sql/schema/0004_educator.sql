-- +goose up
CREATE TABLE IF NOT EXISTS educator (
    educator_id UUID PRIMARY KEY REFERENCES "user"(user_id) ON DELETE CASCADE,
    educator_type TEXT NOT NULL CHECK (educator_type in ('teacher', 'assistant'))
);

-- +goose down
DROP TABLE educator;