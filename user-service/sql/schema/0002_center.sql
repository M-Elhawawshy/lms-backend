-- +goose up
CREATE TABLE IF NOT EXISTS center (
    center_id UUID PRIMARY KEY REFERENCES "user"(user_id) ON DELETE CASCADE,
    owner_name VARCHAR(50),
    logo_url TEXT,
    location TEXT
);

-- +goose down
DROP TABLE center;