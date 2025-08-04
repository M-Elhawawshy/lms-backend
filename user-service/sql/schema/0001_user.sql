-- +goose up
CREATE TABLE IF NOT EXISTS "user" (
    user_id UUID PRIMARY KEY,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    user_type TEXT NOT NULL CHECK (user_type IN ('center', 'student', 'teacher', 'assistant'))
);

CREATE TABLE phone_number (
    phone_number VARCHAR(20) PRIMARY KEY,
    user_id UUID REFERENCES "user"(user_id)

);

CREATE TABLE name (
    user_id UUID PRIMARY KEY REFERENCES "user"(user_id) ON DELETE CASCADE,
    first_name VARCHAR(50) NOT NULL,
    middle_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL
);

-- +goose down
DROP TABLE name;
DROP TABLE phone_number;
DROP TABLE "user";
