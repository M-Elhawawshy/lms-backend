-- +goose up
CREATE TABLE outbox(
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL, -- kafka topic
    aggregate_type TEXT NOT NULL, -- type of entity involved
    aggregate_id TEXT NOT NULL, -- kafka key
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    published BOOLEAN NOT NULL DEFAULT FALSE
);

-- +goose statementbegin
CREATE OR REPLACE FUNCTION notify_new_outbox_event()
    RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('outbox_channel', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose statementend

CREATE TRIGGER outbox_insert_trigger
    AFTER INSERT ON outbox
    FOR EACH ROW EXECUTE FUNCTION notify_new_outbox_event();

-- +goose down
DROP TRIGGER outbox_insert_trigger ON outbox;
DROP FUNCTION notify_new_outbox_event;
DROP TABLE outbox;