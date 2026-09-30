-- +goose NO TRANSACTION
-- +goose Up
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_at_idx ON audit_log (at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_topic_idx ON outbox (topic);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS outbox_topic_idx;
DROP INDEX CONCURRENTLY IF EXISTS audit_log_at_idx;
