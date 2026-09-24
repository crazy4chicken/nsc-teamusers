package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"

	"nsc-teamusers/internal/config"
	"nsc-teamusers/internal/store"
)

const (
	defaultPollInterval = 2 * time.Second
	outboxBatchSize     = 1000
)

var natsSubjects = map[string]string{
	"perm.changed":  "iam.perm.changed",
	"user.disabled": "iam.user.disabled",
	"role.updated":  "iam.role.updated",
	"key.rotated":   "iam.key.rotated",
}

// Relay publishes unpublished non-webhook outbox events to JetStream. Rows
// remain unpublished when a publish fails, so a later poll retries them.
type Relay struct {
	q            store.Q
	natsURL      string
	logger       *slog.Logger
	pollInterval time.Duration
}

// NewRelay constructs an outbox relay. An empty NATS URL enables development
// mode, where supported events are acknowledged without a broker.
func NewRelay(q store.Q, cfg config.Config, logger *slog.Logger) *Relay {
	if logger == nil {
		logger = slog.Default()
	}
	return &Relay{
		q:            q,
		natsURL:      cfg.NATSURL,
		logger:       logger,
		pollInterval: defaultPollInterval,
	}
}

// Run polls the outbox until ctx is canceled.
func (r *Relay) Run(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	var conn *nats.Conn
	var js nats.JetStreamContext
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := r.publishBatch(ctx, &conn, &js); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("outbox relay poll failed", "error", err)
		}
		timer := time.NewTimer(r.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (r *Relay) publishBatch(ctx context.Context, conn **nats.Conn, js *nats.JetStreamContext) error {
	cursor := int64(0)
	for {
		events, nextCursor, err := store.FetchUnpublishedOutbox(ctx, r.q, cursor, outboxBatchSize)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		if err := r.publishEvents(ctx, events, conn, js); err != nil {
			return err
		}
		if nextCursor == 0 {
			return nil
		}
		cursor = nextCursor
	}
}

func (r *Relay) publishEvents(ctx context.Context, events []store.OutboxEvent, conn **nats.Conn, js *nats.JetStreamContext) error {
	if r.natsURL == "" {
		ids := make([]int64, 0, len(events))
		for _, event := range events {
			if _, ok := natsSubjects[event.Topic]; !ok {
				continue
			}
			ids = append(ids, event.ID)
		}
		if err := store.MarkOutboxPublished(ctx, r.q, ids, time.Time{}); err != nil {
			return err
		}
		if len(ids) > 0 {
			r.logger.Debug("acknowledged outbox events without NATS", "count", len(ids), "mode", "dev")
		}
		return nil
	}

	if err := r.ensureJetStream(conn, js); err != nil {
		return err
	}
	published := make([]int64, 0, len(events))
	for _, event := range events {
		subject, ok := natsSubjects[event.Topic]
		if !ok {
			continue
		}
		payload, err := relayPayload(event)
		if err != nil {
			r.logger.Error("invalid outbox payload", "event_id", event.ID, "topic", event.Topic, "error", err)
			continue
		}
		if _, err := (*js).Publish(subject, payload); err != nil {
			if *conn != nil && (*conn).IsClosed() {
				(*conn).Close()
				*conn = nil
				*js = nil
			}
			r.logger.Error("publish outbox event failed", "event_id", event.ID, "topic", event.Topic, "subject", subject, "error", err)
			continue
		}
		published = append(published, event.ID)
	}
	return store.MarkOutboxPublished(ctx, r.q, published, time.Time{})
}

func (r *Relay) ensureJetStream(conn **nats.Conn, js *nats.JetStreamContext) error {
	if *conn != nil && !(*conn).IsClosed() && *js != nil {
		return nil
	}
	if *conn != nil {
		(*conn).Close()
		*conn = nil
		*js = nil
	}
	connected, err := nats.Connect(
		r.natsURL,
		nats.Name("nsc-teamusers-outbox-relay"),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	jetstream, err := connected.JetStream()
	if err != nil {
		connected.Close()
		return fmt.Errorf("initialize NATS JetStream: %w", err)
	}
	*conn = connected
	*js = jetstream
	return nil
}

func relayPayload(event store.OutboxEvent) ([]byte, error) {
	payload := make(map[string]any)
	if len(event.Payload) > 0 {
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return nil, err
		}
	}
	if payload == nil {
		payload = make(map[string]any)
	}
	payload["event_id"] = event.ID
	if _, ok := payload["type"]; !ok {
		payload["type"] = event.Topic
	}
	if _, ok := payload["user_ids"]; !ok {
		payload["user_ids"] = []string{}
	}
	if _, ok := payload["team_id"]; !ok {
		payload["team_id"] = nil
	}
	if _, ok := payload["at"]; !ok {
		payload["at"] = time.Now().UTC()
	}
	return json.Marshal(payload)
}
