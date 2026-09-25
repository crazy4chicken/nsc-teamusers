package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

const (
	notificationHTTPTimeout = 5 * time.Second
	notificationMaxAttempts = 4 // initial delivery plus three retries
)

var notificationRetryBackoff = [...]time.Duration{time.Second, 4 * time.Second, 15 * time.Second}

// Notifier delivers notification directives from the outbox to every configured
// notification service endpoint. A directive can represent a user.created
// welcome email or a session.reuse_detected security alert. This is not a
// general-purpose event bus: this service alone decides what constitutes a
// notification and when to emit it. The notification service owns actual
// email/SMS delivery, while failed rows remain unpublished for a later poll.
type Notifier struct {
	q            store.Q
	endpoints    []string
	secret       string
	client       *http.Client
	logger       *slog.Logger
	pollInterval time.Duration
}

// NewNotifier constructs a notification-service integration from process configuration.
func NewNotifier(q store.Q, cfg config.Config, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}
	endpoints := make([]string, 0, len(cfg.NotificationEndpoints))
	for _, endpoint := range cfg.NotificationEndpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return &Notifier{
		q:            q,
		endpoints:    endpoints,
		secret:       cfg.NotificationSecret,
		client:       &http.Client{Timeout: notificationHTTPTimeout},
		logger:       logger,
		pollInterval: defaultPollInterval,
	}
}

// Run polls the notification outbox until ctx is canceled. Notification delivery is
// best-effort at-least-once: a final delivery failure leaves the row pending.
func (d *Notifier) Run(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := d.dispatchBatch(ctx); err != nil && !errors.Is(err, context.Canceled) {
			d.logger.Error("notification notifier poll failed", "error", err)
		}
		timer := time.NewTimer(d.pollInterval)
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

func (d *Notifier) dispatchBatch(ctx context.Context) error {
	cursor := int64(0)
	for {
		events, nextCursor, err := store.FetchUnpublishedOutbox(ctx, d.q, cursor, outboxBatchSize)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		if err := d.dispatchEvents(ctx, events); err != nil {
			return err
		}
		if nextCursor == 0 {
			return nil
		}
		cursor = nextCursor
	}
}

func (d *Notifier) dispatchEvents(ctx context.Context, events []store.OutboxEvent) error {
	notificationEvents := make([]store.OutboxEvent, 0, len(events))
	for _, event := range events {
		if strings.HasPrefix(event.Topic, "notify.") {
			notificationEvents = append(notificationEvents, event)
		}
	}
	if len(notificationEvents) == 0 {
		return nil
	}
	if len(d.endpoints) == 0 {
		ids := make([]int64, 0, len(notificationEvents))
		for _, event := range notificationEvents {
			ids = append(ids, event.ID)
		}
		if err := store.MarkOutboxPublished(ctx, d.q, ids, time.Time{}); err != nil {
			return err
		}
		d.logger.Debug("acknowledged notification events without endpoints", "count", len(ids), "mode", "dev")
		return nil
	}

	for _, event := range notificationEvents {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, err := notificationPayload(event)
		if err != nil {
			d.logger.Error("invalid notification outbox payload", "event_id", event.ID, "topic", event.Topic, "error", err)
			continue
		}
		signature := d.signature(body)
		if err := d.deliver(ctx, event, body, signature); err != nil {
			d.logger.Error("notification service delivery failed", "event_id", event.ID, "topic", event.Topic, "endpoints", len(d.endpoints), "attempts", notificationMaxAttempts, "retry_backoff", "1s,4s,15s", "error", err)
			continue
		}
		if err := store.MarkOutboxPublished(ctx, d.q, []int64{event.ID}, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Notifier) deliver(ctx context.Context, event store.OutboxEvent, body []byte, signature string) error {
	for _, endpoint := range d.endpoints {
		if err := d.deliverEndpoint(ctx, event, endpoint, body, signature); err != nil {
			return fmt.Errorf("endpoint %q: %w", endpoint, err)
		}
	}
	return nil
}

func (d *Notifier) deliverEndpoint(ctx context.Context, event store.OutboxEvent, endpoint string, body []byte, signature string) error {
	var lastErr error
	for attempt := range notificationMaxAttempts {
		if attempt > 0 {
			if err := waitForRetry(ctx, notificationRetryBackoff[attempt-1]); err != nil {
				return err
			}
		}
		if err := d.post(ctx, endpoint, body, signature); err == nil {
			return nil
		} else {
			lastErr = err
			d.logger.Warn("notification service delivery attempt failed", "event_id", event.ID, "endpoint", endpoint, "attempt", attempt+1, "max_attempts", notificationMaxAttempts, "error", err)
		}
	}
	return lastErr
}

func (d *Notifier) post(ctx context.Context, endpoint string, body []byte, signature string) error {
	requestContext, cancel := context.WithTimeout(ctx, notificationHTTPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Teamusers-Signature-256", signature)
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected HTTP status %s", response.Status)
	}
	return nil
}

func (d *Notifier) signature(body []byte) string {
	mac := hmac.New(sha256.New, []byte(d.secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func notificationPayload(event store.OutboxEvent) ([]byte, error) {
	data := event.Payload
	if len(data) == 0 {
		data = []byte(`{}`)
	}
	if !json.Valid(data) {
		return nil, errors.New("payload is not valid JSON")
	}
	at := time.Now().UTC()
	var metadata struct {
		At time.Time `json:"at"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	if !metadata.At.IsZero() {
		at = metadata.At
	}
	payload := struct {
		ID   int64           `json:"id"`
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
		At   time.Time       `json:"at"`
	}{
		ID: event.ID, Type: strings.TrimPrefix(event.Topic, "notify."), Data: json.RawMessage(data), At: at,
	}
	return json.Marshal(payload)
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
