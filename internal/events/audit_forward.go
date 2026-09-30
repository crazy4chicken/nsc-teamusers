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

// AuditForwarder delivers queued audit rows to configured HTTP endpoints.
type AuditForwarder struct {
	q            store.Q
	endpoints    []string
	secret       string
	client       *http.Client
	logger       *slog.Logger
	pollInterval time.Duration
}

// NewAuditForwarder constructs an audit delivery dispatcher from process configuration.
func NewAuditForwarder(q store.Q, cfg config.Config, logger *slog.Logger) *AuditForwarder {
	if logger == nil {
		logger = slog.Default()
	}
	endpoints := make([]string, 0, len(cfg.AuditForwardEndpoints))
	for _, endpoint := range cfg.AuditForwardEndpoints {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return &AuditForwarder{
		q:            q,
		endpoints:    endpoints,
		secret:       cfg.AuditForwardSecret,
		client:       &http.Client{Timeout: notificationHTTPTimeout},
		logger:       logger,
		pollInterval: defaultPollInterval,
	}
}

// Run polls queued audit rows until ctx is canceled. Failed deliveries remain
// unpublished and are retried by a later poll.
func (d *AuditForwarder) Run(ctx context.Context) {
	if len(d.endpoints) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if err := d.dispatchBatch(ctx); err != nil && !errors.Is(err, context.Canceled) {
			d.logger.Error("audit forwarder poll failed", "error", err)
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

func (d *AuditForwarder) dispatchBatch(ctx context.Context) error {
	cursor := int64(0)
	for {
		events, nextCursor, err := store.FetchUnpublishedAuditForward(ctx, d.q, cursor, outboxBatchSize)
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

func (d *AuditForwarder) dispatchEvents(ctx context.Context, events []store.OutboxEvent) error {
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := []byte(event.Payload)
		if len(body) == 0 {
			body = []byte(`{}`)
		}
		if !json.Valid(body) {
			d.logger.Error("invalid audit forward outbox payload", "outbox_event_id", event.ID)
			continue
		}
		if err := d.deliver(ctx, event, body, d.signature(body)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			d.logger.Error("audit forward delivery failed", "outbox_event_id", event.ID, "endpoints", len(d.endpoints), "attempts", notificationMaxAttempts, "retry_backoff", "1s,4s,15s")
			return fmt.Errorf("deliver audit forward event %d: %w", event.ID, err)
		}
		if err := store.MarkOutboxPublished(ctx, d.q, []int64{event.ID}, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}

func (d *AuditForwarder) deliver(ctx context.Context, event store.OutboxEvent, body []byte, signature string) error {
	for endpointIndex, endpoint := range d.endpoints {
		if err := d.deliverEndpoint(ctx, event, endpoint, endpointIndex+1, body, signature); err != nil {
			return fmt.Errorf("endpoint %d: %w", endpointIndex+1, err)
		}
	}
	return nil
}

func (d *AuditForwarder) deliverEndpoint(ctx context.Context, event store.OutboxEvent, endpoint string, endpointIndex int, body []byte, signature string) error {
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
			d.logger.Warn("audit forward delivery attempt failed", "outbox_event_id", event.ID, "endpoint_index", endpointIndex, "attempt", attempt+1, "max_attempts", notificationMaxAttempts)
		}
	}
	return lastErr
}

func (d *AuditForwarder) post(ctx context.Context, endpoint string, body []byte, signature string) error {
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

func (d *AuditForwarder) signature(body []byte) string {
	mac := hmac.New(sha256.New, []byte(d.secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
