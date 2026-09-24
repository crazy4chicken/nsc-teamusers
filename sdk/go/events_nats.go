//go:build nats

package iam

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/nats-io/nats.go"
)

var permissionEventSubjects = []string{
	"iam.perm.changed",
	"iam.user.disabled",
	"iam.role.updated",
}

type permissionEvent struct {
	EventID string   `json:"event_id"`
	Type    string   `json:"type"`
	UserIDs []string `json:"user_ids"`
	TeamID  string   `json:"team_id"`
	At      string   `json:"at"`
}

func subscribePermissionsNATS(client *PermissionsClient, natsURL string, handler func([]string)) (*PermissionSubscription, error) {
	if strings.TrimSpace(natsURL) == "" {
		return nil, nil
	}
	connection, err := nats.Connect(natsURL)
	if err != nil {
		return nil, err
	}
	subscriptions := make([]*nats.Subscription, 0, len(permissionEventSubjects))
	closeSubscriptions := func() error {
		var closeErr error
		for _, subscription := range subscriptions {
			if err := subscription.Unsubscribe(); err != nil && closeErr == nil {
				closeErr = err
			}
		}
		if err := connection.Drain(); err != nil && closeErr == nil {
			closeErr = err
		}
		connection.Close()
		return closeErr
	}
	for _, subject := range permissionEventSubjects {
		subscription, subscribeErr := connection.Subscribe(subject, func(message *nats.Msg) {
			var event permissionEvent
			if err := json.Unmarshal(message.Data, &event); err != nil {
				return
			}
			if len(event.UserIDs) == 0 {
				return
			}
			userIDs := append([]string(nil), event.UserIDs...)
			client.Invalidate(userIDs...)
			if handler != nil {
				handler(userIDs)
			}
		})
		if subscribeErr != nil {
			_ = closeSubscriptions()
			return nil, subscribeErr
		}
		subscriptions = append(subscriptions, subscription)
	}
	if err := connection.Flush(); err != nil {
		_ = closeSubscriptions()
		return nil, errors.New("flush NATS subscriptions: " + err.Error())
	}
	return &PermissionSubscription{close: closeSubscriptions}, nil
}
