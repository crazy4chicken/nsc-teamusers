//go:build !nats

package iam

import "errors"

func subscribePermissionsNATS(_ *PermissionsClient, _ string, _ func([]string)) (*PermissionSubscription, error) {
	return nil, errors.New("NATS support is disabled; rebuild with -tags nats")
}
