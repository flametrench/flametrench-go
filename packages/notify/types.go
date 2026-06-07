// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package notify

import "time"

// State is the lifecycle state of a notification (ADR 0022 §Lifecycle).
type State string

const (
	StateUnread    State = "unread"
	StateRead      State = "read"
	StateDismissed State = "dismissed"
)

// Subject is the entity the notification is about.
type Subject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Notification is the per-recipient record that something happened (ADR 0022).
type Notification struct {
	ID             string         `json:"id"`
	Scope          string         `json:"scope"`
	RecipientUsrID string         `json:"recipient_usr_id"`
	Type           string         `json:"type"`
	Subject        Subject        `json:"subject"`
	Data           map[string]any `json:"data"`
	State          State          `json:"state"`
	CreatedAt      time.Time      `json:"created_at"`
	StateChangedAt time.Time      `json:"state_changed_at"`
}

// NotificationPage is a cursor-paginated list of notifications.
type NotificationPage struct {
	Data       []Notification
	NextCursor *string
}
