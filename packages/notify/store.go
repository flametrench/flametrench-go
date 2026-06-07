// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
package notify

// CreateNotificationInput holds the fields required to create a notification.
type CreateNotificationInput struct {
	Scope          string
	RecipientUsrID string
	Type           string
	Subject        Subject
	Data           map[string]any
}

// ListNotificationsOptions controls the cursor-paginated inbox query.
type ListNotificationsOptions struct {
	RecipientUsrID string
	Scope          string
	State          *State
	Type           *string
	Cursor         *string
	Limit          int
}

// NotificationStore is the ADR 0022 notifications primitive interface.
// Every per-notification operation takes the authenticated recipient_usr_id;
// the implementation MUST scope the lookup to it (SDK-enforced, Option-2).
type NotificationStore interface {
	CreateNotification(in CreateNotificationInput) (Notification, error)
	GetNotification(recipientUsrID, id string) (Notification, error)
	ListNotifications(opts ListNotificationsOptions) (NotificationPage, error)
	CountUnread(recipientUsrID string) (int, error)
	MarkRead(recipientUsrID, id string) (Notification, error)
	MarkUnread(recipientUsrID, id string) (Notification, error)
	Dismiss(recipientUsrID, id string) (Notification, error)
}
