////////////////////////////////////////////////////////////////////////////////
// Copyright © 2023 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package storage

import (
	"time"
)

// Message defines the IndexedDb representation of a single Message.
//
// A Message belongs to one Conversation.
// A Message may belong to one Message (Parent).
type Message struct {
	Id                 uint64 `gorm:"primaryKey;autoIncrement:true"`
	MessageId          []byte `gorm:"uniqueIndex;not null"`
	ConversationPubKey []byte `gorm:"index;not null"`
	ParentMessageId    []byte
	Timestamp          time.Time `gorm:"index;not null"`
	SenderPubKey       []byte    `gorm:"index;not null"`
	CodesetVersion     uint8     `gorm:"not null"`
	Status             uint8     `gorm:"not null"`
	Text               []byte    `gorm:"not null"`
	Type               uint16    `gorm:"not null"`
	Round              uint64    `gorm:"not null"`
}

// Conversation defines the IndexedDb representation of a single
// message exchange between two recipients.
// A Conversation has many Message.
type Conversation struct {
	Pubkey         []byte `gorm:"primaryKey;not null;autoIncrement:false"`
	Nickname       string `gorm:"not null"`
	Token          uint32 `gorm:"not null"`
	CodesetVersion uint8  `gorm:"not null"`
	Blocked        bool   `gorm:"not null"`

	Messages []Message `gorm:"constraint:OnDelete:CASCADE"`
}
