////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"fmt"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/crypto/fastRNG"
	"strconv"
	"sync"
	"time"

	"gitlab.com/elixxir/client/v4/cmix/rounds"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/xx_network/primitives/id"
)

// AdminUsername defines the displayed username of admin messages, which are
// unique users for every channel defined by the channel's private key.
const AdminUsername = "Admin"

// SentStatus represents the current status of a channel message.
type SentStatus uint8

const (
	// Unsent is the status of a message when it is pending to be sent.
	Unsent SentStatus = iota

	// Sent is the status of a message once the round it is sent on completed.
	Sent

	// Delivered is the status of a message once is has been received.
	Delivered

	// Failed is the status of a message if it failed to send.
	Failed
)

// String returns a human-readable version of [SentStatus], used for debugging
// and logging. This function adheres to the [fmt.Stringer] interface.
func (ss SentStatus) String() string {
	switch ss {
	case Unsent:
		return "unsent"
	case Sent:
		return "sent"
	case Delivered:
		return "delivered"
	case Failed:
		return "failed"
	default:
		return "Invalid SentStatus: " + strconv.Itoa(int(ss))
	}
}

var AdminFakePubKey = ed25519.PublicKey{}

// EventModel is an interface which an external party which uses the channels
// system passed an object which adheres to in order to get events on the
// channel.
type EventModel interface {
	// JoinChannel is called whenever a channel is joined locally.
	JoinChannel(channel *cryptoBroadcast.Channel)

	// LeaveChannel is called whenever a channel is left locally.
	LeaveChannel(channelID *id.ID)

	// ReceiveMessage is called whenever a message is received on a given
	// channel. It may be called multiple times on the same message. It is
	// incumbent on the user of the API to filter such called by message ID.
	//
	// The API needs to return a UUID of the message that can be referenced at a
	// later time.
	//
	// messageID, timestamp, and round are all nillable and may be updated based
	// upon the UUID at a later date. A time of time.Time{} will be passed for a
	// nilled timestamp.
	//
	// nickname may be empty, in which case the UI is expected to display the
	// codename.
	//
	// messageType type is included in the call; it will always be Text (1) for
	// this call, but it may be required in downstream databases.
	ReceiveMessage(channelID *id.ID, messageID cryptoChannel.MessageID,
		nickname, text string, pubKey ed25519.PublicKey, codeset uint8,
		timestamp time.Time, lease time.Duration, round rounds.Round,
		messageType MessageType, status SentStatus, hidden bool) uint64

	// ReceiveReply is called whenever a message is received that is a reply on
	// a given channel. It may be called multiple times on the same message. It
	// is incumbent on the user of the API to filter such called by message ID.
	//
	// Messages may arrive our of order, so a reply, in theory, can arrive
	// before the initial message. As a result, it may be important to buffer
	// replies.
	//
	// The API needs to return a UUID of the message that can be referenced at a
	// later time.
	//
	// messageID, timestamp, and round are all nillable and may be updated based
	// upon the UUID at a later date. A time of time.Time{} will be passed for a
	// nilled timestamp.
	//
	// nickname may be empty, in which case the UI is expected to display the
	// codename.
	//
	// messageType type is included in the call; it will always be Text (1) for
	// this call, but it may be required in downstream databases.
	ReceiveReply(channelID *id.ID, messageID,
		reactionTo cryptoChannel.MessageID, nickname, text string,
		pubKey ed25519.PublicKey, codeset uint8, timestamp time.Time,
		lease time.Duration, round rounds.Round, messageType MessageType,
		status SentStatus, hidden bool) uint64

	// ReceiveReaction is called whenever a reaction to a message is received on
	// a given channel. It may be called multiple times on the same reaction. It
	// is incumbent on the user of the API to filter such called by message ID.
	//
	// Messages may arrive our of order, so a reply, in theory, can arrive
	// before the initial message. As a result, it may be important to buffer
	// replies.
	//
	// The API needs to return a UUID of the message that can be referenced at a
	// later time.
	//
	// messageID, timestamp, and round are all nillable and may be updated based
	// upon the UUID at a later date. A time of time.Time{} will be passed for a
	// nilled timestamp.
	//
	// nickname may be empty, in which case the UI is expected to display the
	// codename.
	//
	// messageType type is included in the call; it will always be Text (1) for
	// this call, but it may be required in downstream databases.
	ReceiveReaction(channelID *id.ID, messageID,
		reactionTo cryptoChannel.MessageID, nickname, reaction string,
		pubKey ed25519.PublicKey, codeset uint8, timestamp time.Time,
		lease time.Duration, round rounds.Round, mType MessageType,
		status SentStatus, hidden bool) uint64

	// UpdateFromUUID is called whenever a message at the UUID is modified.
	//
	// messageID, timestamp, round, pinned, hidden, and status are all nillable
	// and may be updated based upon the UUID at a later date. If a nil value is
	// passed, then make no update.
	UpdateFromUUID(uuid uint64, messageID *cryptoChannel.MessageID,
		timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
		status *SentStatus)

	// UpdateFromMessageID is called whenever a message with the message ID is
	// modified.
	//
	// The API needs to return the UUID of the modified message that can be
	// referenced at a later time.
	//
	// timestamp, round, pinned, hidden, and status are all nillable and may be
	// updated based upon the UUID at a later date. If a nil value is passed,
	// then make no update.
	UpdateFromMessageID(messageID cryptoChannel.MessageID, timestamp *time.Time,
		round *rounds.Round, pinned, hidden *bool, status *SentStatus) uint64

	// GetMessage returns the message with the given channel.MessageID.
	GetMessage(messageID cryptoChannel.MessageID) (ModelMessage, error)
}

// ModelMessage contains a message and all of its information.
type ModelMessage struct {
	UUID            uint64                  `json:"uuid"`
	Nickname        string                  `json:"nickname"`
	MessageID       cryptoChannel.MessageID `json:"messageID"`
	ChannelID       *id.ID                  `json:"channelID"`
	ParentMessageID cryptoChannel.MessageID `json:"parentMessageID"`
	Timestamp       time.Time               `json:"timestamp"`
	Lease           time.Duration           `json:"lease"`
	Status          SentStatus              `json:"status"`
	Hidden          bool                    `json:"hidden"`
	Pinned          bool                    `json:"pinned"`
	Content         []byte                  `json:"content"`
	Type            MessageType             `json:"type"`
	Round           id.Round                `json:"round"`
	PubKey          ed25519.PublicKey       `json:"pubKey"`
	CodesetVersion  uint8                   `json:"codesetVersion"`
}

// MessageTypeReceiveMessage defines handlers for messages of various message
// types. Default ones for Text, Reaction, and AdminText.
//
// A unique UUID must be returned by which the message can be referenced later
// via [EventModel.UpdateFromUUID].
//
// If fromAdmin is true, then the message has been verifies to come from the
// channel admin.
type MessageTypeReceiveMessage func(v ReceiveMessageValues) uint64

// ReceiveMessageValues is returned to a MessageTypeReceiveMessage containing
// all its parameters in a single structure.
type ReceiveMessageValues struct {
	// ChannelID is the ID of the channel. It is set by the listener receiving
	// the message.
	ChannelID *id.ID

	// MessageID is the ID of the message. It is calculated on message reception
	// and is the hash of the marshalled ChannelMessage and channel ID.
	MessageID cryptoChannel.MessageID

	// MessageType is the type of channel message. It comes from the received
	// ChannelMessage.PayloadType
	MessageType MessageType

	// Nickname is the nickname of the sender. It comes from the received
	// ChannelMessage.Nickname
	Nickname string

	// Content is the message contents. In most cases, this is the various
	// marshalled proto messages (e.g., CMIXChannelText and CMIXChannelDelete).
	// It comes from the received ChannelMessage.Payload
	Content []byte

	// EncryptedPayload is the encrypted contents of the received format.Message
	// (with its outer layer of encryption removed). This is the encrypted
	// ChannelMessage.
	EncryptedPayload []byte

	// PubKey is the Ed25519 public key of the sender. It comes from the
	// received UserMessage.ECCPublicKey.
	PubKey ed25519.PublicKey

	// Codeset is the codeset.
	Codeset uint8

	// Timestamp is the time that the round was queued. It is set by the
	// listener to be either ChannelMessage.LocalTimestamp or the timestamp for
	// states.QUEUED of the round it was sent on, if that is significantly later
	// than LocalTimestamp. If the message is a replay, then Timestamp will
	// always be the queued time of the round.
	Timestamp time.Time

	// LocalTimestamp is the time the sender queued the message for sending on
	// their client. It comes from the received ChannelMessage.LocalTimestamp.
	LocalTimestamp time.Time

	// Lease is how long the message should persist. It comes from the received
	// ChannelMessage.Lease.
	Lease time.Duration

	// Round is the information about the round the message was sent on. For
	// replay messages, this is the round of the most recent replay, not the
	// round of the original message.
	Round rounds.Round

	// OriginalRoundID is the ID the message was originally sent on. It comes
	// from the received ChannelMessage.RoundID. For most messages, this will be
	// equal to Round.ID. For replay messages, OriginalRoundID is equal to the
	// round ID the original message was sent on.
	OriginalRoundID id.Round

	// Status is the current status of the message. It is set to Delivered by
	// the listener.
	Status SentStatus

	// FromAdmin indicates if the message came from the channel admin. It is set
	// by the appropriate trigger (admin vs. user).
	FromAdmin bool

	// UserMuted indicates if the sender of the message is muted. This is
	// determined in the trigger.
	UserMuted bool
}

// UpdateFromUuidFunc is a function type for EventModel.UpdateFromUUID so it can
// be mocked for testing where used.
type UpdateFromUuidFunc func(uuid uint64, messageID *cryptoChannel.MessageID,
	timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
	status *SentStatus)

// events is an internal structure that processes events and stores the handlers
// for those events.
type events struct {
	model      EventModel
	registered map[MessageType]*ReceiveMessageHandler
	leases     *actionLeaseList
	mutedUsers *mutedUserManager

	// List of registered message processors
	processors *processorList

	// Used when creating new format.Message for replays
	maxMessageLength int

	mux sync.RWMutex
}

// getHandler returned the handler registered to the message type. It returns an
// error if no handler exists or if the handler does not match the message
// space.
func (e *events) getHandler(messageType MessageType, user, admin, muted bool) (
	*ReceiveMessageHandler, error) {
	e.mux.RLock()
	handler, exists := e.registered[messageType]
	e.mux.RUnlock()

	// Check that a handler is registered for the message type
	if !exists {
		return nil,
			errors.Errorf("no handler found for message type %s", messageType)
	}

	// Check if the received message is in the correct space for the listener
	if err := handler.CheckSpace(user, admin, muted); err != nil {
		return nil, err
	}

	return handler, nil
}

// ReceiveMessageHandler contains a message listener MessageTypeReceiveMessage
// linked to a specific MessageType. It also lists which spaces this handler can
// receive messages for.
type ReceiveMessageHandler struct {
	name       string // Describes the listener (used for logging)
	listener   MessageTypeReceiveMessage
	userSpace  bool
	adminSpace bool
	mutedSpace bool
}

// NewReceiveMessageHandler generates a new ReceiveMessageHandler.
//
// Parameters:
//   - name - A name describing what type of messages the listener picks up.
//     This is used for debugging and logging.
//   - listener - The listener that handles the received message.
//   - userSpace - Set to true if this listener can receive messages from normal
//     users.
//   - adminSpace - Set to true if this listener can receive messages from
//     admins.
//   - mutedSpace - Set to true if this listener can receive messages from muted
//     users.
func NewReceiveMessageHandler(name string, listener MessageTypeReceiveMessage,
	userSpace, adminSpace, mutedSpace bool) *ReceiveMessageHandler {
	return &ReceiveMessageHandler{
		name:       name,
		listener:   listener,
		userSpace:  userSpace,
		adminSpace: adminSpace,
		mutedSpace: mutedSpace,
	}
}

// SpaceString returns a string with the values of each space. This is used for
// logging and debugging purposes.
func (rmh *ReceiveMessageHandler) SpaceString() string {
	return fmt.Sprintf("{user:%t admin:%t muted:%t}",
		rmh.userSpace, rmh.adminSpace, rmh.mutedSpace)
}

// CheckSpace checks that ReceiveMessageHandler can receive in the given user
// spaces. Returns nil if the message matches one or more of the handler's
// spaces. Returns an error if it does not.
func (rmh *ReceiveMessageHandler) CheckSpace(user, admin, muted bool) error {
	// Always reject a muted user if they are not allowed even if this message
	// satisfies one or more of the other spaces
	if !rmh.mutedSpace && muted {
		return errors.Errorf("rejected channel message from %s listener "+
			"because sender is muted. Accepted spaces:%s, message spaces:"+
			"{user:%t admin:%t muted:%t}",
			rmh.name, rmh.SpaceString(), user, admin, muted)
	}

	switch {
	case rmh.userSpace && user:
		return nil
	case rmh.adminSpace && admin:
		return nil
	}

	return errors.Errorf("Rejected channel message from %s listener because "+
		"message space mismatch. Accepted spaces:%s, message spaces:"+
		"{user:%t admin:%t muted:%t}",
		rmh.name, rmh.SpaceString(), user, admin, muted)
}

// initEvents initializes the event model and registers default message type
// handlers.
func initEvents(model EventModel, maxMessageLength int, kv *versioned.KV,
	rng *fastRNG.StreamGenerator) *events {
	e := &events{
		model:            model,
		processors:       newProcessorList(),
		maxMessageLength: maxMessageLength,
	}

	// Set up default message types
	e.registered = map[MessageType]*ReceiveMessageHandler{
		Text:        {"userTextMessage", e.receiveTextMessage, true, false, true},
		AdminText:   {"adminTextMessage", e.receiveTextMessage, false, true, true},
		Reaction:    {"reaction", e.receiveReaction, true, false, true},
		Delete:      {"delete", e.receiveDelete, true, true, false},
		Pinned:      {"pinned", e.receivePinned, false, true, false},
		Mute:        {"mute", e.receiveMute, false, true, false},
		AdminReplay: {"adminReplay", e.receiveAdminReplay, true, true, false},
	}

	// Initialise list of message leases
	var err error
	e.leases, err = newOrLoadActionLeaseList(e.triggerActionEvent, kv, rng)
	if err != nil {
		jww.FATAL.Panicf("[CH] Failed to initialise lease list: %+v", err)
	}

	// Initialise list of muted users
	e.mutedUsers, err = newOrLoadMutedUserManager(kv)
	if err != nil {
		jww.FATAL.Panicf("[CH] Failed to initialise muted user list: %+v", err)
	}

	return e
}

// RegisterReceiveHandler registers a listener for non-default message types so
// that they can be processed by modules. It is important that such modules sync
// up with the event model implementation.
//
// There can only be one handler per message type; the error
// MessageTypeAlreadyRegistered will be returned on multiple registrations of
// the same type.
//
// To create a ReceiveMessageHandler, use NewReceiveMessageHandler.
func (e *events) RegisterReceiveHandler(
	messageType MessageType, handler *ReceiveMessageHandler) error {
	jww.INFO.Printf(
		"[CH] RegisterReceiveHandler for message type %s", messageType)
	e.mux.Lock()
	defer e.mux.Unlock()

	// Check if the type is already registered
	if _, exists := e.registered[messageType]; exists {
		return MessageTypeAlreadyRegistered
	}

	// Register the message type
	e.registered[messageType] = handler
	jww.INFO.Printf("[CH] Registered Listener for Message Type %s", messageType)
	return nil
}
