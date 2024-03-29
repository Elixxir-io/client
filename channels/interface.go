////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"math"
	"time"

	"github.com/pkg/errors"

	"gitlab.com/elixxir/client/v4/cmix"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	clientNotif "gitlab.com/elixxir/client/v4/notifications"
	"gitlab.com/elixxir/client/v4/xxdk"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/message"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
)

// ValidForever is used as a validUntil lease when sending to denote the message
// or operation never expires.
//
// Note: A message relay must be present to enforce this otherwise things expire
// after 3 weeks due to network retention.
var ValidForever = time.Duration(math.MaxInt64)

// Manager provides an interface to manager channels.
type Manager interface {

	////////////////////////////////////////////////////////////////////////////
	// Channel Actions                                                        //
	////////////////////////////////////////////////////////////////////////////

	// GenerateChannel creates a new channel with the user as the admin and
	// returns the broadcast.Channel object. This function only create a channel
	// and does not join it.
	//
	// The private key is saved to storage and can be accessed with
	// ExportChannelAdminKey.
	//
	// Parameters:
	//   - name - The name of the new channel. The name must be between 3 and 24
	//     characters inclusive. It can only include upper and lowercase Unicode
	//     letters, digits 0 through 9, and underscores (_). It cannot be
	//     changed once a channel is created.
	//   - description - The description of a channel. The description is
	//     optional but cannot be longer than 144 characters and can include all
	//     Unicode characters. It cannot be changed once a channel is created.
	//   - privacyLevel - The broadcast.PrivacyLevel of the channel.
	GenerateChannel(
		name, description string, privacyLevel cryptoBroadcast.PrivacyLevel) (
		*cryptoBroadcast.Channel, error)

	// JoinChannel joins the given channel. It will return the error
	// ChannelAlreadyExistsErr if the channel has already been joined.
	JoinChannel(channel *cryptoBroadcast.Channel) error

	// LeaveChannel leaves the given channel. It will return the error
	// ChannelDoesNotExistsErr if the channel was not previously joined.
	LeaveChannel(channelID *id.ID) error

	// EnableDirectMessages enables the token for direct messaging for this
	// channel.
	EnableDirectMessages(chId *id.ID) error

	// DisableDirectMessages removes the token for direct messaging for a
	// given channel.
	DisableDirectMessages(chId *id.ID) error

	// AreDMsEnabled returns the status of DMs for a given channel;
	// returns true if DMs are enabled.
	AreDMsEnabled(chId *id.ID) bool

	// ReplayChannel replays all messages from the channel within the network's
	// memory (~3 weeks) over the event model. It does this by wiping the
	// underlying state tracking for message pickup for the channel, causing all
	// messages to be re-retrieved from the network.
	//
	// Returns the error ChannelDoesNotExistsErr if the channel was not
	// previously joined.
	ReplayChannel(channelID *id.ID) error

	// GetChannels returns the IDs of all channels that have been joined.
	GetChannels() []*id.ID

	// GetChannel returns the underlying cryptographic structure for a given
	// channel.
	//
	// Returns the error ChannelDoesNotExistsErr if the channel was not
	// previously joined.
	GetChannel(channelID *id.ID) (*cryptoBroadcast.Channel, error)

	////////////////////////////////////////////////////////////////////////////
	// Sending                                                                //
	////////////////////////////////////////////////////////////////////////////

	// SendGeneric is used to send a raw message over a channel. In general, it
	// should be wrapped in a function that defines the wire protocol.
	//
	// If the final message, before being sent over the wire, is too long, this
	// will return an error. Due to the underlying encoding using compression,
	// it is not possible to define the largest payload that can be sent, but it
	// will always be possible to send a payload of 802 bytes at minimum.
	//
	// The meaning of validUntil depends on the use case.
	//
	// Set tracked to true if the message should be tracked in the sendTracker,
	// which allows messages to be shown locally before they are received on the
	// network. In general, all messages that will be displayed to the user
	// should be tracked while all actions should not be. More technically, any
	// messageType that corresponds to a handler that does not return a unique
	// ID (i.e., always returns 0) cannot be tracked, or it will cause errors.
	SendGeneric(channelID *id.ID, messageType MessageType, msg []byte,
		validUntil time.Duration, tracked bool, params cmix.CMIXParams,
		pingsMap map[PingType][]ed25519.PublicKey) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// SendMessage is used to send a formatted message over a channel.
	//
	// Due to the underlying encoding using compression, it is not possible to
	// define the largest payload that can be sent, but it will always be
	// possible to send a payload of 798 bytes at minimum.
	//
	// The message will auto delete validUntil after the round it is sent in,
	// lasting forever if ValidForever is used.
	SendMessage(channelID *id.ID, msg string, validUntil time.Duration,
		params cmix.CMIXParams, pings []ed25519.PublicKey) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// SendReply is used to send a formatted message over a channel.
	//
	// Due to the underlying encoding using compression, it is not possible to
	// define the largest payload that can be sent, but it will always be
	// possible to send a payload of 766 bytes at minimum.
	//
	// If the message ID that the reply is sent to does not exist, then the
	// other side will post the message as a normal message and not as a reply.
	//
	// The message will auto delete validUntil after the round it is sent in,
	// lasting forever if ValidForever is used.
	SendReply(channelID *id.ID, msg string, replyTo message.ID,
		validUntil time.Duration, params cmix.CMIXParams,
		pings []ed25519.PublicKey) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// SendReaction is used to send a reaction to a message over a channel. The
	// reaction must be a single emoji with no other characters, and will be
	// rejected otherwise.
	//
	// Clients will drop the reaction if they do not recognize the reactTo
	// message.
	//
	// The message will auto delete validUntil after the round it is sent in,
	// lasting forever if ValidForever is used.
	SendReaction(channelID *id.ID, reaction string, reactTo message.ID,
		validUntil time.Duration, params cmix.CMIXParams) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// SendSilent is used to send to a channel a message with no notifications.
	// Its primary purpose is to communicate new nicknames without calling
	// SendMessage.
	//
	// It takes no payload intentionally as the message should be very
	// lightweight.
	SendSilent(channelID *id.ID, validUntil time.Duration,
		params cmix.CMIXParams) (message.ID, rounds.Round, ephemeral.Id, error)

	// SendInvite is used to send to a channel (invited) an invitation to another
	// channel (invitee).
	//
	// If the channel ID for the invitee channel is not recognized by the Manager,
	// then an error will be returned.
	//
	// See [Manager.SendGeneric] for details on payload size limitations and
	// elaboration of pings.
	SendInvite(channelID *id.ID, msg string, inviteTo *cryptoBroadcast.Channel,
		host string,
		validUntil time.Duration, params cmix.CMIXParams,
		pings []ed25519.PublicKey) (
		message.ID, rounds.Round, ephemeral.Id, error)

	////////////////////////////////////////////////////////////////////////////
	// Admin Sending                                                          //
	////////////////////////////////////////////////////////////////////////////

	// SendAdminGeneric is used to send a raw message over a channel encrypted
	// with admin keys, identifying it as sent by the admin. In general, it
	// should be wrapped in a function that defines the wire protocol.
	//
	// If the final message, before being sent over the wire, is too long, this
	// will return an error. The message must be at most 510 bytes long.
	//
	// If the user is not an admin of the channel (i.e. does not have a private
	// key for the channel saved to storage), then the error NotAnAdminErr is
	// returned.
	//
	// Set tracked to true if the message should be tracked in the sendTracker,
	// which allows messages to be shown locally before they are received on the
	// network. In general, all messages that will be displayed to the user
	// should be tracked while all actions should not be. More technically, any
	// messageType that corresponds to a handler that does not return a unique
	// ID (i.e., always returns 0) cannot be tracked, or it will cause errors.
	SendAdminGeneric(channelID *id.ID, messageType MessageType, msg []byte,
		validUntil time.Duration, tracked bool, params cmix.CMIXParams) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// DeleteMessage deletes the targeted message from storage. Users may delete
	// their own messages but only the channel admin can delete other user's
	// messages. If the user is not an admin of the channel or if they are not
	// the sender of the targetMessage, then the error NotAnAdminErr is
	// returned.
	//
	// Clients will drop the deletion if they do not recognize the target
	// message.
	DeleteMessage(channelID *id.ID, targetMessage message.ID,
		params cmix.CMIXParams) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// PinMessage pins the target message to the top of a channel view for all
	// users in the specified channel. Only the channel admin can pin user
	// messages; if the user is not an admin of the channel, then the error
	// NotAnAdminErr is returned.
	//
	// If undoAction is true, then the targeted message is unpinned. validUntil
	// is the time the message will be pinned for; set this to ValidForever to
	// pin indefinitely. validUntil is ignored if undoAction is true.
	//
	// Clients will drop the pin if they do not recognize the target message.
	PinMessage(channelID *id.ID, targetMessage message.ID,
		undoAction bool, validUntil time.Duration, params cmix.CMIXParams) (
		message.ID, rounds.Round, ephemeral.Id, error)

	// MuteUser is used to mute a user in a channel. Muting a user will cause
	// all future messages from the user being dropped on reception. Muted users
	// are also unable to send messages. Only the channel admin can mute a user;
	// if the user is not an admin of the channel, then the error NotAnAdminErr
	// is returned.
	//
	// If undoAction is true, then the targeted user will be unmuted. validUntil
	// is the time the user will be muted for; set this to ValidForever to mute
	// the user indefinitely. validUntil is ignored if undoAction is true.
	MuteUser(channelID *id.ID, mutedUser ed25519.PublicKey, undoAction bool,
		validUntil time.Duration, params cmix.CMIXParams) (
		message.ID, rounds.Round, ephemeral.Id, error)

	////////////////////////////////////////////////////////////////////////////
	// Other Channel Actions                                                  //
	////////////////////////////////////////////////////////////////////////////

	// GetIdentity returns the public identity of the user associated with this
	// channel manager.
	GetIdentity() cryptoChannel.Identity

	// ExportPrivateIdentity encrypts the private identity using the password
	// and exports it to a portable string.
	ExportPrivateIdentity(password string) ([]byte, error)

	// GetStorageTag returns the tag where this manager is stored. To be used
	// when loading the manager. The storage tag is derived from the public key.
	GetStorageTag() string

	// RegisterReceiveHandler registers a listener for non-default message types
	// so that they can be processed by modules. It is important that such
	// modules collective up with the event model implementation.
	//
	// There can only be one handler per message type; the error
	// MessageTypeAlreadyRegistered will be returned on multiple registrations
	// of the same type.
	//
	// To create a ReceiveMessageHandler, use NewReceiveMessageHandler.
	RegisterReceiveHandler(
		messageType MessageType, handler *ReceiveMessageHandler) error

	// SetNickname sets the nickname in a channel after checking that the
	// nickname is valid using [IsNicknameValid].
	SetNickname(nickname string, channelID *id.ID) error

	// DeleteNickname removes the nickname for a given channel. The name will
	// revert back to the codename for this channel instead.
	DeleteNickname(channelID *id.ID) error

	// GetNickname returns the nickname for the given channel, if it exists.
	GetNickname(channelID *id.ID) (nickname string, exists bool)

	// Muted returns true if the user is currently muted in the given channel.
	Muted(channelID *id.ID) bool

	// GetMutedUsers returns the list of the public keys for each muted user in
	// the channel. If there are no muted user or if the channel does not exist,
	// an empty list is returned.
	GetMutedUsers(channelID *id.ID) []ed25519.PublicKey

	// GetNotificationLevel returns the notification level for the given channel.
	GetNotificationLevel(channelID *id.ID) (NotificationLevel, error)

	// GetNotificationStatus returns the notification status for the given channel.
	GetNotificationStatus(channelID *id.ID) (clientNotif.NotificationState, error)

	// SetMobileNotificationsLevel sets the notification level for the given
	// channel. The [NotificationLevel] dictates the type of notifications
	// received and the status controls weather the notification is push or
	// in-app. If muted, both the level and status must be set to mute.
	//
	// To use push notifications, a token must be registered with the
	// notification manager. Note, when enabling push notifications, information
	// may be shared with third parties (i.e., Firebase and Google's Palantir)
	// and may represent a security risk to the user.
	SetMobileNotificationsLevel(channelID *id.ID, level NotificationLevel,
		status clientNotif.NotificationState) error

	////////////////////////////////////////////////////////////////////////////
	// Admin Management                                                       //
	////////////////////////////////////////////////////////////////////////////

	// IsChannelAdmin returns true if the user is an admin of the channel.
	IsChannelAdmin(channelID *id.ID) bool

	// ExportChannelAdminKey gets the private key for the given channel ID,
	// encrypts it with the provided encryptionPassword, and exports it into a
	// portable format. Returns an error if the user is not an admin of the
	// channel.
	//
	// This key can be provided to other users in a channel to grant them admin
	// access using ImportChannelAdminKey.
	//
	// The private key is encrypted using a key generated from the password
	// using Argon2. Each call to ExportChannelAdminKey produces a different
	// encrypted packet regardless if the same password is used for the same
	// channel. It cannot be determined which channel the payload is for nor
	// that two payloads are for the same channel.
	//
	// The passwords between each call are not related. They can be the same or
	// different with no adverse impact on the security properties.
	ExportChannelAdminKey(
		channelID *id.ID, encryptionPassword string) ([]byte, error)

	// VerifyChannelAdminKey verifies that the encrypted private key can be
	// decrypted and that it matches the expected channel. Returns false if
	// private key does not belong to the given channel.
	//
	// Returns the error WrongPasswordErr for an invalid password. Returns the
	// error ChannelDoesNotExistsErr if the channel has not already been joined.
	VerifyChannelAdminKey(
		channelID *id.ID, encryptionPassword string, encryptedPrivKey []byte) (
		bool, error)

	// ImportChannelAdminKey decrypts and imports the given encrypted private
	// key and grants the user admin access to the channel the private key
	// belongs to. Returns an error if the private key cannot be decrypted or if
	// the private key is for the wrong channel.
	//
	// Returns the error WrongPasswordErr for an invalid password. Returns the
	// error ChannelDoesNotExistsErr if the channel has not already been joined.
	// Returns the error WrongPrivateKeyErr if the private key does not belong
	// to the channel.
	ImportChannelAdminKey(channelID *id.ID, encryptionPassword string,
		encryptedPrivKey []byte) error

	// DeleteChannelAdminKey deletes the private key for the given channel.
	//
	// CAUTION: This will remove admin access. This cannot be undone. If the
	// private key is deleted, it cannot be recovered and the channel can never
	// have another admin.
	DeleteChannelAdminKey(channelID *id.ID) error
}

// NotAnAdminErr is returned if the user is attempting to do an admin command
// while not being an admin.
var NotAnAdminErr = errors.New("user not a member of the channel")

// EventModelBuilder initialises the event model using the given path.
type EventModelBuilder func(path string) (EventModel, error)

// ExtensionMessageHandler is the mechanism by which extensions register their
// message handlers with the event model.
type ExtensionMessageHandler interface {
	// GetType registers the message type that this handler is for. All messages
	// of this type will be passed through this handler.
	GetType() MessageType

	// GetProperties returns debugging and pre-filtering information.
	//
	// Parameters:
	//   - name - A name that is included in log messages for debugging.
	//   - userSpace - If true, then normal user messages will be passed to the
	//     handler, otherwise it is dropped.
	//   - adminSpace - If true, then admin messages will be passed to the
	//     handler, otherwise it is dropped.
	//   - mutedSpace - If true, then muted user messages will be passed to the
	//     handler, otherwise it is dropped.
	//
	// userSpace or adminSpace must be true or all messages will be ignored
	GetProperties() (name string, userSpace, adminSpace, mutedSpace bool)

	// Handle is called when the message is actually received.
	//
	// Parameters:
	//	 - channelID - ID of the channel that the message belongs to.
	//	 - messageID - Unique ID of the message. May not be present if this
	//	   user is the sender.
	//   - messageType - The type of the message. It will always be the same as
	//     GetType.
	//   - nickname - Sender's chosen username. It will be "admin" if it is sent
	//     by a channel administrator.
	//	 - content - The decrypted contents of the payload. This is the actual
	//	   message contents sent from the sender.
	//   - encryptedPayload - Encrypted contents of the received format.Message,
	//     which is the encrypted channels.ChannelMessage. It is used for some
	//     specific admin interactions.
	//   - pubKey - The Ed25519 public key of the sender.
	//   - dmToken - An optional token that the sender may add to allow any
	//     recipient to message them directly.
	//   - codeset - Codename generation version.
	//   - timestamp - Time the message was sent according to the sender.
	//   - originatingTimestamp - The time the mix round the message was
	//     originally sent on started.
	//   - lease - How long the message should persist. The behavior of the
	//     lease is subject to what the extension author wants.
	//   - originatingRound - The ID of the round the message was originally
	//     sent on.
	//   - round - All known details of the round the message was sent on.
	//   - status - The current state of the message, if it is queued to send,
	//     has been sent, and if it has been delivered. Unless this client is
	//     the sender, it will always be Delivered.
	//   - fromAdmin - Indicates if the message came from the channel admin.
	//   - hidden - Designation that the message should not be shown.
	Handle(channelID *id.ID, messageID message.ID, messageType MessageType,
		nickname string, content, encryptedPayload []byte,
		pubKey ed25519.PublicKey, dmToken uint32, codeset uint8, timestamp,
		originatingTimestamp time.Time, lease time.Duration,
		originatingRound id.Round, round rounds.Round, status SentStatus,
		fromAdmin, hidden bool) uint64

	// GetNotificationTags is called to get the asymmetric and symmetric allow
	// lists for the given channel at the specified level that are appended to
	// the [NotificationFilter].
	GetNotificationTags(channelID *id.ID, level NotificationLevel) (
		asymmetric, symmetric AllowLists)
}

// ExtensionBuilder builds an extension off of an event model. It must cast the
// event model to its event model type and return an error if the cast fails. It
// returns a slice of [ExtensionMessageHandler] that contains the handlers for
// every custom message type that the extension will handle.
//
// Note: The first thing the function should do is extract the extension's event
// model using the call:
//
//	eventModel, success := e.(ExtensionEventModel)
//
// It should return an error if the casting is a failure.
type ExtensionBuilder func(e EventModel, m Manager,
	me cryptoChannel.PrivateIdentity) ([]ExtensionMessageHandler, error)

// AddServiceFn adds a service to be controlled by the client thread control.
// These will be started and stopped with the network follower.
//
// This type must match [Client.AddService].
type AddServiceFn func(sp xxdk.Service) error

// UiCallbacks is an interface that a caller can adhere to in order to get
// updates on when sync events occur that require the UI to be updated and what
// those events are.
type UiCallbacks interface {
	// NicknameUpdate is called when your nickname changes due to a
	// change on a remote.
	NicknameUpdate(channelId *id.ID, nickname string, exists bool)

	// NotificationUpdate is a callback that is called any time a notification
	// level changes. It is also called when loading, adding, and deleting
	// channels.
	//
	// It returns a slice of [NotificationFilter] for all channels with
	// notifications enabled. The [NotificationFilter] is used to determine
	// which notifications from the notification server belong to the caller.
	//
	// It also returns a map of all channel notification states that have
	// changed and all that have been deleted. The maxState is the global state
	// set for notifications.
	NotificationUpdate(nfs []NotificationFilter,
		changedNotificationStates []NotificationState,
		deletedNotificationStates []*id.ID, maxState clientNotif.NotificationState)

	// AdminKeysUpdate is a callback be called when a channel's admin key is
	// added or removed. (See [Manager.ImportChannelAdminKey] or
	// [Manager.DeleteChannelAdminKey]).
	AdminKeysUpdate(chID *id.ID, isAdmin bool)

	// DmTokenUpdate is a callback be called when a channel's dm token state is
	// changed
	DmTokenUpdate(chID *id.ID, sendToken bool)

	// ChannelUpdate is called any time the user joins or leaves a channel.
	// deleted is false when joining and true when leaving.
	ChannelUpdate(channelID *id.ID, deleted bool)

	// MessageReceived is called any time a new message is received or an
	// existing message is modified. update is ture when the message is
	// modified. It is false when receiving a new message.
	MessageReceived(uuid int64, channelID *id.ID, update bool)

	// UserMuted is called every time a user is muted or unmuted.
	UserMuted(channelID *id.ID, pubKey ed25519.PublicKey, unmute bool)

	// MessageDeleted is called every time a message is deleted.
	MessageDeleted(messageID message.ID)
}
