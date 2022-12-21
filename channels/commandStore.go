////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"time"
)

// Storage values.
const (
	commandStorePrefix  = "channelCommandStore"
	commandStoreVersion = 0
)

// CommandStore stores message information about channel commands in storage.
// Each message
type CommandStore struct {
	kv *versioned.KV
}

// NewCommandStore initialises a new message CommandStore object with a prefixed
// KV.
func NewCommandStore(kv *versioned.KV) *CommandStore {
	return &CommandStore{
		kv: kv.Prefix(commandStorePrefix),
	}
}

// SaveCommand stores the command message and its data to storage.
func (cs *CommandStore) SaveCommand(channelID *id.ID,
	messageID cryptoChannel.MessageID, messageType MessageType, nickname string,
	content, encryptedPayload []byte, pubKey ed25519.PublicKey, codeset uint8,
	timestamp, localTimestamp time.Time, lease time.Duration,
	round rounds.Round, status SentStatus, fromAdmin, userMuted bool) error {

	m := CommandMessage{
		ChannelID:        channelID,
		MessageID:        messageID,
		MessageType:      messageType,
		Nickname:         nickname,
		Content:          content,
		EncryptedPayload: encryptedPayload,
		PubKey:           pubKey,
		Codeset:          codeset,
		Timestamp:        timestamp.Round(0),
		LocalTimestamp:   localTimestamp.Round(0),
		Lease:            lease,
		Round:            round,
		Status:           status,
		FromAdmin:        fromAdmin,
		UserMuted:        userMuted,
	}

	data, err := json.Marshal(m)
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   commandStoreVersion,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	key := string(newCommandFingerprint(channelID, messageType, content).key())
	return cs.kv.Set(key, obj)
}

// LoadCommand loads the command message from storage.
func (cs *CommandStore) LoadCommand(channelID *id.ID,
	messageType MessageType, content []byte) (CommandMessage, error) {
	key := string(newCommandFingerprint(channelID, messageType, content).key())

	obj, err := cs.kv.Get(key, commandStoreVersion)
	if err != nil {
		return CommandMessage{}, err
	}

	var m CommandMessage
	return m, json.Unmarshal(obj.Data, &m)
}

// DeleteCommand deletes the command message from storage.
func (cs *CommandStore) DeleteCommand(
	channelID *id.ID, messageType MessageType, content []byte) error {
	key := string(newCommandFingerprint(channelID, messageType, content).key())
	return cs.kv.Delete(key, commandStoreVersion)
}

////////////////////////////////////////////////////////////////////////////////
// Storage Message                                                            //
////////////////////////////////////////////////////////////////////////////////

// CommandMessage contains all the information about a command channel message
// that will be saved to storage
type CommandMessage struct {
	// ChannelID is the ID of the channel.
	ChannelID *id.ID `json:"channelID"`

	// MessageID is the ID of the message.
	MessageID cryptoChannel.MessageID `json:"messageID"`

	// MessageType is the Type of channel message.
	MessageType MessageType `json:"messageType"`

	// Nickname is the nickname of the sender.
	Nickname string `json:"nickname"`

	// Content is the message contents. In most cases, this is the various
	// marshalled proto messages (e.g., channels.CMIXChannelText and
	// channels.CMIXChannelDelete).
	Content []byte `json:"content"`

	// EncryptedPayload is the encrypted contents of the received format.Message
	// (with its outer layer of encryption removed). This is the encrypted
	// channels.ChannelMessage.
	EncryptedPayload []byte `json:"encryptedPayload"`

	// PubKey is the Ed25519 public key of the sender.
	PubKey ed25519.PublicKey `json:"pubKey"`

	// Codeset is the codeset version.
	Codeset uint8 `json:"codeset"`

	// Timestamp is the time that the round was queued. It is set by the
	// listener to be either ChannelMessage.LocalTimestamp or the timestamp for
	// states.QUEUED of the round it was sent on, if that is significantly later
	// than LocalTimestamp. If the message is a replay, then Timestamp will
	// always be the queued time of the round.
	Timestamp time.Time `json:"timestamp"`

	// LocalTimestamp is the time the sender queued the message for sending on
	// their client.
	LocalTimestamp time.Time `json:"localTimestamp"`

	// Lease is how long the message should persist.
	Lease time.Duration `json:"lease"`

	// Round is the information about the round the message was sent on. For
	// replay messages, this is the round of the most recent replay, not the
	// round of the original message.
	Round rounds.Round `json:"round"`

	// Status is the current status of the message. It is set to Delivered by
	// the listener.
	Status SentStatus `json:"status"`

	// FromAdmin indicates if the message came from the channel admin.
	FromAdmin bool `json:"fromAdmin"`

	// UserMuted indicates if the sender of the message is muted.
	UserMuted bool `json:"userMuted"`
}

////////////////////////////////////////////////////////////////////////////////
// Fingerprint                                                                //
////////////////////////////////////////////////////////////////////////////////

// commandFpLen is the length of a commandFingerprint.
const commandFpLen = 32

// commandFingerprint is a unique identifier for a command on a channel message.
// It is generated by taking the hash of a chanel ID, a command, and the message
// payload.
type commandFingerprint [commandFpLen]byte

// commandFingerprintKey is the string form of commandFingerprint. It is used in
// maps so that they are JSON marshallable.
type commandFingerprintKey string

// newCommandFingerprint generates a new commandFingerprint from a channel ID, a
// command (message type), and a decrypted message payload (marshalled proto
// message).
func newCommandFingerprint(
	channelID *id.ID, command MessageType, payload []byte) commandFingerprint {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[CH] Failed to get hash to make command fingerprint "+
			"for command %s in channel %s: %+v", command, channelID, err)
	}

	h.Write(channelID.Bytes())
	h.Write(command.Bytes())
	h.Write(payload)

	var fp commandFingerprint
	copy(fp[:], h.Sum(nil))
	return fp
}

// key creates a commandFingerprintKey from the commandFingerprint to be used
// when accessing the fingerprint map.
func (afp commandFingerprint) key() commandFingerprintKey {
	return commandFingerprintKey(base64.StdEncoding.EncodeToString(afp[:]))
}

// String returns a human-readable version of commandFingerprint used for
// debugging and logging. This function adheres to the fmt.Stringer interface.
func (afp commandFingerprint) String() string {
	return base64.StdEncoding.EncodeToString(afp[:])
}
