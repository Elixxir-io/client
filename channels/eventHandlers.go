////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"github.com/golang/protobuf/proto"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// Message Handlers                                                           //
////////////////////////////////////////////////////////////////////////////////

// receiveTextMessage is the internal function that handles the reception of
// text messages. It handles both messages and replies and calls the correct
// function on the event model.
//
// If the message has a reply, but it is malformed, it will drop the reply and
// write to the log.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receiveTextMessage(v ReceiveMessageValues) uint64 {
	txt := &CMIXChannelText{}
	if err := proto.Unmarshal(v.Content, txt); err != nil {
		jww.ERROR.Printf("[CH] Failed to text unmarshal message %s from %x on "+
			"channel %s, type %s, ts: %s, lease: %s, round: %d: %+v",
			v.MessageID, v.PubKey, v.ChannelID, v.MessageType, v.Timestamp,
			v.Lease, v.Round.ID, err)
		return 0
	}

	if txt.ReplyMessageID != nil {
		if len(txt.ReplyMessageID) == cryptoChannel.MessageIDLen {
			var replyTo cryptoChannel.MessageID
			copy(replyTo[:], txt.ReplyMessageID)
			tag :=
				makeChaDebugTag(v.ChannelID, v.PubKey, v.Content,  SendReplyTag)
			jww.INFO.Printf("[CH] [%s] Received reply from %x to %x on %s",
				tag, v.PubKey, txt.ReplyMessageID, v.ChannelID)
			return e.model.ReceiveReply(
				v.ChannelID, v.MessageID, replyTo, v.Nickname, txt.Text,
				v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, Text,
				v.Status, v.UserMuted)
		} else {
			jww.ERROR.Printf("[CH] Failed process reply to for message %s "+
				"from public key %x (codeset %d) on channel %s, type %s, ts: "+
				"%s, lease: %s, round: %d, returning without reply",
				v.MessageID, v.PubKey, v.Codeset, v.ChannelID, v.MessageType,
				v.Timestamp, v.Lease, v.Round.ID)
			// Still process the message, but drop the reply because it is
			// malformed
		}
	}

	tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content,  SendMessageTag)
	jww.INFO.Printf("[CH] [%s] Received message from %x to %x on %s",
		tag, v.PubKey, txt.ReplyMessageID, v.ChannelID)

	return e.model.ReceiveMessage(v.ChannelID, v.MessageID, v.Nickname, txt.Text,
		v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, Text, v.Status, v.UserMuted)
}

// receiveReaction is the internal function that handles the reception of
// Reactions.
//
// It does edge checking to ensure the received reaction is just a single emoji.
// If the received reaction is not, the reaction is dropped.
// If the messageID for the message the reaction is to is malformed, the
// reaction is dropped.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receiveReaction(v ReceiveMessageValues) uint64 {
	react := &CMIXChannelReaction{}
	if err := proto.Unmarshal(v.Content, react); err != nil {
		jww.ERROR.Printf("[CH] Failed to text unmarshal message %s from %x on "+
			"channel %s, type %s, ts: %s, lease: %s, round: %d: %+v",
			v.MessageID, v.PubKey, v.ChannelID, v.MessageType, v.Timestamp,
			v.Lease, v.Round.ID, err)
		return 0
	}

	// check that the reaction is a single emoji and ignore if it isn't
	if err := ValidateReaction(react.Reaction); err != nil {
		jww.ERROR.Printf("[CH] Failed process reaction %s from %x on channel "+
			"%s, type %s, ts: %s, lease: %s, round: %d, due to malformed "+
			"reaction (%s), ignoring reaction",
			v.MessageID, v.PubKey, v.ChannelID, v.MessageType, v.Timestamp,
			v.Lease, v.Round.ID, err)
		return 0
	}

	if react.ReactionMessageID != nil &&
		len(react.ReactionMessageID) == cryptoChannel.MessageIDLen {
		var reactTo cryptoChannel.MessageID
		copy(reactTo[:], react.ReactionMessageID)

		tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content,  SendReactionTag)
		jww.INFO.Printf("[CH] [%s] Received reaction from %x to %x on %s",
			tag, v.PubKey, react.ReactionMessageID, v.ChannelID)

		return e.model.ReceiveReaction(v.ChannelID, v.MessageID, reactTo,
			v.Nickname, react.Reaction, v.PubKey, v.Codeset, v.Timestamp,
			v.Lease, v.Round, v.MessageType, v.Status, v.UserMuted)
	} else {
		jww.ERROR.Printf("[CH] Failed process reaction %s from public key %x "+
			"(codeset %d) on channel %s, type %s, ts: %s, lease: %s, "+
			"round: %d, reacting to invalid message, ignoring reaction",
			v.MessageID, v.PubKey, v.Codeset, v.ChannelID, v.MessageType,
			v.Timestamp, v.Lease, v.Round.ID)
	}
	return 0
}

// receiveDelete is the internal function that handles the reception of deleted
// messages.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receiveDelete(v ReceiveMessageValues) uint64 {
	msgLog := sprintfReceiveMessage(v.ChannelID, v.MessageID, v.MessageType,
		v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, v.FromAdmin)

	deleteMsg := &CMIXChannelDelete{}
	if err := proto.Unmarshal(v.Content, deleteMsg); err != nil {
		jww.ERROR.Printf(
			"[CH] Failed to proto unmarshal %T from payload in %s: %+v",
			deleteMsg, msgLog, err)
		return 0
	}

	deleteMessageID, err := cryptoChannel.UnmarshalMessageID(deleteMsg.MessageID)
	if err != nil {
		jww.ERROR.Printf("[CH] Failed unmarshal message ID of message "+
			"targeted for deletion in %s: %+v", msgLog, err)
		return 0
	}

	vb := deleteVerb(deleteMsg.UndoAction)
	tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content, SendDeleteTag)
	jww.INFO.Printf(
		"[CH] [%s] Received message %s from %x to channel %s to %s message %s",
		tag, v.MessageID, v.PubKey, v.ChannelID, vb, deleteMessageID)

	// Reject the message deletion if not from original sender or admin
	if !v.FromAdmin {
		targetMsg, err2 := e.model.GetMessage(deleteMessageID)
		if err2 != nil {
			jww.ERROR.Printf("[CH] [%s] Failed to find target message %s for "+
				"deletion from %s: %+v", tag, deleteMsg, msgLog, err2)
			return 0
		}
		if !bytes.Equal(targetMsg.PubKey, v.PubKey) {
			jww.ERROR.Printf("[CH] [%s] Deletion message must come from "+
				"original sender or admin for %s", tag, msgLog)
			return 0
		}
	}

	undoAction := deleteMsg.UndoAction
	deleteMsg.UndoAction = true
	payload, err := proto.Marshal(deleteMsg)
	if err != nil {
		jww.ERROR.Printf(
			"[CH] [%s] Failed to proto marshal %T from payload in %s: %+v",
			tag, deleteMsg, msgLog, err)
		return 0
	}

	var deleted bool
	if undoAction {
		e.leases.removeMessage(v.ChannelID, v.MessageType, payload)
		deleted = false
	} else {
		e.leases.addMessage(v, payload)
		deleted = true
	}

	return e.model.UpdateFromMessageID(v.MessageID, nil, nil, nil, &deleted, nil)
}

// receivePinned is the internal function that handles the reception of pinned
// messages.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receivePinned(v ReceiveMessageValues) uint64 {
	msgLog := sprintfReceiveMessage(v.ChannelID, v.MessageID, v.MessageType,
		v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, v.FromAdmin)

	pinnedMsg := &CMIXChannelPinned{}
	if err := proto.Unmarshal(v.Content, pinnedMsg); err != nil {
		jww.ERROR.Printf(
			"[CH] Failed to proto unmarshal %T from payload in %s: %+v",
			pinnedMsg, msgLog, err)
		return 0
	}

	pinnedMessageID, err := cryptoChannel.UnmarshalMessageID(pinnedMsg.MessageID)
	if err != nil {
		jww.ERROR.Printf("[CH] Failed unmarshal message ID of message "+
			"targeted for pinning in %s: %+v", msgLog, err)
		return 0
	}

	vb := pinnedVerb(pinnedMsg.UndoAction)
	tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content, SendPinnedTag)
	jww.INFO.Printf(
		"[CH] [%s] Received message %s from %x to channel %s to %s message %s",
		tag, v.MessageID, v.PubKey, v.ChannelID, vb, pinnedMessageID)

	undoAction := pinnedMsg.UndoAction
	pinnedMsg.UndoAction = true
	payload, err := proto.Marshal(pinnedMsg)
	if err != nil {
		jww.ERROR.Printf(
			"[CH] [%s] Failed to proto marshal %T from payload in %s: %+v",
			tag, pinnedMsg, msgLog, err)
		return 0
	}

	var pinned bool
	if undoAction {
		e.leases.removeMessage(v.ChannelID, v.MessageType, payload)
		pinned = false
	} else {
		e.leases.addMessage(v, payload)
		pinned = true
	}

	return e.model.UpdateFromMessageID(v.MessageID, nil, nil, &pinned, nil, nil)
}

// receiveMute is the internal function that handles the reception of muted
// users.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receiveMute(v ReceiveMessageValues) uint64 {
	msgLog := sprintfReceiveMessage(v.ChannelID, v.MessageID, v.MessageType,
		v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, v.FromAdmin)

	muteMsg := &CMIXChannelMute{}
	if err := proto.Unmarshal(v.Content, muteMsg); err != nil {
		jww.ERROR.Printf(
			"[CH] Failed to proto unmarshal %T from payload in %s: %+v",
			muteMsg, msgLog, err)
		return 0
	}

	if len(muteMsg.PubKey) != ed25519.PublicKeySize {
		jww.ERROR.Printf("[CH] Failed unmarshal public key of user targeted "+
			"for pinning in %s: length of %d bytes required, received %d bytes",
			msgLog, ed25519.PublicKeySize, len(muteMsg.PubKey))
		return 0
	}

	var mutedUser ed25519.PublicKey
	copy(mutedUser[:], muteMsg.PubKey)

	tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content,  SendMuteTag)
	jww.INFO.Printf(
		"[CH] [%s] Received message %s from %x to channel %s to %s user %x", tag,
		v.MessageID, v.PubKey, v.ChannelID, muteVerb(muteMsg.UndoAction), mutedUser)

	muteMsg.UndoAction = true
	payload, err := proto.Marshal(muteMsg)
	if err != nil {
		jww.ERROR.Printf(
			"[CH] [%s] Failed to proto marshal %T from payload in %s: %+v",
			tag, muteMsg, msgLog, err)
		return 0
	}

	if muteMsg.UndoAction {
		e.leases.removeMessage(v.ChannelID, v.MessageType, payload)
		e.mutedUsers.unmuteUser(v.ChannelID, v.PubKey)
		return 0
	} else {
		e.leases.addMessage(v, payload)
		e.mutedUsers.muteUser(v.ChannelID, v.PubKey)
		return 0
	}
}

// receiveAdminReplay handles replayed admin commands.
//
// This function adheres to the MessageTypeReceiveMessage type.
func (e *events) receiveAdminReplay(v ReceiveMessageValues) uint64 {

	msgLog := sprintfReceiveMessage(v.ChannelID, v.MessageID, v.MessageType,
		v.PubKey, v.Codeset, v.Timestamp, v.Lease, v.Round, v.FromAdmin)

	tag := makeChaDebugTag(v.ChannelID, v.PubKey, v.Content,  SendAdminReplayTag)
	jww.INFO.Printf(
		"[CH] [%s] Received admin replay message %s from %x to channel %s",
		tag, v.MessageID, v.PubKey, v.ChannelID)

	p, err := e.processors.getProcessor(v.ChannelID, adminProcessor)
	if err != nil {
		jww.ERROR.Printf("[CH] [%s] Failed to find processor to process "+
			"replayed admin message in %s: %+v", tag, msgLog, err)
		return 0
	}

	go p.ProcessAdminMessage(
		v.Content, receptionID.EphemeralIdentity{}, v.Round)
	return 0
}

////////////////////////////////////////////////////////////////////////////////
// Debugging and Logging Utilities                                            //
////////////////////////////////////////////////////////////////////////////////

// sprintfReceiveMessage returns a string describing the received message. Used
// for debugging and logging.
func sprintfReceiveMessage(channelID *id.ID,
	messageID cryptoChannel.MessageID, messageType MessageType,
	pubKey ed25519.PublicKey, codeset uint8, timestamp time.Time,
	lease time.Duration, round rounds.Round, fromAdmin bool) string {
	return fmt.Sprintf("message %s from %x (codeset %d) on channel %s "+
		"{type:%s timestamp:%s lease:%s round:%d fromAdmin:%t}", messageID,
		pubKey, codeset, channelID, messageType, timestamp.Round(0), lease,
		round.ID, fromAdmin)
}

// deleteVerb returns the correct verb for the delete action to use for logging
// and debugging.
func deleteVerb(b bool) string {
	if b {
		return "delete"
	}
	return "un-delete"
}

// pinnedVerb returns the correct verb for the pinned action to use for logging
// and debugging.
func pinnedVerb(b bool) string {
	if b {
		return "pin"
	}
	return "unpin"
}

// muteVerb returns the correct verb for the mute action to use for logging and
// debugging.
func muteVerb(b bool) string {
	if b {
		return "mute"
	}
	return "unmute"
}
