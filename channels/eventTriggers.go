////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// Message Triggers                                                           //
////////////////////////////////////////////////////////////////////////////////

// triggerEventFunc is triggered on normal message reception.
type triggerEventFunc func(channelID *id.ID, umi *userMessageInternal,
	encryptedPayload []byte, timestamp time.Time,
	receptionID receptionID.EphemeralIdentity, round rounds.Round,
	status SentStatus) (uint64, error)

// triggerEvent is an internal function that is used to trigger message
// reception on a message received from a user (symmetric encryption).
//
// It will call the appropriate MessageTypeReceiveMessage, assuming one exists.
//
// This function adheres to the triggerEventFunc type.
func (e *events) triggerEvent(channelID *id.ID, umi *userMessageInternal,
	encryptedPayload []byte, timestamp time.Time,
	_ receptionID.EphemeralIdentity, round rounds.Round, status SentStatus) (
	uint64, error) {
	um := umi.GetUserMessage()
	cm := umi.GetChannelMessage()
	messageType := MessageType(cm.PayloadType)

	// Check if the user is muted on this channel
	isMuted := e.mutedUsers.isMuted(channelID, um.ECCPublicKey)

	// Get handler for message type
	handler, err := e.getHandler(messageType, true, false, isMuted)
	if err != nil {
		err = errors.Errorf("Received message %s from %x on channel %s in "+
			"round %d that could not be handled: %s; Contents: %v",
			umi.GetMessageID(), um.ECCPublicKey, channelID, round.ID, err,
			cm.Payload)
		jww.ERROR.Printf("[CH] %+v", err)
		return 0, err
	}

	// Call the listener. This is already in an instanced event; no new thread
	// is needed.
	uuid := handler.listener(ReceiveMessageValues{
		ChannelID:        channelID,
		MessageID:        umi.GetMessageID(),
		MessageType:      messageType,
		Nickname:         cm.Nickname,
		Content:          cm.Payload,
		EncryptedPayload: encryptedPayload,
		PubKey:           um.ECCPublicKey,
		Codeset:          0,
		Timestamp:        timestamp,
		LocalTimestamp:   time.Unix(0, cm.LocalTimestamp),
		Lease:            time.Duration(cm.Lease),
		Round:            round,
		OriginalRoundID:  id.Round(cm.RoundID),
		Status:           status,
		FromAdmin:        false,
		UserMuted:        isMuted,
	})
	return uuid, nil
}

// triggerAdminEventFunc is triggered on admin message reception.
type triggerAdminEventFunc func(channelID *id.ID, cm *ChannelMessage,
	encryptedPayload []byte, timestamp time.Time,
	messageID cryptoChannel.MessageID,
	receptionID receptionID.EphemeralIdentity, round rounds.Round,
	status SentStatus) (uint64, error)

// triggerAdminEvent is an internal function that is used to trigger message
// reception on a message received from the admin (asymmetric encryption).
//
// It will call the appropriate MessageTypeReceiveMessage, assuming one exists.
//
// This function adheres to the triggerAdminEventFunc type.
func (e *events) triggerAdminEvent(channelID *id.ID, cm *ChannelMessage,
	encryptedPayload []byte, timestamp time.Time,
	messageID cryptoChannel.MessageID, _ receptionID.EphemeralIdentity,
	round rounds.Round, status SentStatus) (uint64, error) {
	messageType := MessageType(cm.PayloadType)

	// Get handler for message type
	handler, err := e.getHandler(messageType, false, true, false)
	if err != nil {
		err = errors.Errorf("Received admin message %s from %s on channel %s "+
			"in round %d that could not be handled: %s; Contents: %v",
			messageID, AdminUsername, channelID, round.ID, err, cm.Payload)
		jww.ERROR.Printf("[CH] %+v", err)
		return 0, err
	}

	// Call the listener. This is already in an instanced event; no new thread
	// is needed.
	uuid := handler.listener(ReceiveMessageValues{
		ChannelID:        channelID,
		MessageID:        messageID,
		MessageType:      messageType,
		Nickname:         AdminUsername,
		Content:          cm.Payload,
		EncryptedPayload: encryptedPayload,
		PubKey:           AdminFakePubKey,
		Codeset:          0,
		Timestamp:        timestamp,
		LocalTimestamp:   time.Unix(0, cm.LocalTimestamp),
		Lease:            time.Duration(cm.Lease),
		Round:            round,
		OriginalRoundID:  id.Round(cm.RoundID),
		Status:           status,
		FromAdmin:        true,
		UserMuted:        false,
	})
	return uuid, nil
}

// triggerAdminEventFunc is triggered on for message actions.
type triggerActionEventFunc func(channelID *id.ID,
	messageID cryptoChannel.MessageID, messageType MessageType, nickname string,
	payload, encryptedPayload []byte, timestamp, localTimestamp time.Time, lease time.Duration,
	round rounds.Round, originalRound id.Round, status SentStatus, fromAdmin, replay bool) (
	uint64, error)

// triggerActionEvent is an internal function that is used to trigger an action
// on a message. Currently, this function does not receive any messages and is
// only called by the internal lease manager to undo a message action. An action
// is set via triggerAdminEvent and triggerEvent.
//
// It will call the appropriate MessageTypeReceiveMessage, assuming one exists.
//
// This function adheres to the triggerActionEventFunc type.
func (e *events) triggerActionEvent(channelID *id.ID,
	messageID cryptoChannel.MessageID, messageType MessageType, nickname string,
	payload, encryptedPayload []byte, timestamp, localTimestamp time.Time, lease time.Duration,
	round rounds.Round, originalRound id.Round, status SentStatus, fromAdmin, replay bool) (
	uint64, error) {

	// If the action needs to be replayed, redirect it to the replay handler
	if replay {
		messageType = SendAdminReplay
	}

	// Get handler for message type
	handler, err := e.getHandler(messageType, true, fromAdmin, false)
	if err != nil {
		err = errors.Errorf("Received action trigger message %s from %s on "+
			"channel %s in round %d that could not be handled: %s; Contents: %v",
			messageID, nickname, channelID, round.ID, err, payload)
		jww.ERROR.Printf("[CH] %+v", err)
		return 0, err
	}

	// Call the listener. This is already in an instanced event; no new thread
	// is needed.
	uuid := handler.listener(ReceiveMessageValues{
		ChannelID:        channelID,
		MessageID:        messageID,
		MessageType:      messageType,
		Nickname:         nickname,
		Content:          payload,
		EncryptedPayload: encryptedPayload,
		PubKey:           AdminFakePubKey,
		Codeset:          0,
		Timestamp:        timestamp,
		LocalTimestamp:   localTimestamp,
		Lease:            lease,
		Round:            round,
		OriginalRoundID:  originalRound,
		Status:           status,
		FromAdmin:        fromAdmin,
		UserMuted:        false,
	})
	return uuid, nil
}