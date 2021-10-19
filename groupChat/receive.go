///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	gs "gitlab.com/elixxir/client/groupChat/groupStore"
	"gitlab.com/elixxir/client/interfaces/message"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/crypto/group"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

// Error messages.
const (
	newDecryptKeyErr        = "failed to generate key for decrypting group payload: %+v"
	unmarshalInternalMsgErr = "failed to unmarshal group internal message: %+v"
	unmarshalSenderIdErr    = "failed to unmarshal sender ID: %+v"
	unmarshalPublicMsgErr   = "failed to unmarshal group cMix message contents: %+v"
	findGroupKeyFpErr       = "failed to find group with key fingerprint matching %s"
	genCryptKeyMacErr       = "failed to generate encryption key for group " +
		"cMix message because MAC verification failed (epoch %d could be off)"
)

// receive starts the group message reception worker that waits for new group
// messages to arrive.
func (m Manager) receive(rawMsgs chan message.Receive, stop *stoppable.Single) {
	jww.DEBUG.Print("Starting group message reception worker.")

	for {
		select {
		case <-stop.Quit():
			jww.DEBUG.Print("Stopping group message reception worker.")
			stop.ToStopped()
			return
		case receiveMsg := <-rawMsgs:
			jww.DEBUG.Print("Group message reception received cMix message.")

			// Attempt to read the message
			g, msgID, timestamp, senderID, msg, err := m.readMessage(receiveMsg)
			if err != nil {
				jww.WARN.Printf("Group message reception failed to read cMix "+
					"message: %+v", err)
				continue
			}

			// If the message was read correctly, send it to the callback
			go m.receiveFunc(MessageReceive{
				GroupID:        g.ID,
				ID:             msgID,
				Payload:        msg,
				SenderID:       senderID,
				RecipientID:    receiveMsg.RecipientID,
				EphemeralID:    receiveMsg.EphemeralID,
				Timestamp:      receiveMsg.Timestamp,
				RoundID:        receiveMsg.RoundId,
				RoundTimestamp: timestamp,
			})
		}
	}
}

// readMessage returns the group, message ID, timestamp, sender ID, and message
// of a group message. The encrypted group message data is unmarshalled from a
// cMix message in the message.Receive and then decrypted and the MAC is
// verified. The group is found by finding the group with a matching key
// fingerprint.
func (m *Manager) readMessage(msg message.Receive) (gs.Group, group.MessageID,
	time.Time, *id.ID, []byte, error) {
	// Unmarshal payload into cMix message
	cMixMsg := format.Unmarshal(msg.Payload)

	// Unmarshal cMix message contents to get public message format
	publicMsg, err := unmarshalPublicMsg(cMixMsg.GetContents())
	if err != nil {
		return gs.Group{}, group.MessageID{}, time.Time{}, nil, nil,
			errors.Errorf(unmarshalPublicMsgErr, err)
	}

	// Get the group from storage via key fingerprint lookup
	g, exists := m.gs.GetByKeyFp(cMixMsg.GetKeyFP(), publicMsg.GetSalt())
	if !exists {
		return gs.Group{}, group.MessageID{}, time.Time{}, nil, nil,
			errors.Errorf(findGroupKeyFpErr, cMixMsg.GetKeyFP())
	}

	// Decrypt the payload and return the messages timestamp, sender ID, and
	// message contents
	messageID, timestamp, senderID, contents, err := m.decryptMessage(
		g, cMixMsg, publicMsg, msg.RoundTimestamp)
	return g, messageID, timestamp, senderID, contents, err
}

// decryptMessage decrypts the group message payload and returns its message ID,
// timestamp, sender ID, and message contents.
func (m *Manager) decryptMessage(g gs.Group, cMixMsg format.Message,
	publicMsg publicMsg, roundTimestamp time.Time) (group.MessageID, time.Time,
	*id.ID, []byte, error) {

	key, err := getCryptKey(g.Key, publicMsg.GetSalt(), cMixMsg.GetMac(),
		publicMsg.GetPayload(), g.DhKeys, roundTimestamp)
	if err != nil {
		return group.MessageID{}, time.Time{}, nil, nil, err
	}

	// Decrypt internal message
	decryptedPayload := group.Decrypt(key, cMixMsg.GetKeyFP(),
		publicMsg.GetPayload())

	// Unmarshal internal message
	internalMsg, err := unmarshalInternalMsg(decryptedPayload)
	if err != nil {
		return group.MessageID{}, time.Time{}, nil, nil,
			errors.Errorf(unmarshalInternalMsgErr, err)
	}

	// Unmarshal sender ID
	senderID, err := internalMsg.GetSenderID()
	if err != nil {
		return group.MessageID{}, time.Time{}, nil, nil,
			errors.Errorf(unmarshalSenderIdErr, err)
	}

	messageID := group.NewMessageID(g.ID, internalMsg.Marshal())

	return messageID, internalMsg.GetTimestamp(), senderID,
		internalMsg.GetPayload(), nil
}

// getCryptKey generates the decryption key for a group internal message. The
// key is generated using the group key, an epoch, and a salt. The epoch is
// based off the round timestamp. So, to avoid missing the correct epoch, the
// current, past, and next epochs are checked until one of them produces a key
// that matches the message's MAC. The DH key is also unknown, so each member's
// DH key is tried until there is a match.
func getCryptKey(key group.Key, salt [group.SaltLen]byte, mac, payload []byte,
	dhKeys gs.DhKeyList, roundTimestamp time.Time) (group.CryptKey, error) {
	// Compute the current epoch
	epoch := group.ComputeEpoch(roundTimestamp)

	for _, dhKey := range dhKeys {

		// Create a key with the correct epoch
		for _, epoch := range []uint32{epoch, epoch - 1, epoch + 1} {
			// Generate key
			cryptKey, err := group.NewKdfKey(key, epoch, salt)
			if err != nil {
				return group.CryptKey{}, errors.Errorf(newDecryptKeyErr, err)
			}

			// Return the key if the MAC matches
			if group.CheckMAC(mac, cryptKey, payload, dhKey) {
				return cryptKey, nil
			}
		}
	}

	// Return an error if none of the epochs worked
	return group.CryptKey{}, errors.Errorf(genCryptKeyMacErr, epoch)
}
