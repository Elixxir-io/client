////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"encoding/hex"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"sync"
	"time"
)

// Error messages.
const (
	// ReplayBlocker.VerifyReplay
	saveReplayCommandMessageErr = "failed to save command message"
)

// ReplayBlocker ensures that any channel commands received as a replay messages
// are newer than the most recent command message. If it is not, then the
// ReplayBlocker rejects it and replays the correct command.
type ReplayBlocker struct {
	// List of command messages grouped by the channel and keyed on a unique
	// fingerprint.
	messagesByChannel map[id.ID]map[commandFingerprintKey]*commandMessage

	// replay allows a command to be replayed.
	replay triggerLeaseReplay

	store *CommandStore
	kv    *versioned.KV
	mux sync.Mutex
}

// triggerLeaseReplay takes the information needed to schedule a replay on the
// lease system.
type triggerLeaseReplay func(
	channelID *id.ID, action MessageType, payload []byte) error

// commandMessage contains the information to uniquely identify a command in a
// channel and which round it originated from and the round it was last replayed
// on.
type commandMessage struct {
	// ChannelID is the ID of the channel that his message is in.
	ChannelID *id.ID `json:"channelID"`

	// Action is the action applied to the message (currently only Pinned and
	// Mute).
	Action MessageType `json:"action"`

	// Payload is the contents of the ChannelMessage.Payload.
	Payload []byte `json:"payload"`

	// OriginatingRound is the ID of the round the message was originally sent
	// on.
	OriginatingRound id.Round `json:"originatingRound"`
}

// NewOrLoadReplayBlocker loads an existing ReplayBlocker from storage, if it
// exists. Otherwise, it initialises a new empty ReplayBlocker.
// TODO: test
func NewOrLoadReplayBlocker(replay triggerLeaseReplay, store *CommandStore,
	kv *versioned.KV) (*ReplayBlocker, error) {
	rb := NewReplayBlocker(replay, store, kv)

	err := rb.load()
	if err != nil && kv.Exists(err) {
		return nil, err
	}

	return rb, err
}

// NewReplayBlocker initialises a new empty ReplayBlocker.
func NewReplayBlocker(replay triggerLeaseReplay, store *CommandStore,
	kv *versioned.KV) *ReplayBlocker {
	return &ReplayBlocker{
		messagesByChannel: make(map[id.ID]map[commandFingerprintKey]*commandMessage),
		replay:            replay,
		store:             store,
		kv:                kv.Prefix(replayBlockerStoragePrefix),
	}
}

// VerifyReplay verifies if the replay is valid by checking if it is the newest
// version (i.e. the originating round is newer). If it is not, VerifyReplay
// returns false. Otherwise, the replay is valid, and it returns true.
// TODO: test
func (rb *ReplayBlocker) VerifyReplay(channelID *id.ID,
	messageID cryptoChannel.MessageID, action MessageType, payload,
	encryptedPayload []byte, timestamp, originatingTimestamp time.Time,
	lease time.Duration, originatingRound id.Round, round rounds.Round,
	fromAdmin bool) (bool, error) {
	fp := newCommandFingerprint(channelID, action, payload)

	newCm := &commandMessage{
		ChannelID:        channelID,
		Action:           action,
		Payload:          payload,
		OriginatingRound: originatingRound,
	}

	var cm *commandMessage
	var channelIdUpdate bool
	rb.mux.Lock()
	defer rb.mux.Unlock()
	if messages, exists := rb.messagesByChannel[*channelID]; exists {
		if cm, exists = messages[fp.key()]; exists &&
			cm.OriginatingRound >= newCm.OriginatingRound {
			// If the message is replaying an older command, then reject the
			// message (return false) and replay the correct command
			go func(cm *commandMessage) {
				err := rb.replay(cm.ChannelID, cm.Action, cm.Payload)
				if err != nil {
					jww.ERROR.Printf(
						"[CH] Failed to replay %s on channel %s: %+v",
						cm.Action, cm.ChannelID, err)
				}
			}(cm)
			return false, nil
		} else {
			// Add the command message if it does not exist or overwrite if the
			// new message occurred on a newer round
			rb.messagesByChannel[*channelID][fp.key()] = newCm
		}
	} else {
		// Add the channel if it does not exist
		rb.messagesByChannel[*channelID] =
			map[commandFingerprintKey]*commandMessage{fp.key(): newCm}
		channelIdUpdate = true
	}

	// Save message details to storage
	err := rb.store.SaveCommand(channelID, messageID, action, "", payload,
		encryptedPayload, nil, 0, timestamp, originatingTimestamp, lease,
		originatingRound, round, 0, fromAdmin, false)
	if err != nil {
		return true, errors.Wrap(err, saveReplayCommandMessageErr)
	}

	// Update storage
	return true, rb.updateStorage(channelID, channelIdUpdate)
}

// RemoveChannelCommands removes all commands for the channel from the messages
// map. Also deletes from storage.
// TODO: test
func (rb *ReplayBlocker) RemoveChannelCommands(channelID *id.ID) error {
	commands, exists := rb.messagesByChannel[*channelID]
	if !exists {
		return nil
	}

	for _, cm := range commands {
		err := rb.store.DeleteCommand(cm.ChannelID, cm.Action, cm.Payload)
		if err != nil {
			jww.ERROR.Printf("[CH] Failed to delete command %s for channel %s "+
				"from storage: %+v", cm.Action, cm.ChannelID, err)
		}
	}

	delete(rb.messagesByChannel, *channelID)

	err := rb.storeCommandChannelsList()
	if err != nil {
		return err
	}

	return rb.deleteCommandMessages(channelID)
}


////////////////////////////////////////////////////////////////////////////////
// Storage Functions                                                          //
////////////////////////////////////////////////////////////////////////////////

// Storage values.
const (
	replayBlockerStoragePrefix = "channelReplayBlocker"

	commandChannelListVer     = 0
	commandChannelListKey     = "channelCommandList"
	channelCommandMessagesVer = 0
)

// Error messages.
const (
	// ReplayBlocker.updateStorage
	storeCommandMessagesErr = "could not store command messages for channel %s: %+v"
	storeCommandChanIDsErr  = "could not store command channel IDs: %+v"

	// ReplayBlocker.load
	loadCommandChanIDsErr  = "could not load list of channels"
	loadCommandMessagesErr = "could not load command messages for channel %s"
)

// load gets all the command messages from storage and loads them into the
// message map.
func (rb *ReplayBlocker) load() error {
	// Get list of channel IDs
	channelIDs, err := rb.loadCommandChannelsList()
	if err != nil {
		return errors.Wrap(err, loadCommandChanIDsErr)
	}

	// Get list of command messages and load them into the message map
	for _, channelID := range channelIDs {
		rb.messagesByChannel[*channelID], err = rb.loadCommandMessages(channelID)
		if err != nil {
			return errors.Wrapf(err, loadCommandMessagesErr, channelID)
		}
	}

	return nil
}

// updateStorage updates the given channel command list in storage. If
// channelIdUpdate is true, then the main list of channel IDs is also updated.
// Use this option when adding or removing a channel ID from the message map.
func (rb *ReplayBlocker) updateStorage(
	channelID *id.ID, channelIdUpdate bool) error {
	if err := rb.storeCommandMessages(channelID); err != nil {
		return errors.Errorf(storeCommandMessagesErr, channelID, err)
	} else if channelIdUpdate {
		if err = rb.storeCommandChannelsList(); err != nil {
			return errors.Errorf(storeCommandChanIDsErr, err)
		}
	}
	return nil
}

// storeCommandChannelsList stores the list of all channel IDs in the command
// list to storage.
func (rb *ReplayBlocker) storeCommandChannelsList() error {
	channelIDs := make([]*id.ID, 0, len(rb.messagesByChannel))
	for chanID := range rb.messagesByChannel {
		channelIDs = append(channelIDs, chanID.DeepCopy())
	}

	data, err := json.Marshal(&channelIDs)
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   commandChannelListVer,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	return rb.kv.Set(commandChannelListKey, obj)
}

// loadCommandChannelsList loads the list of all channel IDs in the command list
// from storage.
func (rb *ReplayBlocker) loadCommandChannelsList() ([]*id.ID, error) {
	obj, err := rb.kv.Get(commandChannelListKey, commandChannelListVer)
	if err != nil {
		return nil, err
	}

	var channelIDs []*id.ID
	return channelIDs, json.Unmarshal(obj.Data, &channelIDs)
}

// storeCommandMessages stores the map of commandMessage objects for the given
// channel ID to storage keying on the channel ID.
func (rb *ReplayBlocker) storeCommandMessages(channelID *id.ID) error {
	// If the list is empty, then delete it from storage
	if len(rb.messagesByChannel[*channelID]) == 0 {
		return rb.deleteCommandMessages(channelID)
	}

	data, err := json.Marshal(rb.messagesByChannel[*channelID])
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   channelCommandMessagesVer,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	return rb.kv.Set(makeChannelCommandMessagesKey(channelID), obj)
}

// loadCommandMessages loads the map of commandMessage from storage keyed on the
// channel ID.
func (rb *ReplayBlocker) loadCommandMessages(channelID *id.ID) (
	map[commandFingerprintKey]*commandMessage, error) {
	obj, err := rb.kv.Get(
		makeChannelCommandMessagesKey(channelID), channelCommandMessagesVer)
	if err != nil {
		return nil, err
	}

	var messages map[commandFingerprintKey]*commandMessage
	return messages, json.Unmarshal(obj.Data, &messages)
}

// deleteCommandMessages deletes the map of commandMessage from storage that is
// keyed on the channel ID.
func (rb *ReplayBlocker) deleteCommandMessages(channelID *id.ID) error {
	return rb.kv.Delete(
		makeChannelCommandMessagesKey(channelID), channelCommandMessagesVer)
}

// makeChannelCommandMessagesKey creates a key for saving channel replay
// messages to storage.
func makeChannelCommandMessagesKey(channelID *id.ID) string {
	return hex.EncodeToString(channelID.Marshal())
}
