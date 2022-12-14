////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"container/list"
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/stoppable"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/crypto/randomness"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"io"
	"math/big"
	"time"
)

const leaseThreadStoppable = "ActionLeaseThread"
const (
	addLeaseMessageChanSize    = 100
	removeLeaseMessageChanSize = 100
	removeChannelChChanSize    = 100
)

// MessageLife is how long a message is available from the network before it
// expires and is irretrievable.
const MessageLife = 500 * time.Hour

// Error messages.
const (
	// actionLeaseList.updateStorage
	storeLeaseMessagesErr = "could not store message leases for channel %s: %+v"
	storeLeaseChanIDsErr  = "could not store lease channel IDs: %+v"

	// actionLeaseList.load
	loadLeaseChanIDsErr  = "could not load list of channels"
	loadLeaseMessagesErr = "could not load message leases for channel %s"
)

// actionLeaseList keeps a list of messages and actions and undoes each action
// when its lease is up.
type actionLeaseList struct {
	// List of messages with leases sorted by when their lease ends, smallest to
	// largest.
	leases *list.List

	// List of messages with leases grouped by the channel and keyed on a unique
	// fingerprint.
	messages map[id.ID]map[leaseFingerprintKey]*leaseMessage

	// New lease messages are added to this channel.
	addLeaseMessage chan *leaseMessage

	// Lease messages that need to be removed are added to this channel.
	removeLeaseMessage chan *leaseMessage

	// Channels that need to be removed are added to this channel.
	removeChannelCh chan *id.ID

	// triggerFn is called when a lease expired to trigger the undoing of the
	// action.
	triggerFn triggerActionEventFunc

	kv  *versioned.KV
	rng *fastRNG.StreamGenerator
}

// leaseMessage contains a message and an associated action.
type leaseMessage struct {
	// ChannelID is the ID of the channel that his message is in.
	ChannelID *id.ID `json:"channelID"`

	// MessageID is the ID of the message the action was sent in.
	MessageID cryptoChannel.MessageID `json:"messageID"`

	// Action is the action applied to the message (currently only Pinned and
	// Mute).
	Action MessageType `json:"action"`

	// Nickname is the nickname of the user who sent the message.
	Nickname string `json:"nickname"`

	// Payload is the contents of the ChannelMessage.Payload.
	Payload []byte `json:"payload"`

	// EncryptedPayload is the encrypted contents of the format.Message the
	// message was sent in.
	EncryptedPayload []byte `json:"encryptedPayload"`

	// Timestamp is the time the message was sent. On a replayed message, this
	// will be the timestamp of the replayed message and not the original
	// message.
	//
	// Timestamp is either the value ChannelMessage.LocalTimestamp in the
	// received message or the timestamp of states.QUEUED of the round the
	// message was sent/received in.
	Timestamp time.Time `json:"timestamp"`

	// OriginalTimestamp is the time the original message was sent. On normal
	// actions, this is the same as Timestamp. On a replayed messages, this is
	// the timestamp of the original message, not the timestamp of the replayed
	// message.
	OriginalTimestamp time.Time `json:"originalTimestamp"`

	// Lease is the duration of the message lease. This is the original lease
	// set and indicates the duration to wait from the OriginalTimestamp.
	Lease time.Duration `json:"lease"`

	// LeaseEnd is the time (Unix nano) when the message lease ends. It is the
	// calculated by adding the lease duration to the message's timestamp. Note
	// that LeaseEnd is not when the lease will be triggered.
	LeaseEnd int64 `json:"leaseEnd"`

	// LeaseTrigger is the time (Unix nano) when the lease is triggered. This is
	// equal to LeaseEnd if Lease is less than MessageLife. Otherwise, this is
	// randomly set between MessageLife/2 and MessageLife.
	LeaseTrigger int64 `json:"leaseTrigger"`

	// Round is the round that the message was sent on.
	Round rounds.Round `json:"round"`

	// OriginalRoundID is the original round ID that the message was sent on.
	// This is equal to Round.ID unless the message has been replayed.
	OriginalRoundID id.Round `json:"originalRound"`

	// Status is the status of the message send.
	Status SentStatus `json:"status"`

	// FromAdmin is true if the message was originally sent by the channel
	// admin.
	// TODO: FromAdmin is not currently set. Does this need to be implemented or should it be removed?
	FromAdmin bool `json:"fromAdmin"`

	// e is a link to this message in the lease list.
	e *list.Element
}

// newOrLoadActionLeaseList loads an existing actionLeaseList from storage, if
// it exists. Otherwise, it initialises a new empty actionLeaseList.
func newOrLoadActionLeaseList(triggerFn triggerActionEventFunc,
	kv *versioned.KV, rng *fastRNG.StreamGenerator) (*actionLeaseList, error) {
	all := newActionLeaseList(triggerFn, kv, rng)

	err := all.load()
	if err != nil && kv.Exists(err) {
		return nil, err
	}

	return all, nil
}

// newActionLeaseList initialises a new empty actionLeaseList.
func newActionLeaseList(triggerFn triggerActionEventFunc, kv *versioned.KV,
	rng *fastRNG.StreamGenerator) *actionLeaseList {
	return &actionLeaseList{
		leases:             list.New(),
		messages:           make(map[id.ID]map[leaseFingerprintKey]*leaseMessage),
		addLeaseMessage:    make(chan *leaseMessage, addLeaseMessageChanSize),
		removeLeaseMessage: make(chan *leaseMessage, removeLeaseMessageChanSize),
		removeChannelCh:    make(chan *id.ID, removeChannelChChanSize),
		triggerFn:          triggerFn,
		kv:                 kv,
		rng:                rng,
	}
}

// StartProcesses starts the thread that checks for expired action leases and
// undoes the action. This function adheres to the xxdk.Service type.
//
// This function always returns a nil error.
func (all *actionLeaseList) StartProcesses() (stoppable.Stoppable, error) {
	actionThreadStop := stoppable.NewSingle(leaseThreadStoppable)

	// Start the thread
	go all.updateLeasesThread(actionThreadStop)

	return actionThreadStop, nil
}

// updateLeasesThread updates the list of message leases and undoes each action
// message when the lease expires.
func (all *actionLeaseList) updateLeasesThread(stop *stoppable.Single) {
	jww.INFO.Printf(
		"[CH] Starting action lease list thread with stoppable %s", stop.Name())

	// Start timer stopped to wait to receive first message
	var alarmTime time.Duration
	timer := time.NewTimer(alarmTime)
	timer.Stop()

	for {
		var lm *leaseMessage

		select {
		case <-stop.Quit():
			jww.INFO.Printf("[CH] Stopping action lease list thread: "+
				"stoppable %s quit", stop.Name())
			stop.ToStopped()
			return
		case lm = <-all.addLeaseMessage:
			jww.DEBUG.Printf("[CH] Adding new lease message: %+v", lm)
			err := all._addMessage(lm)
			if err != nil {
				jww.FATAL.Panicf("[CH] Failed to add new lease message: %+v", err)
			}
		case lm = <-all.removeLeaseMessage:
			jww.DEBUG.Printf("[CH] Removing lease message: %+v", lm)
			err := all._removeMessage(lm)
			if err != nil {
				jww.FATAL.Panicf("[CH] Failed to remove lease message: %+v", err)
			}
		case channelID := <-all.removeChannelCh:
			jww.DEBUG.Printf("[CH] Removing leases for channel %s", channelID)
			err := all._removeChannel(channelID)
			if err != nil {
				jww.FATAL.Panicf("[CH] Failed to remove channel: %+v", err)
			}
		case <-timer.C:
			// Once the timer is triggered, drop below to undo any expired
			// message actions and start the next timer
			jww.DEBUG.Printf("[CH] Lease alarm triggered after %s.", alarmTime)
		}

		timer.Stop()

		// Create list of leases to remove and so the list is not modified until
		// after the loop is complete. Otherwise, removing elements during the
		// loop could cause skipping of elements.
		var lmToRemove, lmToUpdate []*leaseMessage
		for e := all.leases.Front(); e != nil; e = e.Next() {
			lm = e.Value.(*leaseMessage)
			if lm.LeaseTrigger <= netTime.Now().UnixNano() {
				// Replay the message if the real lease has not been reached
				replay := lm.LeaseEnd != lm.LeaseTrigger
				if !replay {
					// Mark message for removal
					lmToRemove = append(lmToRemove, lm)

					jww.DEBUG.Printf(
						"[CH] Lease %s expired; undoing %s for %+v",
						time.Unix(0, lm.LeaseEnd), lm.Action, lm)
				} else {
					// Mark message for updating
					lmToUpdate = append(lmToUpdate, lm)
					jww.DEBUG.Printf(
						"[CH] Lease triggered %s; replaying %s for %+v",
						time.Unix(0, lm.LeaseTrigger), lm.Action, lm)
				}

				// Trigger undo or replay
				go func() {
					_, err := all.triggerFn(lm.ChannelID, lm.MessageID,
						lm.Action, lm.Nickname, lm.Payload, lm.EncryptedPayload,
						lm.Timestamp, lm.OriginalTimestamp, lm.Lease, lm.Round,
						lm.OriginalRoundID, lm.Status, lm.FromAdmin, replay)
					if err != nil {
						jww.FATAL.Panicf("[CH] Failed to trigger undo: %+v", err)
					}
				}()
			} else {
				// Trigger alarm for next lease end
				alarmTime = netTime.Until(time.Unix(0, lm.LeaseTrigger))
				timer.Reset(alarmTime)

				jww.DEBUG.Printf("[CH] Lease alarm reset for %s", alarmTime)
				break
			}
		}

		// Remove all expired actions
		for _, m := range lmToRemove {
			if err := all._removeMessage(m); err != nil {
				jww.FATAL.Panicf(
					"[CH] Could not remove lease message: %+v", err)
			}
		}

		// Update all replayed actions
		for _, m := range lmToUpdate {
			if err := all._updateLeaseTrigger(m); err != nil {
				jww.FATAL.Panicf(
					"[CH] Could not update lease trigger time: %+v", err)
			}
		}

	}
}

// addMessage triggers the lease message for insertion.
func (all *actionLeaseList) addMessage(v ReceiveMessageValues, payload []byte) {
	all.addLeaseMessage <- &leaseMessage{
		ChannelID:         v.ChannelID,
		MessageID:         v.MessageID,
		Action:            v.MessageType,
		Nickname:          v.Nickname,
		Payload:           payload,
		EncryptedPayload:  v.EncryptedPayload,
		Timestamp:         v.Timestamp,
		OriginalTimestamp: v.LocalTimestamp,
		Lease:             v.Lease,
		Round:             v.Round,
		OriginalRoundID:   v.OriginalRoundID,
		Status:            v.Status,
	}
}

// _addMessage inserts the message into the lease list. If the message already
// exists, then its lease is updated.
func (all *actionLeaseList) _addMessage(newLm *leaseMessage) error {
	fp := newLeaseFingerprint(newLm.ChannelID, newLm.Action, newLm.Payload)

	// Calculate lease end time
	newLm.LeaseEnd = newLm.OriginalTimestamp.Add(newLm.Lease).UnixNano()
	rng := all.rng.GetStream()
	newLm.LeaseTrigger = calculateLeaseTrigger(
		newLm.Timestamp, newLm.OriginalTimestamp, newLm.Lease, rng).UnixNano()
	rng.Close()

	// When set to true, the list of channels IDs will be updated in storage
	var channelIdUpdate bool

	if messages, exists := all.messages[*newLm.ChannelID]; !exists {
		// Add the channel if it does not exist
		newLm.e = all.insertLease(newLm)
		all.messages[*newLm.ChannelID] =
			map[leaseFingerprintKey]*leaseMessage{fp.key(): newLm}
		channelIdUpdate = true
	} else if lm, exists2 := messages[fp.key()]; !exists2 {
		// Add the lease message if it does not exist
		newLm.e = all.insertLease(newLm)
		all.messages[*newLm.ChannelID][fp.key()] = newLm
	} else {
		lm = newLm
		all.updateLease(lm.e)
	}

	// Update storage
	return all.updateStorage(newLm.ChannelID, channelIdUpdate)
}

// insertLease inserts the leaseMessage to the lease list in order and returns
// the element in the list. Returns true if it was added to the head of the
// list.
func (all *actionLeaseList) insertLease(lm *leaseMessage) *list.Element {
	for mark := all.leases.Front(); mark != nil; mark = mark.Next() {
		if lm.LeaseTrigger < mark.Value.(*leaseMessage).LeaseTrigger {
			return all.leases.InsertBefore(lm, mark)
		}
	}
	return all.leases.PushBack(lm)
}

// removeMessage triggers the lease message for removal.
func (all *actionLeaseList) removeMessage(
	channelID *id.ID, action MessageType, payload []byte) {
	all.removeLeaseMessage <- &leaseMessage{
		ChannelID: channelID,
		Action:    action,
		Payload:   payload,
	}
}

// _removeMessage removes the lease message from the lease list and the message
// map. This function also updates storage. If the message does not exist, nil
// is returned.
func (all *actionLeaseList) _removeMessage(newLm *leaseMessage) error {
	fp := newLeaseFingerprint(newLm.ChannelID, newLm.Action, newLm.Payload)
	lm, exists := all.messages[*newLm.ChannelID][fp.key()]
	if !exists {
		return nil
	}

	// Remove from lease list
	all.leases.Remove(lm.e)

	// When set to true, the list of channels IDs will be updated in storage
	var channelIdUpdate bool

	// Remove from message map
	delete(all.messages[*lm.ChannelID], fp.key())
	if len(all.messages[*lm.ChannelID]) == 0 {
		delete(all.messages, *lm.ChannelID)
		channelIdUpdate = true
	}

	// Update storage
	return all.updateStorage(lm.ChannelID, channelIdUpdate)
}

// _updateLeaseTrigger updates the lease trigger time for the given lease
// message. This function also updates storage. If the message does not exist,
// nil is returned.
// TODO: test
func (all *actionLeaseList) _updateLeaseTrigger(newLm *leaseMessage) error {
	fp := newLeaseFingerprint(newLm.ChannelID, newLm.Action, newLm.Payload)
	lm, exists := all.messages[*newLm.ChannelID][fp.key()]
	if !exists {
		return nil
	}

	// Calculate random trigger duration
	rng := all.rng.GetStream()
	leaseTrigger := calculateLeaseTrigger(
		lm.Timestamp, lm.OriginalTimestamp, lm.Lease, rng).UnixNano()
	rng.Close()

	all.messages[*newLm.ChannelID][fp.key()].LeaseTrigger = leaseTrigger
	all.updateLease(lm.e)

	// Update storage
	return all.updateStorage(lm.ChannelID, false)
}

// updateLease updates the location of the given element. This should be called
// when the LeaseTrigger for a message changes. Returns true if it was added to
// the head of the list.
func (all *actionLeaseList) updateLease(e *list.Element) {
	leaseTrigger := e.Value.(*leaseMessage).LeaseTrigger
	for mark := all.leases.Front(); mark != nil; mark = mark.Next() {
		if leaseTrigger < mark.Value.(*leaseMessage).LeaseTrigger {
			all.leases.MoveBefore(e, mark)
			return
		}
	}
	all.leases.MoveToBack(e)
}

// removeMessage triggers the channel for removal.
func (all *actionLeaseList) removeChannel(channelID *id.ID) {
	all.removeChannelCh <- channelID
}

// _removeChannel removes each lease message for the channel from the leases
// list and removes the channel from the messages map. Also deletes from
// storage.
func (all *actionLeaseList) _removeChannel(channelID *id.ID) error {
	leases, exists := all.messages[*channelID]
	if !exists {
		return nil
	}

	for _, lm := range leases {
		all.leases.Remove(lm.e)
	}

	delete(all.messages, *channelID)

	err := all.storeLeaseChannels()
	if err != nil {
		return err
	}

	return all.deleteLeaseMessages(channelID)
}

// calculateLeaseTrigger calculates the time until the lease should be
// triggered so that it can be replayed. If the lease duration is smaller than
// MessageLife, then the lease does not need to be replayed and the trigger is
// the same as lease end. If the lease duration is longer than MessageLife, then
// the duration is randomly chosen between MessageLife and the lease duration
// minus 10%.
func calculateLeaseTrigger(timestamp, originalTimestamp time.Time,
	lease time.Duration, rng io.Reader) time.Time {
	since := timestamp.Sub(originalTimestamp)

	// Check if the message needs to be replayed before its lease its reached
	if lease == ValidForever || lease-since >= MessageLife {
		// If the message lasts forever or the lease extends longer than a
		// message life, then it needs to be replayed
		lease = MessageLife
	} else {
		// If the lease is smaller than MessageLife, than the lease trigger is
		// the same as the lease end
		return originalTimestamp.Add(lease)
	}

	// Calculate the floor and ceiling to calculate the trigger time between.
	// The floor is half the lease. The ceiling the lease minus 10% to ensure
	// the replay has a chance to send before it expires.
	floor := lease / 2
	ceiling := lease - (lease / 10)

	// Generate random duration between floor and ceiling
	lease = time.Duration(randInt64InRange(int64(floor), int64(ceiling), rng))

	return timestamp.Add(lease)
}

// randInt64InRange generates a random positive int64 between start and end.
func randInt64InRange(start, end int64, rng io.Reader) int64 {
	// Generate 256-bit seed
	seed := make([]byte, 32)
	if _, err := rng.Read(seed); err != nil {
		jww.FATAL.Panicf("[CH] Failed to generate random seed: %+v", err)
	}

	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[CH] Failed to initialize new hash: %+v", err)
	}

	n := randomness.RandInInterval(big.NewInt(end-start), seed, h)

	return n.Int64() + start
}

////////////////////////////////////////////////////////////////////////////////
// Storage Functions                                                          //
////////////////////////////////////////////////////////////////////////////////

// Storage values.
const (
	channelLeaseVer               = 0
	channelLeaseKey               = "channelLeases"
	channelLeaseMessagesVer       = 0
	channelLeaseMessagesKeyPrefix = "channelLeaseMessages/"
)

// load gets all the lease messages from storage and loads them into the lease
// list and message map.
func (all *actionLeaseList) load() error {
	// Get list of channel IDs
	channelIDs, err := all.loadLeaseChannels()
	if err != nil {
		return errors.Wrap(err, loadLeaseChanIDsErr)
	}

	// Get list of lease messages and load them into the message map and lease
	// list
	for _, channelID := range channelIDs {
		all.messages[*channelID], err = all.loadLeaseMessages(channelID)
		if err != nil {
			return errors.Wrapf(err, loadLeaseMessagesErr, channelID)
		}

		for _, lm := range all.messages[*channelID] {
			lm.e = all.insertLease(lm)
		}
	}

	return nil
}

// updateStorage updates the given channel lease list in storage. If
// channelIdUpdate is true, then the main list of channel IDs is also updated.
// Use this option when adding or removing a channel ID from the message map.
func (all *actionLeaseList) updateStorage(
	channelID *id.ID, channelIdUpdate bool) error {
	if err := all.storeLeaseMessages(channelID); err != nil {
		return errors.Errorf(storeLeaseMessagesErr, channelID, err)
	} else if channelIdUpdate {
		if err = all.storeLeaseChannels(); err != nil {
			return errors.Errorf(storeLeaseChanIDsErr, err)
		}
	}
	return nil
}

// storeLeaseChannels stores the list of all channel IDs in the lease list to
// storage.
func (all *actionLeaseList) storeLeaseChannels() error {
	channelIDs := make([]*id.ID, 0, len(all.messages))
	for chanID := range all.messages {
		cid := chanID
		channelIDs = append(channelIDs, &cid)
	}

	data, err := json.Marshal(&channelIDs)
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   channelLeaseVer,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	return all.kv.Set(channelLeaseKey, obj)
}

// loadLeaseChannels loads the list of all channel IDs in the lease list from
// storage.
func (all *actionLeaseList) loadLeaseChannels() ([]*id.ID, error) {
	obj, err := all.kv.Get(channelLeaseKey, channelLeaseVer)
	if err != nil {
		return nil, err
	}

	var channelIDs []*id.ID
	return channelIDs, json.Unmarshal(obj.Data, &channelIDs)
}

// storeLeaseMessages stores the list of leaseMessage objects for the given
// channel ID to storage keying on the channel ID.
func (all *actionLeaseList) storeLeaseMessages(channelID *id.ID) error {
	// If the list is empty, then delete it from storage
	if len(all.messages[*channelID]) == 0 {
		return all.deleteLeaseMessages(channelID)
	}

	data, err := json.Marshal(all.messages[*channelID])
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   channelLeaseMessagesVer,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	return all.kv.Set(makeChannelLeaseMessagesKey(channelID), obj)
}

// loadLeaseMessages loads the list of leaseMessage from storage keyed on the
// channel ID.
func (all *actionLeaseList) loadLeaseMessages(channelID *id.ID) (
	map[leaseFingerprintKey]*leaseMessage, error) {
	obj, err := all.kv.Get(
		makeChannelLeaseMessagesKey(channelID), channelLeaseMessagesVer)
	if err != nil {
		return nil, err
	}

	var messages map[leaseFingerprintKey]*leaseMessage
	return messages, json.Unmarshal(obj.Data, &messages)
}

// deleteLeaseMessages deletes the list of leaseMessage from storage that is
// keyed on the channel ID.
func (all *actionLeaseList) deleteLeaseMessages(channelID *id.ID) error {
	return all.kv.Delete(
		makeChannelLeaseMessagesKey(channelID), channelLeaseMessagesVer)
}

// makeChannelLeaseMessagesKey creates a key for saving channel lease messages
// to storage.
func makeChannelLeaseMessagesKey(channelID *id.ID) string {
	return channelLeaseMessagesKeyPrefix +
		base64.StdEncoding.EncodeToString(channelID.Marshal())
}

////////////////////////////////////////////////////////////////////////////////
// Fingerprint                                                                //
////////////////////////////////////////////////////////////////////////////////

// leaseFpLen is the length of a leaseFingerprint.
const leaseFpLen = 32

// leaseFingerprint is a unique identifier for an action on a channel message.
// It is generated by taking the hash of a chanel ID, an action, and the message
// payload.
type leaseFingerprint [leaseFpLen]byte

// leaseFingerprintKey is the string form of leaseFingerprint.
type leaseFingerprintKey string

// newLeaseFingerprint generates a new leaseFingerprint from a channel ID, an
// action, and a decrypted message payload (marshalled proto message).
func newLeaseFingerprint(
	channelID *id.ID, action MessageType, payload []byte) leaseFingerprint {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[CH] Failed to get hash to make lease fingerprint "+
			"for action %s in channel %s: %+v", action, channelID, err)
	}

	h.Write(channelID.Bytes())
	h.Write(action.Bytes())
	h.Write(payload)

	var fp leaseFingerprint
	copy(fp[:], h.Sum(nil))
	return fp
}

// key creates a leaseFingerprintKey from the leaseFingerprint to be used when
// accessing the fingerprint map.
func (lfp leaseFingerprint) key() leaseFingerprintKey {
	return leaseFingerprintKey(base64.StdEncoding.EncodeToString(lfp[:]))
}

// String returns a human-readable version of leaseFingerprint used for
// debugging and logging. This function adheres to the fmt.Stringer interface.
func (lfp leaseFingerprint) String() string {
	return base64.StdEncoding.EncodeToString(lfp[:])
}
