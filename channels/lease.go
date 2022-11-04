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
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"sync"
	"time"
)

// Error messages.
const (
	// actionLeaseList.addMessage and actionLeaseList.removeMessage
	storeLeaseMessagesErr = "could not store message leases for channel %s: %+v"
	storeLeaseChanIDsErr  = "could not store lease channel IDs: %+v"

	// actionLeaseList.load
	loadLeaseChanIDsErr  = "could not load list of channels: %+v"
	loadLeaseMessagesErr = "could not load message leases for channel %s: %+v"
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

	kv  *versioned.KV
	mux sync.RWMutex
}

// leaseMessage contains a message and an associated action.
type leaseMessage struct {
	// ChannelID is the ID of the channel that his message is in.
	ChannelID *id.ID `json:"channelID"`

	// The Target of the Action. This can be a message ID or user ID.
	Target []byte `json:"target"`

	// Action is the action applied to the message (currently only Pinned and
	// Hidden).
	Action MessageType `json:"action"`

	// LeaseEnd is the time (Unix nano) when the lease ends. It is the
	// calculated by adding the lease duration to the message's timestamp.
	LeaseEnd int64 `json:"leaseEnd"`

	// e is a link to this message in the lease list.
	e *list.Element
}

// newOrLoadActionLeaseList loads an existing actionLeaseList from storage, if
// it exists. Otherwise, it initialises a new empty actionLeaseList.
func newOrLoadActionLeaseList(kv *versioned.KV) (*actionLeaseList, error) {
	all := newActionLeaseList(kv)

	err := all.load()
	if err != nil && kv.Exists(err) {
		return nil, err
	}

	return all, nil
}

// newActionLeaseList initialises a new empty actionLeaseList.
func newActionLeaseList(kv *versioned.KV) *actionLeaseList {
	return &actionLeaseList{
		leases:   list.New(),
		messages: make(map[id.ID]map[leaseFingerprintKey]*leaseMessage),
		kv:       kv,
	}
}

// addMessage inserts the message into the lease list. If the message already
// exists, then its lease is updated.
func (all *actionLeaseList) addMessage(channelID *id.ID, target []byte,
	action MessageType, timestamp time.Time, lease time.Duration) error {
	fp := newLeaseFingerprint(channelID, target, action)
	leaseEnd := timestamp.Add(lease)
	newLm := &leaseMessage{
		ChannelID: channelID,
		Target:    target,
		Action:    action,
		LeaseEnd:  leaseEnd.UnixNano(),
	}

	all.mux.Lock()
	defer all.mux.Unlock()

	// When set to true, the list of channels IDs will be updated in storage
	var channelIdUpdate bool

	if messages, exists := all.messages[*channelID]; !exists {
		// Add the channel if it does not exist
		newLm.e = all.insertLease(newLm)
		all.messages[*channelID] =
			map[leaseFingerprintKey]*leaseMessage{fp.key(): newLm}
		channelIdUpdate = true
	} else if lm, exists2 := messages[fp.key()]; !exists2 {
		// Add the lease message if it does not exist
		newLm.e = all.insertLease(newLm)
		all.messages[*channelID][fp.key()] = newLm
	} else {
		// Update the lease message if it does exist
		lm.LeaseEnd = leaseEnd.UnixNano()
		all.updateLease(lm.e)
	}

	// Update storage
	return all.updateStorage(channelID, channelIdUpdate)
}

// removeMessage removes the list.Element contains a leaseMessage from the lease
// list and the message map. This function also updates storage.
func (all *actionLeaseList) removeMessage(e *list.Element) error {
	lm := e.Value.(*leaseMessage)

	// Remove from lease list
	all.leases.Remove(e)

	// When set to true, the list of channels IDs will be updated in storage
	var channelIdUpdate bool

	// Remove from message map
	delete(all.messages[*lm.ChannelID], newLeaseFingerprint(
		lm.ChannelID, lm.Target, lm.Action).key())
	if len(all.messages[*lm.ChannelID]) == 0 {
		delete(all.messages, *lm.ChannelID)
		channelIdUpdate = true
	}

	// Update storage
	return all.updateStorage(lm.ChannelID, channelIdUpdate)
}

// insertLease inserts the leaseMessage to the lease list in order.
func (all *actionLeaseList) insertLease(lm *leaseMessage) *list.Element {
	for mark := all.leases.Front(); mark != nil; mark = mark.Next() {
		if lm.LeaseEnd < mark.Value.(*leaseMessage).LeaseEnd {
			return all.leases.InsertBefore(lm, mark)
		}
	}
	return all.leases.PushBack(lm)
}

// updateLease updates the location of the given element. This should be called
// when the LeaseEnd for a message changes.
func (all *actionLeaseList) updateLease(e *list.Element) {
	leaseEnd := e.Value.(*leaseMessage).LeaseEnd
	for mark := all.leases.Front(); mark != nil; mark = mark.Next() {
		if leaseEnd < mark.Value.(*leaseMessage).LeaseEnd {
			all.leases.MoveBefore(e, mark)
			return
		}
	}
	all.leases.MoveToBack(e)
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
		return errors.Errorf(loadLeaseChanIDsErr, err)
	}

	// Get list of lease messages and load them into the message map and lease
	// list
	for _, channelID := range channelIDs {
		all.messages[*channelID], err = all.loadLeaseMessages(channelID)
		if err != nil {
			return errors.Errorf(loadLeaseMessagesErr, channelID, err)
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
	}
	if channelIdUpdate {
		if err := all.storeLeaseChannels(); err != nil {
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

// leaseFingerprint is a unique identifier for a channel message and an
// associated Action.
type leaseFingerprint [leaseFpLen]byte

// leaseFingerprintKey is the string form of leaseFingerprint.
type leaseFingerprintKey string

// newLeaseFingerprint generates a new leaseFingerprint from an Action and
// message ID.
func newLeaseFingerprint(
	channelID *id.ID, target []byte, action MessageType) leaseFingerprint {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf(
			"Failed to get hash to make lease fingerprint: %+v", err)
	}

	h.Write(channelID.Bytes())
	h.Write(target)
	h.Write(action.Bytes())

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
