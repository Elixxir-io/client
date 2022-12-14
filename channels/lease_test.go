////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/stoppable"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/comms/mixmessages"
	pb "gitlab.com/elixxir/comms/mixmessages"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/ekv"
	commsMessages "gitlab.com/xx_network/comms/messages"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"io"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Tests that newOrLoadActionLeaseList initialises a new empty actionLeaseList
// when called for the first time and that it loads the actionLeaseList from
// storage after the original has been saved.
func Test_newOrLoadActionLeaseList(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rng := fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG)
	expected := newActionLeaseList(nil, kv, rng)

	all, err := newOrLoadActionLeaseList(nil, kv, rng)
	if err != nil {
		t.Errorf("Failed to create new actionLeaseList: %+v", err)
	}

	all.addLeaseMessage = expected.addLeaseMessage
	all.removeLeaseMessage = expected.removeLeaseMessage
	all.removeChannelCh = expected.removeChannelCh
	if !reflect.DeepEqual(expected, all) {
		t.Errorf("New actionLeaseList does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, all)
	}

	lm := &leaseMessage{
		ChannelID:         newRandomChanID(prng, t),
		Action:            newRandomAction(prng, t),
		Payload:           newRandomPayload(prng, t),
		Timestamp:         newRandomLeaseEnd(prng, t),
		OriginalTimestamp: newRandomLeaseEnd(prng, t),
		Lease:             time.Hour,
		LeaseEnd:          newRandomLeaseEnd(prng, t).UnixNano(),
		LeaseTrigger:      newRandomLeaseEnd(prng, t).UnixNano(),
		Round:             rounds.Round{},
	}
	err = all._addMessage(lm)
	if err != nil {
		t.Errorf("Failed to add message: %+v", err)
	}

	loadedAll, err := newOrLoadActionLeaseList(nil, kv, rng)
	if err != nil {
		t.Errorf("Failed to load actionLeaseList: %+v", err)
	}

	all.addLeaseMessage = loadedAll.addLeaseMessage
	all.removeLeaseMessage = loadedAll.removeLeaseMessage
	all.removeChannelCh = loadedAll.removeChannelCh
	if !reflect.DeepEqual(all, loadedAll) {
		t.Errorf("Loaded actionLeaseList does not match expected."+
			"\nexpected: %+v\nreceived: %+v", all, loadedAll)
	}
}

// Tests that newActionLeaseList returns the expected new actionLeaseList.
func Test_newActionLeaseList(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	rng := fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG)
	expected := &actionLeaseList{
		leases:             list.New(),
		messages:           make(map[id.ID]map[leaseFingerprintKey]*leaseMessage),
		addLeaseMessage:    make(chan *leaseMessage, addLeaseMessageChanSize),
		removeLeaseMessage: make(chan *leaseMessage, removeLeaseMessageChanSize),
		removeChannelCh:    make(chan *id.ID, removeChannelChChanSize),
		triggerFn:          nil,
		kv:                 kv,
		rng:                rng,
	}

	all := newActionLeaseList(nil, kv, rng)
	all.addLeaseMessage = expected.addLeaseMessage
	all.removeLeaseMessage = expected.removeLeaseMessage
	all.removeChannelCh = expected.removeChannelCh

	if !reflect.DeepEqual(expected, all) {
		t.Errorf("New actionLeaseList does not match expected."+
			"\nexpected: %#v\nreceived: %#v", expected, all)
	}
}

// Tests that actionLeaseList.updateLeasesThread removes the expected number of
// lease messages when they expire.
func Test_actionLeaseList(t *testing.T) {
	// jww.SetStdoutThreshold(jww.LevelTrace)
	prng := rand.New(rand.NewSource(32))
	triggerChan := make(chan *leaseMessage, 3)
	trigger := func(channelID *id.ID, _ cryptoChannel.MessageID,
		messageType MessageType, nickname string, payload, _ []byte, timestamp,
		originalTimestamp time.Time, lease time.Duration, _ rounds.Round,
		_ id.Round, _ SentStatus, _, _ bool) (uint64, error) {
		triggerChan <- &leaseMessage{
			ChannelID:         channelID,
			Action:            messageType,
			Nickname:          nickname,
			Payload:           payload,
			Timestamp:         timestamp,
			OriginalTimestamp: originalTimestamp,
		}
		return 0, nil
	}
	all := newActionLeaseList(trigger, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	stop := stoppable.NewSingle(leaseThreadStoppable)
	go all.updateLeasesThread(stop)

	expectedMessages := map[time.Duration]*leaseMessage{
		50 * time.Millisecond: {
			ChannelID:         newRandomChanID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "A",
			Payload:           newRandomPayload(prng, t),
			Timestamp:         netTime.Now().UTC(),
			OriginalTimestamp: netTime.Now().UTC(),
		},
		200 * time.Millisecond: {
			ChannelID:         newRandomChanID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "B",
			Payload:           newRandomPayload(prng, t),
			Timestamp:         netTime.Now().UTC(),
			OriginalTimestamp: netTime.Now().UTC(),
		},
		400 * time.Millisecond: {
			ChannelID:         newRandomChanID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "C",
			Payload:           newRandomPayload(prng, t),
			Timestamp:         netTime.Now().UTC(),
			OriginalTimestamp: netTime.Now().UTC(),
		},
		600 * time.Hour: { // This tests the replay code
			ChannelID:         newRandomChanID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "D",
			Payload:           newRandomPayload(prng, t),
			Timestamp:         netTime.Now().UTC(),
			OriginalTimestamp: netTime.Now().UTC().Add(-time.Hour),
		},
	}

	for lease, e := range expectedMessages {
		all.addMessage(ReceiveMessageValues{e.ChannelID, e.MessageID, e.Action,
			e.Nickname, nil, e.EncryptedPayload, nil, 0, e.Timestamp,
			e.OriginalTimestamp, lease, rounds.Round{ID: 5}, 5, 0, e.FromAdmin,
			false}, e.Payload)
	}

	fp := newLeaseFingerprint(expectedMessages[600*time.Hour].ChannelID,
		expectedMessages[600*time.Hour].Action,
		expectedMessages[600*time.Hour].Payload)

	// Modify lease trigger of 600*time.Hour so the test doesn't take hours
	for {
		messages, exists :=
			all.messages[*expectedMessages[600*time.Hour].ChannelID]
		if exists {
			if _, exists = messages[fp.key()]; exists {
				all.messages[*expectedMessages[600*time.Hour].
					ChannelID][fp.key()].LeaseTrigger =
					netTime.Now().Add(600 * time.Millisecond).UnixNano()
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}

	select {
	case lm := <-triggerChan:
		expected := expectedMessages[50*time.Millisecond]
		if !reflect.DeepEqual(expected, lm) {
			t.Errorf("Did not receive expected lease message."+
				"\nexpected: %+v\nreceived: %+v", expected, lm)
		}
		// all.removeMessage(lm.ChannelID, lm.Action, lm.Payload)
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Timed out waiting for message to be triggered.")
	}

	select {
	case lm := <-triggerChan:
		expected := expectedMessages[200*time.Millisecond]
		if !reflect.DeepEqual(expected, lm) {
			t.Errorf("Did not receive expected lease message."+
				"\nexpected: %+v\nreceived: %+v", expected, lm)
		}
		// all.removeMessage(lm.ChannelID, lm.Action, lm.Payload)
	case <-time.After(200 * time.Millisecond):
		t.Errorf("Timed out waiting for message to be triggered.")
	}

	select {
	case lm := <-triggerChan:
		expected := expectedMessages[400*time.Millisecond]
		if !reflect.DeepEqual(expected, lm) {
			t.Errorf("Did not receive expected lease message."+
				"\nexpected: %+v\nreceived: %+v", expected, lm)
		}
		// all.removeMessage(lm.ChannelID, lm.Action, lm.Payload)
	case <-time.After(400 * time.Millisecond):
		t.Errorf("Timed out waiting for message to be triggered.")
	}

	select {
	case lm := <-triggerChan:
		expected := expectedMessages[600*time.Hour]
		if !reflect.DeepEqual(expected, lm) {
			t.Errorf("Did not receive expected lease message."+
				"\nexpected: %+v\nreceived: %+v", expected, lm)
		}
		// all.removeMessage(lm.ChannelID, lm.Action, lm.Payload)
	case <-time.After(800 * time.Millisecond):
		t.Errorf("Timed out waiting for message to be triggered.")
	}

	if err := stop.Close(); err != nil {
		t.Errorf("Failed to close thread: %+v", err)
	}
}

// Tests that actionLeaseList.updateLeasesThread adds and removes a lease
// channel.
func Test_actionLeaseList_updateLeasesThread_AddAndRemove(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	stop := stoppable.NewSingle(leaseThreadStoppable)
	go all.updateLeasesThread(stop)

	timestamp, lease := netTime.Now().UTC(), time.Hour*50
	exp := &leaseMessage{
		ChannelID:         newRandomChanID(prng, t),
		MessageID:         newRandomMessageID(prng, t),
		Action:            newRandomAction(prng, t),
		Nickname:          "George",
		Payload:           newRandomPayload(prng, t),
		EncryptedPayload:  newRandomPayload(prng, t),
		Timestamp:         timestamp,
		OriginalTimestamp: timestamp,
		Lease:             lease,
		LeaseEnd:          timestamp.Add(lease).UnixNano(),
		LeaseTrigger:      timestamp.Add(lease).UnixNano(),
		Round:             rounds.Round{ID: 5},
		OriginalRoundID:   5,
		Status:            Delivered,
		FromAdmin:         false,
		e:                 nil,
	}
	fp := newLeaseFingerprint(
		exp.ChannelID, exp.Action, exp.Payload)

	all.addMessage(ReceiveMessageValues{exp.ChannelID, exp.MessageID,
		exp.Action, exp.Nickname, nil, exp.EncryptedPayload, nil, 0, timestamp,
		timestamp, lease, exp.Round, exp.OriginalRoundID, exp.Status,
		exp.FromAdmin, false}, exp.Payload)

	done := make(chan struct{})
	go func() {
		for len(all.messages) < 1 {
			time.Sleep(time.Millisecond)
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Millisecond):
		t.Errorf("Timed out waiting for message to be added to message map.")
	}

	lm := all.leases.Front().Value.(*leaseMessage)
	exp.e = lm.e
	exp.LeaseTrigger = lm.LeaseTrigger
	if !reflect.DeepEqual(exp, lm) {
		t.Errorf("Unexpected lease message added to lease list."+
			"\nexpected: %+v\nreceived: %+v", exp, lm)
	}

	if messages, exists := all.messages[*exp.ChannelID]; !exists {
		t.Errorf("Channel %s not found in message map.", exp.ChannelID)
	} else if lm, exists = messages[fp.key()]; !exists {
		t.Errorf("Message with fingerprint %s not found in message map.", fp)
	} else if !reflect.DeepEqual(exp, lm) {
		t.Errorf("Unexpected lease message added to message map."+
			"\nexpected: %+v\nreceived: %+v", exp, lm)
	}

	all.removeMessage(exp.ChannelID, exp.Action, exp.Payload)

	done = make(chan struct{})
	go func() {
		for len(all.messages) != 0 {
			time.Sleep(time.Millisecond)
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Millisecond):
		t.Error("Timed out waiting for message to be removed from message map.")
	}

	if all.leases.Len() != 0 {
		t.Errorf("%d messages left in lease list.", all.leases.Len())
	}

	if err := stop.Close(); err != nil {
		t.Errorf("Failed to close thread: %+v", err)
	}
}

// Tests that actionLeaseList.removeChannel removes all leases for the channel
// from the list.
func Test_actionLeaseList_removeChannel(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	stop := stoppable.NewSingle(leaseThreadStoppable)
	go all.updateLeasesThread(stop)

	var channelID *id.ID
	for i := 0; i < 5; i++ {
		channelID = newRandomChanID(prng, t)
		for j := 0; j < 5; j++ {
			exp := &leaseMessage{
				ChannelID:         channelID,
				MessageID:         newRandomMessageID(prng, t),
				Action:            newRandomAction(prng, t),
				Nickname:          "George",
				Payload:           newRandomPayload(prng, t),
				EncryptedPayload:  newRandomPayload(prng, t),
				Timestamp:         netTime.Now(),
				OriginalTimestamp: netTime.Now(),
				Lease:             newRandomLease(prng, t),
				LeaseEnd:          newRandomLeaseEnd(prng, t).UnixNano(),
				LeaseTrigger:      newRandomLeaseEnd(prng, t).UnixNano(),
				Round:             rounds.Round{ID: 5},
				OriginalRoundID:   5,
				Status:            Delivered,
				FromAdmin:         false,
				e:                 nil,
			}

			all.addMessage(ReceiveMessageValues{exp.ChannelID, exp.MessageID,
				exp.Action, exp.Nickname, nil, exp.EncryptedPayload, nil, 0,
				exp.Timestamp, exp.OriginalTimestamp, exp.Lease, exp.Round,
				exp.OriginalRoundID, exp.Status, exp.FromAdmin, false},
				exp.Payload)
		}
	}

	done := make(chan struct{})
	go func() {
		for len(all.messages) < 5 {
			time.Sleep(time.Millisecond)
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Millisecond):
		t.Errorf("Timed out waiting for messages to be added to message map.")
	}

	all.removeChannel(channelID)

	done = make(chan struct{})
	go func() {
		for len(all.messages) > 4 {
			time.Sleep(time.Millisecond)
		}
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Millisecond):
		t.Error("Timed out waiting for message to be removed from message map.")
	}

	if all.leases.Len() != 20 {
		t.Errorf("%d messages left in lease list when %d expected.",
			all.leases.Len(), 20)
	}

	if err := stop.Close(); err != nil {
		t.Errorf("Failed to close thread: %+v", err)
	}
}

// Tests that actionLeaseList.updateLeasesThread stops the stoppable when
// triggered and returns.
func Test_actionLeaseList_updateLeasesThread_Stoppable(t *testing.T) {
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	stop := stoppable.NewSingle(leaseThreadStoppable)
	stopped := make(chan struct{})
	go func() {
		all.updateLeasesThread(stop)
		stopped <- struct{}{}
	}()

	if err := stop.Close(); err != nil {
		t.Errorf("Failed to close thread: %+v", err)
	}

	select {
	case <-stopped:
		if !stop.IsStopped() {
			t.Errorf("Stoppable not stopped.")
		}
	case <-time.After(5 * time.Millisecond):
		t.Errorf("Timed out waitinf for updateLeasesThread to return")
	}
}

// Tests that actionLeaseList.addMessage sends the expected leaseMessage on the
// addLeaseMessage channel.
func Test_actionLeaseList_addMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	timestamp := newRandomLeaseEnd(prng, t)
	lease := newRandomLease(prng, t)
	exp := &leaseMessage{
		ChannelID:         newRandomChanID(prng, t),
		MessageID:         newRandomMessageID(prng, t),
		Action:            newRandomAction(prng, t),
		Nickname:          "MyNickname",
		Payload:           newRandomPayload(prng, t),
		EncryptedPayload:  newRandomPayload(prng, t),
		Timestamp:         timestamp,
		OriginalTimestamp: timestamp,
		Lease:             lease,
		LeaseEnd:          0,
		LeaseTrigger:      0,
		Round:             rounds.Round{ID: 5},
		OriginalRoundID:   5,
		Status:            Delivered,
		FromAdmin:         false,
		e:                 nil,
	}

	all.addMessage(ReceiveMessageValues{exp.ChannelID, exp.MessageID,
		exp.Action, exp.Nickname, nil, exp.EncryptedPayload, nil, 0,
		exp.Timestamp, exp.OriginalTimestamp, exp.Lease, exp.Round,
		exp.OriginalRoundID, exp.Status, exp.FromAdmin, false}, exp.Payload)

	select {
	case lm := <-all.addLeaseMessage:
		exp.LeaseTrigger = lm.LeaseTrigger
		if !reflect.DeepEqual(exp, lm) {
			t.Errorf("leaseMessage does not match expected."+
				"\nexpected: %+v\nreceived: %+v", exp, lm)
		}
	case <-time.After(5 * time.Millisecond):
		t.Error("Timed out waiting on addLeaseMessage.")
	}
}

// Tests that actionLeaseList._addMessage adds all the messages to both the
// lease list and the message map and that the lease list is in the correct
// order.
func Test_actionLeaseList__addMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	const m, n, o = 20, 5, 3
	expected := make([]*leaseMessage, 0, m*n*o)
	for i := 0; i < m; i++ {
		// Make multiple messages with same channel ID
		channelID := newRandomChanID(prng, t)

		for j := 0; j < n; j++ {
			// Make multiple messages with same payload (but different actions
			// and leases)
			payload := newRandomPayload(prng, t)
			encrypted := newRandomPayload(prng, t)

			for k := 0; k < o; k++ {
				timestamp := newRandomLeaseEnd(prng, t)
				lease := newRandomLease(prng, t)
				lm := &leaseMessage{
					ChannelID:        channelID,
					Action:           MessageType(k),
					Payload:          payload,
					EncryptedPayload: encrypted,
					LeaseEnd:         timestamp.Add(lease).UnixNano(),
					LeaseTrigger:     timestamp.Add(lease).UnixNano(),
				}
				expected = append(expected, lm)

				err := all._addMessage(lm)
				if err != nil {
					t.Errorf("Failed to add message: %+v", err)
				}
			}
		}
	}

	// Check that the message map has all the expected messages
	for i, exp := range expected {
		fp := newLeaseFingerprint(exp.ChannelID, exp.Action, exp.Payload)
		if messages, exists := all.messages[*exp.ChannelID]; !exists {
			t.Errorf("Channel %s does not exist (%d).", exp.ChannelID, i)
		} else if lm, exists2 := messages[fp.key()]; !exists2 {
			t.Errorf("No lease message found with key %s (%d).", fp.key(), i)
		} else {
			lm.e = nil
			if !reflect.DeepEqual(exp, lm) {
				t.Errorf("leaseMessage does not match expected (%d)."+
					"\nexpected: %+v\nreceived: %+v", i, exp, lm)
			}
		}
	}

	// Check that the lease list has all the expected messages in the correct
	// order
	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i].LeaseTrigger < expected[j].LeaseTrigger
	})
	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i].LeaseTrigger != e.Value.(*leaseMessage).LeaseTrigger {
			t.Errorf("leaseMessage %d not in correct order."+
				"\nexpected: %+v\nreceived: %+v",
				i, expected[i], e.Value.(*leaseMessage))
		}
	}
}

// Tests that after updating half the messages, actionLeaseList._addMessage
// moves the messages to the lease list is still in order.
func Test_actionLeaseList__addMessage_Update(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	const m, n, o = 20, 5, 3
	expected := make([]*leaseMessage, 0, m*n*o)
	for i := 0; i < m; i++ {
		// Make multiple messages with same channel ID
		channelID := newRandomChanID(prng, t)

		for j := 0; j < n; j++ {
			// Make multiple messages with same payload (but different actions
			// and leases)
			payload := newRandomPayload(prng, t)
			encrypted := newRandomPayload(prng, t)

			for k := 0; k < o; k++ {
				timestamp := newRandomLeaseEnd(prng, t)
				lease := newRandomLease(prng, t)
				lm := &leaseMessage{
					ChannelID:        channelID,
					Action:           MessageType(k),
					Payload:          payload,
					EncryptedPayload: encrypted,
					LeaseEnd:         timestamp.Add(lease).UnixNano(),
					LeaseTrigger:     timestamp.Add(lease).UnixNano(),
				}
				expected = append(expected, lm)

				err := all._addMessage(lm)
				if err != nil {
					t.Errorf("Failed to add message: %+v", err)
				}
			}
		}
	}

	// Update the time of half the messages.
	for i, lm := range expected {
		if i%2 == 0 {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm.LeaseTrigger = timestamp.Add(lease).UnixNano()

			err := all._addMessage(lm)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Check that the order is still correct
	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i].LeaseTrigger < expected[j].LeaseTrigger
	})
	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i].LeaseTrigger != e.Value.(*leaseMessage).LeaseTrigger {
			t.Errorf("leaseMessage %d not in correct order."+
				"\nexpected: %+v\nreceived: %+v",
				i, expected[i], e.Value.(*leaseMessage))
		}
	}
}

// Tests that actionLeaseList.removeMessage sends the expected leaseMessage on
// the removeLeaseMessage channel.
func Test_actionLeaseList_removeMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	exp := &leaseMessage{
		ChannelID: newRandomChanID(prng, t),
		Action:    newRandomAction(prng, t),
		Payload:   newRandomPayload(prng, t),
	}

	all.removeMessage(exp.ChannelID, exp.Action, exp.Payload)

	select {
	case lm := <-all.removeLeaseMessage:
		if !reflect.DeepEqual(exp, lm) {
			t.Errorf("leaseMessage does not match expected."+
				"\nexpected: %+v\nreceived: %+v", exp, lm)
		}
	case <-time.After(5 * time.Millisecond):
		t.Error("Timed out waiting on removeLeaseMessage.")
	}
}

// Tests that actionLeaseList._removeMessage removes all the messages from both
// the lease list and the message map and that the lease list remains in the
// correct order after every removal.
func Test_actionLeaseList__removeMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	const m, n, o = 20, 5, 3
	expected := make([]*leaseMessage, 0, m*n*o)
	for i := 0; i < m; i++ {
		// Make multiple messages with same channel ID
		channelID := newRandomChanID(prng, t)

		for j := 0; j < n; j++ {
			// Make multiple messages with same payload (but different actions
			// and leases)
			payload := newRandomPayload(prng, t)
			encrypted := newRandomPayload(prng, t)

			for k := 0; k < o; k++ {
				lm := &leaseMessage{
					ChannelID:        channelID,
					Action:           MessageType(k),
					Payload:          payload,
					EncryptedPayload: encrypted,
					LeaseEnd:         newRandomLeaseEnd(prng, t).UnixNano(),
					LeaseTrigger:     newRandomLeaseEnd(prng, t).UnixNano(),
				}
				fp := newLeaseFingerprint(channelID, lm.Action, payload)
				err := all._addMessage(lm)
				if err != nil {
					t.Errorf("Failed to add message: %+v", err)
				}

				expected = append(expected, all.messages[*channelID][fp.key()])
			}
		}
	}

	// Check that the message map has all the expected messages
	for i, exp := range expected {
		fp := newLeaseFingerprint(exp.ChannelID, exp.Action, exp.Payload)
		if messages, exists := all.messages[*exp.ChannelID]; !exists {
			t.Errorf("Channel %s does not exist (%d).", exp.ChannelID, i)
		} else if lm, exists2 := messages[fp.key()]; !exists2 {
			t.Errorf("No lease message found with key %s (%d).", fp.key(), i)
		} else {
			if !reflect.DeepEqual(exp, lm) {
				t.Errorf("leaseMessage does not match expected (%d)."+
					"\nexpected: %+v\nreceived: %+v", i, exp, lm)
			}
		}
	}

	for i, exp := range expected {
		err := all._removeMessage(exp)
		if err != nil {
			t.Errorf("Failed to remove message %d: %+v", i, exp)
		}

		// Check that the message was removed from the map
		fp := newLeaseFingerprint(exp.ChannelID, exp.Action, exp.Payload)
		if messages, exists := all.messages[*exp.ChannelID]; exists {
			if _, exists = messages[fp.key()]; exists {
				t.Errorf(
					"Removed leaseMessage found with key %s (%d).", fp.key(), i)
			}
		}

		// Check that the lease list is in order
		for e := all.leases.Front(); e != nil && e.Next() != nil; e = e.Next() {
			// Check that the message does not exist in the list
			if reflect.DeepEqual(exp, e.Value) {
				t.Errorf(
					"Removed leaseMessage found in list (%d): %+v", i, e.Value)
			}
			if e.Value.(*leaseMessage).LeaseTrigger >
				e.Next().Value.(*leaseMessage).LeaseTrigger {
				t.Errorf("Lease list not in order.")
			}
		}
	}
}

// Tests that actionLeaseList._removeMessage does nothing and returns nil when
// removing a message that does not exist.
func Test_actionLeaseList__removeMessage_NonExistentMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	const m, n, o = 20, 5, 3
	expected := make([]*leaseMessage, 0, m*n*o)
	for i := 0; i < m; i++ {
		// Make multiple messages with same channel ID
		channelID := newRandomChanID(prng, t)

		for j := 0; j < n; j++ {
			// Make multiple messages with same payload (but different actions
			// and leases)
			payload := newRandomPayload(prng, t)
			encrypted := newRandomPayload(prng, t)

			for k := 0; k < o; k++ {
				lm := &leaseMessage{
					ChannelID:        channelID,
					Action:           MessageType(k),
					Payload:          payload,
					EncryptedPayload: encrypted,
					LeaseEnd:         newRandomLeaseEnd(prng, t).UnixNano(),
					LeaseTrigger:     newRandomLeaseEnd(prng, t).UnixNano(),
				}
				fp := newLeaseFingerprint(channelID, lm.Action, payload)
				err := all._addMessage(lm)
				if err != nil {
					t.Errorf("Failed to add message: %+v", err)
				}

				expected = append(expected, all.messages[*channelID][fp.key()])
			}
		}
	}

	err := all._removeMessage(&leaseMessage{
		ChannelID:    newRandomChanID(prng, t),
		Action:       newRandomAction(prng, t),
		Payload:      newRandomPayload(prng, t),
		LeaseEnd:     newRandomLeaseEnd(prng, t).UnixNano(),
		LeaseTrigger: newRandomLeaseEnd(prng, t).UnixNano(),
	})
	if err != nil {
		t.Errorf("Error removing message that does not exist: %+v", err)
	}

	if all.leases.Len() != len(expected) {
		t.Errorf("Unexpected length of lease list.\nexpected: %d\nreceived: %d",
			len(expected), all.leases.Len())
	}

	if len(all.messages) != m {
		t.Errorf("Unexpected length of message channels."+
			"\nexpected: %d\nreceived: %d", m, len(all.messages))
	}

	for chID, messages := range all.messages {
		if len(messages) != n*o {
			t.Errorf("Unexpected length of messages for channel %s."+
				"\nexpected: %d\nreceived: %d", chID, n*o, len(messages))
		}
	}
}

// Tests that actionLeaseList.insertLease inserts all the leaseMessage in the
// correct order, from smallest LeaseTrigger to largest.
func Test_actionLeaseList_insertLease(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	expected := make([]int64, 50)

	for i := range expected {
		randomTime := time.Unix(0, prng.Int63())
		all.insertLease(&leaseMessage{LeaseTrigger: randomTime.UnixNano()})
		expected[i] = randomTime.UnixNano()
	}

	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i] < expected[j]
	})

	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i] != e.Value.(*leaseMessage).LeaseTrigger {
			t.Errorf("Timestamp %d not in correct order."+
				"\nexpected: %d\nreceived: %d",
				i, expected[i], e.Value.(*leaseMessage).LeaseTrigger)
		}
	}
}

// Fills the lease list with in-order messages and tests that
// actionLeaseList.updateLease correctly moves elements to the correct order
// when their LeaseTrigger changes.
func Test_actionLeaseList_updateLease(t *testing.T) {
	prng := rand.New(rand.NewSource(32_142))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	for i := 0; i < 50; i++ {
		randomTime := time.Unix(0, prng.Int63()).UTC().Round(0)
		all.insertLease(&leaseMessage{LeaseTrigger: randomTime.UnixNano()})
	}

	tests := []struct {
		randomTime int64
		e          *list.Element
	}{
		// Change the first element to a random time
		{prng.Int63(), all.leases.Front()},

		// Change an element to a random time
		{prng.Int63(), all.leases.Front().Next().Next().Next()},

		// Change the last element to a random time
		{prng.Int63(), all.leases.Back()},

		// Change an element to the first element
		{all.leases.Front().Value.(*leaseMessage).LeaseTrigger - 1,
			all.leases.Front().Next().Next()},

		// Change an element to the last element
		{all.leases.Back().Value.(*leaseMessage).LeaseTrigger + 1,
			all.leases.Front().Next().Next().Next().Next().Next()},
	}

	for i, tt := range tests {
		tt.e.Value.(*leaseMessage).LeaseTrigger = tt.randomTime
		all.updateLease(tt.e)

		// Check that the list is in order
		for j, n := 0, all.leases.Front(); n.Next() != nil; j, n = j+1, n.Next() {
			lt1 := n.Value.(*leaseMessage).LeaseTrigger
			lt2 := n.Next().Value.(*leaseMessage).LeaseTrigger
			if lt1 > lt2 {
				t.Errorf("Element #%d is greater than element #%d (%d)."+
					"\nelement #%d: %d\nelement #%d: %d",
					j, j+1, i, j, lt1, j+1, lt2)
			}
		}
	}
}

// Tests that actionLeaseList._removeChannel removes all the messages from both
// the lease list and the message map for the given channel and that the lease
// list remains in the correct order after removal.
func Test_actionLeaseList__removeChannel(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	const m, n, o = 20, 5, 3
	expected := make([]*leaseMessage, 0, m*n*o)
	for i := 0; i < m; i++ {
		// Make multiple messages with same channel ID
		channelID := newRandomChanID(prng, t)

		for j := 0; j < n; j++ {
			// Make multiple messages with same payload (but different actions
			// and leases)
			payload := newRandomPayload(prng, t)
			encrypted := newRandomPayload(prng, t)

			for k := 0; k < o; k++ {
				lm := &leaseMessage{
					ChannelID:        channelID,
					Action:           MessageType(k),
					Payload:          payload,
					EncryptedPayload: encrypted,
					LeaseEnd:         newRandomLeaseEnd(prng, t).UnixNano(),
					LeaseTrigger:     newRandomLeaseEnd(prng, t).UnixNano(),
				}
				fp := newLeaseFingerprint(channelID, lm.Action, payload)
				err := all._addMessage(lm)
				if err != nil {
					t.Errorf("Failed to add message: %+v", err)
				}

				expected = append(expected, all.messages[*channelID][fp.key()])
			}
		}
	}

	// Check that the message map has all the expected messages
	for i, exp := range expected {
		fp := newLeaseFingerprint(exp.ChannelID, exp.Action, exp.Payload)
		if messages, exists := all.messages[*exp.ChannelID]; !exists {
			t.Errorf("Channel %s does not exist (%d).", exp.ChannelID, i)
		} else if lm, exists2 := messages[fp.key()]; !exists2 {
			t.Errorf("No lease message found with key %s (%d).", fp.key(), i)
		} else {
			if !reflect.DeepEqual(exp, lm) {
				t.Errorf("leaseMessage does not match expected (%d)."+
					"\nexpected: %+v\nreceived: %+v", i, exp, lm)
			}
		}
	}

	// Get random channel ID
	var channelID id.ID
	for channelID = range all.messages {
		break
	}

	err := all._removeChannel(&channelID)
	if err != nil {
		t.Errorf("Failed to remove channel: %+v", err)
	}

	for e := all.leases.Front(); e != nil && e.Next() != nil; e = e.Next() {
		// Check that the message does not exist in the list
		if e.Value.(*leaseMessage).ChannelID.Cmp(&channelID) {
			t.Errorf(
				"Found lease message from channel %s: %+v", channelID, e.Value)
		}
		if e.Value.(*leaseMessage).LeaseTrigger >
			e.Next().Value.(*leaseMessage).LeaseTrigger {
			t.Errorf("Lease list not in order.")
		}
	}

	// Test removing a channel that does not exist
	err = all._removeChannel(newRandomChanID(prng, t))
	if err != nil {
		t.Errorf("Error when removing non-existent channel: %+v", err)
	}
}

// Tests that calculateLeaseTrigger returns times within the expected
// window. Runs the test many times to ensure no numbers fall outside the range.
func Test_calculateLeaseTrigger(t *testing.T) {
	rng := csprng.NewSystemRNG()
	ts := time.Date(1955, 11, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		lease                                       time.Duration
		now, timestamp, originalTimestamp, expected time.Time
	}{
		{time.Hour, ts, ts, ts, ts.Add(time.Hour)},
		{time.Hour, ts, ts, ts.Add(-time.Minute), ts.Add(time.Hour - time.Minute)},
		{MessageLife, ts, ts, ts.Add(-MessageLife / 2), ts.Add(MessageLife / 2)},
		{MessageLife, ts, ts, ts, time.Time{}},
		{MessageLife * 3 / 2, ts, ts, ts.Add(-time.Minute), time.Time{}},
		{ValidForever, ts, ts, ts.Add(-2000 * time.Hour), time.Time{}},
	}

	// for i := 0; i < 100; i++ {
	for j, tt := range tests {
		leaseTrigger := calculateLeaseTrigger(
			tt.now, tt.timestamp, tt.originalTimestamp, tt.lease, rng)
		if tt.expected != (time.Time{}) {
			if !leaseTrigger.Equal(tt.expected) {
				t.Errorf("lease trigger duration does not match expected "+
					"(%d).\nexpected: %s\nreceived: %s",
					j, tt.expected, leaseTrigger)
			}
		} else {
			floor := tt.timestamp.Add(MessageLife / 2)
			ceiling := tt.timestamp.Add(MessageLife - (MessageLife / 10))
			if leaseTrigger.Before(floor) {
				t.Errorf("lease trigger occurs before the floor (%d)."+
					"\nfloor:   %s\ntrigger: %s", j, floor, leaseTrigger)
			} else if leaseTrigger.After(ceiling) {
				t.Errorf("lease trigger occurs after the ceiling (%d)."+
					"\nceiling:  %s\ntrigger: %s", j, ceiling, leaseTrigger)
			}
		}
	}
}

// Tests that randDurationInRange returns positive unique numbers in range.
func Test_randDurationInRange(t *testing.T) {
	prng := rand.New(rand.NewSource(684_532))
	rng := csprng.NewSystemRNG()
	const n = 10_000
	ints := make(map[time.Duration]struct{}, n)

	for i := 0; i < n; i++ {
		start := time.Duration(prng.Int63()) / 2
		end := start + time.Duration(prng.Int63())/2

		num := randDurationInRange(start, end, rng)
		if num < start {
			t.Errorf("Int #%d is less than start.\nstart:   %d\nreceived: %d",
				i, start, num)
		} else if num > end {
			t.Errorf("Int #%d is greater than end.\nend:     %d\nreceived: %d",
				i, end, num)
		}

		if _, exists := ints[num]; exists {
			t.Errorf("Int #%d already generated: %d", i, num)
		} else {
			ints[num] = struct{}{}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Storage Functions                                                          //
////////////////////////////////////////////////////////////////////////////////

// Tests that actionLeaseList.load loads an actionLeaseList from storage that
// matches the original.
func Test_actionLeaseList_load(t *testing.T) {
	prng := rand.New(rand.NewSource(23))
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	nid1 := id.NewIdFromString("test01", id.Node, t)
	now := uint64(netTime.Now().UnixNano())
	ri := &mixmessages.RoundInfo{
		ID:        5,
		UpdateID:  1,
		State:     2,
		BatchSize: 150,
		Topology:  [][]byte{nid1.Bytes()},
		Timestamps: []uint64{now - 1000, now - 800, now - 600, now - 400,
			now - 200, now, now + 200},
		Errors: []*mixmessages.RoundError{{
			Id:     uint64(49),
			NodeId: nid1.Bytes(),
			Error:  "Test error",
		}},
		ClientErrors: []*pb.ClientError{
			{ClientId: id.NewIdFromString("ClientId", id.Node, t).Marshal(),
				Error:  "Client Error",
				Source: id.NewIdFromString("Source", id.Node, t).Marshal()}},
		ResourceQueueTimeoutMillis: uint32(376 * time.Millisecond),
		Signature: &commsMessages.RSASignature{
			Nonce:     []byte("RSASignatureNonce"),
			Signature: []byte("RSASignatureSignature"),
		},
		AddressSpaceSize: 8,
		EccSignature: &commsMessages.ECCSignature{
			Nonce:     []byte("ECCSignatureNonce"),
			Signature: []byte("ECCSignatureSignature"),
		},
	}

	for i := 0; i < 10; i++ {
		channelID := newRandomChanID(prng, t)
		for j := 0; j < 5; j++ {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm := &leaseMessage{
				ChannelID:         channelID,
				MessageID:         newRandomMessageID(prng, t),
				Action:            newRandomAction(prng, t),
				Nickname:          "Username",
				Payload:           newRandomPayload(prng, t),
				EncryptedPayload:  newRandomPayload(prng, t),
				Timestamp:         timestamp,
				OriginalTimestamp: timestamp,
				Lease:             lease,
				LeaseEnd:          timestamp.Add(lease).UnixNano(),
				LeaseTrigger:      timestamp.Add(lease).UnixNano(),
				Round:             rounds.MakeRound(ri),
				OriginalRoundID:   id.Round(ri.ID),
				Status:            Delivered,
				FromAdmin:         false,
				e:                 nil,
			}

			err := all._addMessage(lm)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Create new list and load old contents into it
	loadedAll := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	err := loadedAll.load(time.Unix(0, 0))
	if err != nil {
		t.Errorf("Failed to load actionLeaseList from storage: %+v", err)
	}

	// Check that the loaded message map matches the original
	for chanID, messages := range all.messages {
		loadedMessages, exists := loadedAll.messages[chanID]
		if !exists {
			t.Errorf("Channel ID %s does not exist in map.", chanID)
		}

		for fp, lm := range messages {
			loadedLm, exists2 := loadedMessages[fp]
			if !exists2 {
				t.Errorf("Lease message does not exist in map: %+v", lm)
			}

			lm.e, loadedLm.e = nil, nil
			if !reflect.DeepEqual(lm, loadedLm) {
				t.Errorf("leaseMessage does not match expected."+
					"\nexpected: %+v\nreceived: %+v", lm, loadedLm)
			}
		}
	}

	// Check that the loaded lease list matches the original
	e1, e2 := all.leases.Front(), loadedAll.leases.Front()
	for ; e1 != nil; e1, e2 = e1.Next(), e2.Next() {
		if !reflect.DeepEqual(e1.Value, e2.Value) {
			t.Errorf("Element does not match expected."+
				"\nexpected: %+v\nreceived: %+v", e1.Value, e2.Value)
		}
	}
}

// Tests that when actionLeaseList.load loads a leaseMessage with a leaseTrigger
// in the past, that a new one is randomly calculated between replayWaitMin and
// replayWaitMax.
func Test_actionLeaseList_load_LeaseModify(t *testing.T) {
	prng := rand.New(rand.NewSource(23))
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	now := time.Date(1955, 11, 5, 12, 0, 0, 0, time.UTC)
	lease := time.Hour
	timestamp := now.Add(-6 * time.Hour)
	lm := &leaseMessage{
		ChannelID:         newRandomChanID(prng, t),
		MessageID:         newRandomMessageID(prng, t),
		Action:            newRandomAction(prng, t),
		Nickname:          "Username",
		Payload:           newRandomPayload(prng, t),
		EncryptedPayload:  newRandomPayload(prng, t),
		Timestamp:         timestamp,
		OriginalTimestamp: timestamp,
		Lease:             lease,
		LeaseEnd:          timestamp.Add(lease).UnixNano(),
		LeaseTrigger:      timestamp.Add(lease).UnixNano(),
		Status:            Delivered,
		FromAdmin:         false,
		e:                 nil,
	}

	err := all._addMessage(lm)
	if err != nil {
		t.Errorf("Failed to add message: %+v", err)
	}

	// Create new list and load old contents into it
	loadedAll := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	err = loadedAll.load(now)
	if err != nil {
		t.Errorf("Failed to load actionLeaseList from storage: %+v", err)
	}

	fp := newLeaseFingerprint(lm.ChannelID, lm.Action, lm.Payload)
	leaseEnd := loadedAll.messages[*lm.ChannelID][fp.key()].LeaseEnd
	leaseTrigger := loadedAll.messages[*lm.ChannelID][fp.key()].LeaseTrigger
	all.messages[*lm.ChannelID][fp.key()].LeaseEnd = leaseEnd
	all.messages[*lm.ChannelID][fp.key()].LeaseTrigger = leaseTrigger
	if !reflect.DeepEqual(all.messages[*lm.ChannelID][fp.key()],
		loadedAll.messages[*lm.ChannelID][fp.key()]) {
		t.Errorf("Loaded lease message does not match original."+
			"\nexpected: %+v\nreceived: %+v",
			all.messages[*lm.ChannelID][fp.key()],
			loadedAll.messages[*lm.ChannelID][fp.key()])
	}

	if leaseEnd != leaseTrigger {
		t.Errorf("If LeaseEnd and LeaseTrigger start as the same value, they"+
			"should be loaded as the same value."+
			"\nleaseEnd:     %d\nleaseTrigger: %d", leaseEnd, leaseTrigger)
	}

	if leaseEnd < now.Add(replayWaitMin).UnixNano() ||
		leaseEnd > now.Add(replayWaitMax).UnixNano() {
		t.Errorf("Lease end out of range.\nfloor:    %s\nceiling:  %s"+
			"\nleaseEnd: %s", now.Add(replayWaitMin),
			now.Add(replayWaitMax), time.Unix(0, leaseEnd))
	}

	if leaseTrigger < now.Add(replayWaitMin).UnixNano() ||
		leaseTrigger > now.Add(replayWaitMax).UnixNano() {
		t.Errorf("Lease trigger out of range.\nfloor:        %s"+
			"\nceiling:      %s\nleaseTrigger: %s", now.Add(replayWaitMin),
			now.Add(replayWaitMax), time.Unix(0, leaseTrigger))
	}

	// Check that the loaded lease list matches the original
	e1, e2 := all.leases.Front(), loadedAll.leases.Front()
	for ; e1 != nil; e1, e2 = e1.Next(), e2.Next() {
		if !reflect.DeepEqual(e1.Value, e2.Value) {
			t.Errorf("Element does not match expected."+
				"\nexpected: %+v\nreceived: %+v", e1.Value, e2.Value)
		}
	}
}

// Error path: Tests that actionLeaseList.load returns the expected error when
// no channel IDs can be loaded from storage.
func Test_actionLeaseList_load_ChannelListLoadError(t *testing.T) {
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	expectedErr := loadLeaseChanIDsErr

	err := all.load(time.Unix(0, 0))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Failed to return expected error no channel ID list exists."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that actionLeaseList.load returns the expected error when
// no lease messages can be loaded from storage.
func Test_actionLeaseList_load_LeaseMessagesLoadError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	chanID := newRandomChanID(rand.New(rand.NewSource(32)), t)
	all.messages[*chanID] = make(map[leaseFingerprintKey]*leaseMessage)
	err := all.storeLeaseChannels()
	if err != nil {
		t.Errorf("Failed to store lease channels: %+v", err)
	}

	expectedErr := fmt.Sprintf(loadLeaseMessagesErr, chanID)

	err = all.load(time.Unix(0, 0))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Failed to return expected error no lease messages exists."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that the list of channel IDs in the message map can be saved and loaded
// to and from storage with actionLeaseList.storeLeaseChannels and
// actionLeaseList.loadLeaseChannels.
func Test_actionLeaseList_storeLeaseChannels_loadLeaseChannels(t *testing.T) {
	const n = 10
	prng := rand.New(rand.NewSource(32))
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(
		nil, kv, fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	expectedIDs := make([]*id.ID, n)

	for i := 0; i < n; i++ {
		channelID := newRandomChanID(prng, t)
		all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)
		for j := 0; j < 5; j++ {
			payload, action := newRandomPayload(prng, t), newRandomAction(prng, t)
			encrypted := newRandomPayload(prng, t)
			fp := newLeaseFingerprint(channelID, action, payload)
			all.messages[*channelID][fp.key()] = &leaseMessage{
				ChannelID:        channelID,
				Action:           action,
				Payload:          payload,
				EncryptedPayload: encrypted,
			}
		}
		expectedIDs[i] = channelID
	}

	err := all.storeLeaseChannels()
	if err != nil {
		t.Errorf("Failed to store channel IDs: %+v", err)
	}

	loadedIDs, err := all.loadLeaseChannels()
	if err != nil {
		t.Errorf("Failed to load channel IDs: %+v", err)
	}

	sort.SliceStable(expectedIDs, func(i, j int) bool {
		return bytes.Compare(expectedIDs[i][:], expectedIDs[j][:]) == -1
	})
	sort.SliceStable(loadedIDs, func(i, j int) bool {
		return bytes.Compare(loadedIDs[i][:], loadedIDs[j][:]) == -1
	})

	if !reflect.DeepEqual(expectedIDs, loadedIDs) {
		t.Errorf("Loaded channel IDs do not match original."+
			"\nexpected: %+v\nreceived: %+v", expectedIDs, loadedIDs)
	}
}

// Error path: Tests that actionLeaseList.loadLeaseChannels returns an error
// when trying to load when nothing was saved.
func Test_actionLeaseList_loadLeaseChannels_StorageError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	_, err := all.loadLeaseChannels()
	if err == nil || kv.Exists(err) {
		t.Errorf("Failed to return expected error when nothing exists to load."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Tests that a list of leaseMessage can be stored and loaded using
// actionLeaseList.storeLeaseMessages and actionLeaseList.loadLeaseMessages.
func Test_actionLeaseList_storeLeaseMessages_loadLeaseMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	channelID := newRandomChanID(prng, t)
	all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)

	for i := 0; i < 15; i++ {
		lm := &leaseMessage{
			ChannelID:         channelID,
			MessageID:         newRandomMessageID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "Username",
			Payload:           newRandomPayload(prng, t),
			EncryptedPayload:  newRandomPayload(prng, t),
			Timestamp:         newRandomLeaseEnd(prng, t),
			OriginalTimestamp: newRandomLeaseEnd(prng, t),
			Lease:             newRandomLease(prng, t),
			LeaseEnd:          newRandomLeaseEnd(prng, t).UnixNano(),
			LeaseTrigger:      newRandomLeaseEnd(prng, t).UnixNano(),
			Round: rounds.MakeRound(&pb.RoundInfo{ID: uint64(i),
				Topology: [][]byte{newRandomChanID(prng, t).Marshal()}}),
			OriginalRoundID: id.Round(i),
			Status:          Delivered,
			FromAdmin:       false,
			e:               nil,
		}
		fp := newLeaseFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		all.messages[*channelID][fp.key()] = lm
	}

	err := all.storeLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	loadedMessages, err := all.loadLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to load messages: %+v", err)
	}

	if !reflect.DeepEqual(all.messages[*channelID], loadedMessages) {
		t.Errorf("Loaded messages do not match original."+
			"\nexpected: %+v\nreceived: %+v",
			all.messages[*channelID], loadedMessages)
	}
}

// Tests that actionLeaseList.storeLeaseMessages deletes the lease message file
// from storage when the list is empty.
func Test_actionLeaseList_storeLeaseMessages_EmptyList(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	channelID := newRandomChanID(prng, t)
	all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)

	for i := 0; i < 15; i++ {
		lm := &leaseMessage{
			ChannelID:        channelID,
			Action:           newRandomAction(prng, t),
			Payload:          newRandomPayload(prng, t),
			EncryptedPayload: newRandomPayload(prng, t),
			LeaseEnd:         newRandomLeaseEnd(prng, t).UnixNano(),
			LeaseTrigger:     newRandomLeaseEnd(prng, t).UnixNano(),
		}
		fp := newLeaseFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		all.messages[*channelID][fp.key()] = lm
	}

	err := all.storeLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)
	err = all.storeLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	_, err = all.loadLeaseMessages(channelID)
	if err == nil || all.kv.Exists(err) {
		t.Fatalf("Failed to delete lease messages: %+v", err)
	}
}

// Error path: Tests that actionLeaseList.loadLeaseMessages returns an error
// when trying to load when nothing was saved.
func Test_actionLeaseList_loadLeaseMessages_StorageError(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	_, err := all.loadLeaseMessages(newRandomChanID(prng, t))
	if err == nil || all.kv.Exists(err) {
		t.Errorf("Failed to return expected error when nothing exists to load."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Tests that actionLeaseList.deleteLeaseMessages removes the lease messages
// from storage.
func Test_actionLeaseList_deleteLeaseMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(nil, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	channelID := newRandomChanID(prng, t)
	all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)

	for i := 0; i < 15; i++ {
		lm := &leaseMessage{
			ChannelID:        channelID,
			Action:           newRandomAction(prng, t),
			Payload:          newRandomPayload(prng, t),
			EncryptedPayload: newRandomPayload(prng, t),
			LeaseEnd:         newRandomLeaseEnd(prng, t).UnixNano(),
			LeaseTrigger:     newRandomLeaseEnd(prng, t).UnixNano(),
		}
		fp := newLeaseFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		all.messages[*channelID][fp.key()] = lm
	}

	err := all.storeLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	err = all.deleteLeaseMessages(channelID)
	if err != nil {
		t.Errorf("Failed to delete messages: %+v", err)
	}

	_, err = all.loadLeaseMessages(channelID)
	if err == nil || all.kv.Exists(err) {
		t.Fatalf("Failed to delete lease messages: %+v", err)
	}
}

// Tests that a leaseMessage object can be JSON marshalled and unmarshalled.
func Test_leaseMessage_JSON(t *testing.T) {
	prng := rand.New(rand.NewSource(12))
	channelID := newRandomChanID(prng, t)
	payload := []byte("payload")
	encrypted := []byte("encrypted")
	timestamp, lease := netTime.Now().Round(0), 6*time.Minute+30*time.Second
	nid1 := id.NewIdFromString("test01", id.Node, t)
	now := uint64(netTime.Now().UnixNano())
	ri := &mixmessages.RoundInfo{
		ID:        5,
		UpdateID:  1,
		State:     2,
		BatchSize: 150,
		Topology:  [][]byte{nid1.Bytes()},
		Timestamps: []uint64{now - 1000, now - 800, now - 600, now - 400,
			now - 200, now, now + 200},
		Errors: []*mixmessages.RoundError{{
			Id:     uint64(49),
			NodeId: nid1.Bytes(),
			Error:  "Test error",
		}},
		ClientErrors: []*pb.ClientError{
			{ClientId: id.NewIdFromString("ClientId", id.Node, t).Marshal(),
				Error:  "Client Error",
				Source: id.NewIdFromString("Source", id.Node, t).Marshal()}},
		ResourceQueueTimeoutMillis: uint32(376 * time.Millisecond),
		Signature: &commsMessages.RSASignature{
			Nonce:     []byte("RSASignatureNonce"),
			Signature: []byte("RSASignatureSignature"),
		},
		AddressSpaceSize: 8,
		EccSignature: &commsMessages.ECCSignature{
			Nonce:     []byte("ECCSignatureNonce"),
			Signature: []byte("ECCSignatureSignature"),
		},
	}
	lm := leaseMessage{
		ChannelID:         channelID,
		MessageID:         cryptoChannel.MakeMessageID(payload, channelID),
		Action:            newRandomAction(prng, t),
		Nickname:          "John",
		Payload:           payload,
		EncryptedPayload:  encrypted,
		Timestamp:         timestamp.UTC(),
		OriginalTimestamp: timestamp.UTC(),
		Lease:             lease,
		LeaseEnd:          timestamp.Add(lease).UnixNano(),
		LeaseTrigger:      timestamp.Add(lease).UnixNano(),
		Round:             rounds.MakeRound(ri),
		OriginalRoundID:   id.Round(ri.ID),
		Status:            Delivered,
		FromAdmin:         true,
		e:                 nil,
	}

	data, err := json.Marshal(&lm)
	if err != nil {
		t.Errorf("Failed to JSON marshal leaseMessage: %+v", err)
	}

	var loadedLm leaseMessage
	err = json.Unmarshal(data, &loadedLm)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal leaseMessage: %+v", err)
	}

	if !reflect.DeepEqual(lm, loadedLm) {
		t.Errorf("Loaded leaseMessage does not match original."+
			"\nexpected: %#v\nreceived: %#v", lm, loadedLm)
	}
}

// Tests that a map of leaseMessage objects can be JSON marshalled and
// unmarshalled.
func Test_leaseMessageMap_JSON(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	channelID := newRandomChanID(prng, t)
	messages := make(map[leaseFingerprintKey]*leaseMessage, 15)

	nid1 := id.NewIdFromString("test01", id.Node, t)
	now := uint64(netTime.Now().UnixNano())
	ri := &mixmessages.RoundInfo{
		ID:        5,
		UpdateID:  1,
		State:     2,
		BatchSize: 150,
		Topology:  [][]byte{nid1.Bytes()},
		Timestamps: []uint64{now - 1000, now - 800, now - 600, now - 400,
			now - 200, now, now + 200},
		Errors: []*mixmessages.RoundError{{
			Id:     uint64(49),
			NodeId: nid1.Bytes(),
			Error:  "Test error",
		}},
		ClientErrors: []*pb.ClientError{
			{ClientId: id.NewIdFromString("ClientId", id.Node, t).Marshal(),
				Error:  "Client Error",
				Source: id.NewIdFromString("Source", id.Node, t).Marshal()}},
		ResourceQueueTimeoutMillis: uint32(376 * time.Millisecond),
		Signature: &commsMessages.RSASignature{
			Nonce:     []byte("RSASignatureNonce"),
			Signature: []byte("RSASignatureSignature"),
		},
		AddressSpaceSize: 8,
		EccSignature: &commsMessages.ECCSignature{
			Nonce:     []byte("ECCSignatureNonce"),
			Signature: []byte("ECCSignatureSignature"),
		},
	}

	for i := 0; i < 15; i++ {
		lm := &leaseMessage{
			ChannelID:         channelID,
			MessageID:         newRandomMessageID(prng, t),
			Action:            newRandomAction(prng, t),
			Nickname:          "Username",
			Payload:           newRandomPayload(prng, t),
			EncryptedPayload:  newRandomPayload(prng, t),
			Timestamp:         newRandomLeaseEnd(prng, t),
			OriginalTimestamp: newRandomLeaseEnd(prng, t),
			Lease:             newRandomLease(prng, t),
			LeaseEnd:          newRandomLeaseEnd(prng, t).UnixNano(),
			LeaseTrigger:      newRandomLeaseEnd(prng, t).UnixNano(),
			Round:             rounds.MakeRound(ri),
			OriginalRoundID:   id.Round(i),
			Status:            Delivered,
			FromAdmin:         false,
			e:                 nil,
		}
		fp := newLeaseFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		messages[fp.key()] = lm
	}

	data, err := json.Marshal(&messages)
	if err != nil {
		t.Errorf("Failed to JSON marshal map of leaseMessage: %+v", err)
	}

	var loadedMessages map[leaseFingerprintKey]*leaseMessage
	err = json.Unmarshal(data, &loadedMessages)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal map of leaseMessage: %+v", err)
	}

	if !reflect.DeepEqual(messages, loadedMessages) {
		t.Errorf("Loaded map of leaseMessage does not match original."+
			"\nexpected: %#v\nreceived: %#v", messages, loadedMessages)
	}
}

// Consistency test of makeChannelLeaseMessagesKey.
func Test_makeChannelLeaseMessagesKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(11))

	expectedKeys := []string{
		"channelLeaseMessages/WQwUQJiItbB9UagX7gfD8hRZNbxxVePHp2SQw+CqC2oD",
		"channelLeaseMessages/WGLDLvh5GdCZH3r4XpU7dEKP71tXeJvJAi/UyPkxnakD",
		"channelLeaseMessages/mo59OR72CzZlLvnGxzfhscEY4AxjhmvE6b5W+yK1BQUD",
		"channelLeaseMessages/TOFI3iGP8TNZJ/V1/E4SrgW2MiS9LRxIzM0LoMnUmukD",
		"channelLeaseMessages/xfUsHf4FuGVcwFkKywinHo7mCdaXppXef4RU7l0vUQwD",
		"channelLeaseMessages/dpBGwqS9/xi7eiT+cPNRzC3BmdDg/aY3MR2IPdHBUCAD",
		"channelLeaseMessages/ZnT0fZYP2dCHlxxDo6DSpBplgaM3cj7RPgTZ+OF7MiED",
		"channelLeaseMessages/rXartsxcv2+tIPfN2x9r3wgxPqp77YK2/kSqqKzgw5ID",
		"channelLeaseMessages/6G0Z4gfi6u2yUp9opRTgcB0FpSv/x55HgRo6tNNi5lYD",
		"channelLeaseMessages/7aHvDBG6RsPXxMHvw21NIl273F0CzDN5aixeq5VRD+8D",
		"channelLeaseMessages/v0Pw6w7z7XAaebDUOAv6AkcMKzr+2eOIxLcDMMr/i2gD",
		"channelLeaseMessages/7OI/yTc2sr0m0kONaiV3uolWpyvJHXAtts4bZMm7o14D",
		"channelLeaseMessages/jDQqEBKqNhLpKtsIwIaW5hzUy+JdQ0JkXfkbae5iLCgD",
		"channelLeaseMessages/TCTUC3AblwtJiOHcvDNrmY1o+xm6VueZXhXDm3qDwT4D",
		"channelLeaseMessages/niQssT7H/lGZ0QoQWqLwLM24xSJeDBKKadamDlVM340D",
		"channelLeaseMessages/EYzeEw5VzugCW1QGXgq0jWVc5qbeoot+LH+Pt136xIED",
	}
	for i, expected := range expectedKeys {
		key := makeChannelLeaseMessagesKey(newRandomChanID(prng, t))

		if expected != key {
			t.Errorf("Key does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, key)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Fingerprint                                                                //
////////////////////////////////////////////////////////////////////////////////

// Consistency test of newLeaseFingerprint.
func Test_newLeaseFingerprint_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(420))
	expectedFingerprints := []string{
		"ibyeRu0uiDzqU8xXhrnCdHPqMy6eQbr2ze8E6LVvHek=",
		"XLWNDONf4VlBwSbsBIi9yutMiYXStupCUJVouSC9iYE=",
		"TJ9rdst4P1NpCJj1WBDq5WUT+Dr3hIR5OHCX9Dx9Ybg=",
		"ceDqxGNHr+rG4btZtRVt4LBhVkBpPVR39kqNvAbjDTU=",
		"xstNeMNBSTyjs4v6FE3eIJaRDJXCNozGikzVxzIM+rw=",
		"Q+V4YrTF3movBM0LQGXhB+Z0dEoUJdLRG+V8RNSCf5A=",
		"KvsR70ZpnFD6xwrXN84GP/cO2RLJwWaunOGQLMoghww=",
		"jpC3pMrVTNHowvEKWCEtyChoJdfNNP1Z7UN0KuVuj/A=",
		"RrsDsB1edgAmdJF9cXMS/pe9dNqswtnK5Js2U55hKGU=",
		"tYlM1EaRETRkGrGQLHyh41t2bo7K5Zhx4aDz9ijiOUE=",
		"W/3Cuel0IeaZ6gsE/FEdd5ggUV7NYTjP+5yY7a5bBeY=",
		"L5s/DKEoacaFHKRiwEAHL4WMlAxzLrBIiXeIf6XiPyY=",
		"aaOB3gfn3Fr8447UXKwjv5DDg/V0zbeHK5GTF/yGdY0=",
		"2fFjvuHCK1hfMTMp1Xk1mSH1OEGl2zhhtH7oMyHG838=",
		"e65rACsKdX9uV5KlOW97SKInmDGQRqyCok0b1mbCjT8=",
		"Vm3cEMrTeybB4mtC/ItuaP5l9j1w49LXoRWIhIic7dw=",
	}

	for i, expected := range expectedFingerprints {
		fp := newLeaseFingerprint(newRandomChanID(prng, t),
			newRandomAction(prng, t), newRandomPayload(prng, t))

		if expected != fp.String() {
			t.Errorf("leaseFingerprint does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, fp)
		}
	}
}

// Tests that any changes to any of the inputs to newLeaseFingerprint result in
// different fingerprints.
func Test_newLeaseFingerprint_Uniqueness(t *testing.T) {
	rng := csprng.NewSystemRNG()
	const n = 100
	chanIDs := make([]*id.ID, n)
	payloads, encryptedPayloads := make([][]byte, n), make([][]byte, n)
	for i := 0; i < n; i++ {
		chanIDs[i] = newRandomChanID(rng, t)
		payloads[i] = newRandomPayload(rng, t)
		encryptedPayloads[i] = newRandomPayload(rng, t)

	}
	actions := []MessageType{Delete, Pinned, Mute}

	fingerprints := make(map[string]bool)
	for _, channelID := range chanIDs {
		for _, payload := range payloads {
			for _, action := range actions {
				fp := newLeaseFingerprint(channelID, action, payload)
				if fingerprints[fp.String()] {
					t.Errorf("Fingerprint %s already exists.", fp)
				}

				fingerprints[fp.String()] = true
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Test Utility Function                                                      //
////////////////////////////////////////////////////////////////////////////////

// newRandomChanID creates a new random channel id.ID for testing.
func newRandomChanID(rng io.Reader, t *testing.T) *id.ID {
	channelID, err := id.NewRandomID(rng, id.User)
	if err != nil {
		t.Fatalf("Failed to generate new channel ID: %+v", err)
	}

	return channelID
}

// newRandomMessageID creates a new random channel.MessageID for testing.
func newRandomMessageID(rng io.Reader, t *testing.T) cryptoChannel.MessageID {
	message := make([]byte, 256)
	if _, err := rng.Read(message); err != nil {
		t.Fatalf("Failed to generate random message: %+v", err)
	}

	channelID, err := id.NewRandomID(rng, id.User)
	if err != nil {
		t.Fatalf("Failed to generate new channel ID: %+v", err)
	}

	return cryptoChannel.MakeMessageID(message, channelID)
}

// newRandomPayload creates a new random payload for testing.
func newRandomPayload(rng io.Reader, t *testing.T) []byte {
	payload := make([]byte, 32)
	n, err := rng.Read(payload)
	if err != nil {
		t.Fatalf("Failed to generate new payload: %+v", err)
	} else if n != 32 {
		t.Fatalf(
			"Only generated %d bytes when %d bytes required for payload.", n, 32)
	}

	return payload
}

// newRandomAction creates a new random action MessageType for testing.
func newRandomAction(rng io.Reader, t *testing.T) MessageType {
	b := make([]byte, 5)
	n, err := rng.Read(b)
	if err != nil {
		t.Fatalf("Failed to generate new action bytes: %+v", err)
	} else if n != 5 {
		t.Fatalf(
			"Generated %d bytes when %d bytes required for action.", n, 5)
	}

	num := binary.LittleEndian.Uint32(b)
	switch num % 3 {
	case 0:
		return Delete
	case 1:
		return Pinned
	case 2:
		return Mute
	case 3:
		return AdminReplay
	}

	return 0
}

// newRandomLeaseEnd creates a new random action lease end for testing.
func newRandomLeaseEnd(rng io.Reader, t *testing.T) time.Time {
	b := make([]byte, 8)
	n, err := rng.Read(b)
	if err != nil {
		t.Fatalf("Failed to generate new lease time bytes: %+v", err)
	} else if n != 8 {
		t.Fatalf(
			"Only generated %d bytes when %d bytes required for lease.", n, 8)
	}

	lease := randDurationInRange(1*time.Hour, 1000*time.Hour, rng)
	return netTime.Now().Add(lease).UTC().Round(0)
}

// newRandomLease creates a new random lease duration end for testing.
func newRandomLease(rng io.Reader, t *testing.T) time.Duration {
	b := make([]byte, 8)
	n, err := rng.Read(b)
	if err != nil {
		t.Fatalf("Failed to generate new lease bytes: %+v", err)
	} else if n != 8 {
		t.Fatalf(
			"Only generated %d bytes when %d bytes required for lease.", n, 8)
	}

	return time.Duration(binary.LittleEndian.Uint64(b)%1000) * time.Minute
}
