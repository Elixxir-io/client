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
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/ekv"
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

// Tests that newActionLeaseList returns the expected new actionLeaseList.
func Test_newActionLeaseList(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	expected := &actionLeaseList{
		leases:   list.New(),
		messages: make(map[id.ID]map[leaseFingerprintKey]*leaseMessage),
		kv:       kv,
	}

	all := newActionLeaseList(kv)

	if !reflect.DeepEqual(expected, all) {
		t.Errorf("New actionLeaseList does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, all)
	}
}

// Tests that actionLeaseList.addMessage adds all the messages to both the lease
// list and the message map and that the lease list is in the correct order.
func Test_actionLeaseList_addMessage(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))

	var expected []*leaseMessage
	for i := 0; i < 50; i++ {
		channelID := newRandomChanID(prng, t)
		for j := 0; j < 5; j++ {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm := &leaseMessage{
				ChannelID: channelID,
				Target:    newRandomTarget(prng, t),
				Action:    newRandomAction(prng, t),
				LeaseEnd:  timestamp.Add(lease).UnixNano(),
			}
			expected = append(expected, lm)

			err := all.addMessage(
				lm.ChannelID, lm.Target, lm.Action, timestamp, lease)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Check that the message map has all the expected messages
	for i := range expected {
		fp := newLeaseFingerprint(
			expected[i].ChannelID, expected[i].Target, expected[i].Action)
		if messages, exists := all.messages[*expected[i].ChannelID]; !exists {
			t.Errorf(
				"Channel %s does not exist (%d).", expected[i].ChannelID, i)
		} else if lm, exists2 := messages[fp.key()]; !exists2 {
			t.Errorf("No lease message found with key %s (%d).", fp.key(), i)
		} else {
			lm.e = nil
			if !reflect.DeepEqual(expected[i], lm) {
				t.Errorf("leaseMessage does not match expected (%d)."+
					"\nexpected: %+v\nreceived: %+v", i, expected[i], lm)
			}
		}
	}

	// Check that the lease list has all the expected messages in the correct
	// order
	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i].LeaseEnd < expected[j].LeaseEnd
	})
	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i].LeaseEnd != e.Value.(*leaseMessage).LeaseEnd {
			t.Errorf("leaseMessage %d not in correct order."+
				"\nexpected: %+v\nreceived: %+v",
				i, expected[i], e.Value.(*leaseMessage))
		}
	}
}

// Tests that after updating half the messages, actionLeaseList.addMessage moves
// the messages to the lease list is still in order.
func Test_actionLeaseList_addMessage_Update(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))

	var expected []*leaseMessage
	for i := 0; i < 50; i++ {
		channelID := newRandomChanID(prng, t)
		for j := 0; j < 5; j++ {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm := &leaseMessage{
				ChannelID: channelID,
				Target:    newRandomTarget(prng, t),
				Action:    newRandomAction(prng, t),
				LeaseEnd:  timestamp.Add(lease).UnixNano(),
			}
			expected = append(expected, lm)

			err := all.addMessage(
				lm.ChannelID, lm.Target, lm.Action, timestamp, lease)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Update the time of half the messages.
	for i, lm := range expected {
		if i%2 == 0 {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm.LeaseEnd = timestamp.Add(lease).UnixNano()

			err := all.addMessage(
				lm.ChannelID, lm.Target, lm.Action, timestamp, lease)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Check that the order is still correct
	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i].LeaseEnd < expected[j].LeaseEnd
	})
	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i].LeaseEnd != e.Value.(*leaseMessage).LeaseEnd {
			t.Errorf("leaseMessage %d not in correct order."+
				"\nexpected: %+v\nreceived: %+v",
				i, expected[i], e.Value.(*leaseMessage))
		}
	}
}

// Tests that actionLeaseList.insertLease inserts all the leaseMessage in the
// correct order, from smallest LeaseEnd to largest.
func Test_actionLeaseList_insertLease(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))
	expected := make([]int64, 50)

	for i := range expected {
		randomTime := time.Unix(0, prng.Int63())
		all.insertLease(&leaseMessage{LeaseEnd: randomTime.UnixNano()})
		expected[i] = randomTime.UnixNano()
	}

	sort.SliceStable(expected, func(i, j int) bool {
		return expected[i] < expected[j]
	})

	for i, e := 0, all.leases.Front(); e != nil; i, e = i+1, e.Next() {
		if expected[i] != e.Value.(*leaseMessage).LeaseEnd {
			t.Errorf("Timestamp %d not in correct order."+
				"\nexpected: %d\nreceived: %d",
				i, expected[i], e.Value.(*leaseMessage).LeaseEnd)
		}
	}
}

// Fills the lease list with in-order messages and tests that
// actionLeaseList.updateLease correctly moves elements to the correct order
// when their LeaseEnd changes.
func Test_actionLeaseList_updateLease(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))

	for i := 0; i < 50; i++ {
		randomTime := time.Unix(0, prng.Int63())
		all.insertLease(&leaseMessage{LeaseEnd: randomTime.UnixNano()})
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
		{all.leases.Front().Value.(*leaseMessage).LeaseEnd - 1,
			all.leases.Front().Next().Next()},

		// Change an element to the last element
		{all.leases.Back().Value.(*leaseMessage).LeaseEnd + 1,
			all.leases.Front().Next().Next().Next().Next().Next()},
	}

	for i, tt := range tests {
		tt.e.Value.(*leaseMessage).LeaseEnd = tt.randomTime
		all.updateLease(tt.e)

		// Check that the list is in order
		for n := all.leases.Front(); n.Next() != nil; n = n.Next() {
			if n.Value.(*leaseMessage).LeaseEnd >
				n.Next().Value.(*leaseMessage).LeaseEnd {
				t.Errorf("List out of order (%d).", i)
			}
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
	all := newActionLeaseList(kv)

	for i := 0; i < 10; i++ {
		channelID := newRandomChanID(prng, t)
		for j := 0; j < 5; j++ {
			timestamp := newRandomLeaseEnd(prng, t)
			lease := time.Minute
			lm := &leaseMessage{
				ChannelID: channelID,
				Target:    newRandomTarget(prng, t),
				Action:    newRandomAction(prng, t),
				LeaseEnd:  timestamp.Add(lease).UnixNano(),
			}

			err := all.addMessage(
				lm.ChannelID, lm.Target, lm.Action, timestamp, lease)
			if err != nil {
				t.Errorf("Failed to add message: %+v", err)
			}
		}
	}

	// Create new list and load old contents into it
	loadedAll := newActionLeaseList(kv)
	err := loadedAll.load()
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

// Error path: Tests that actionLeaseList.load returns the expected error when
// no channel IDs can be loaded from storage.
func Test_actionLeaseList_load_ChannelListLoadError(t *testing.T) {
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))
	expectedErr := strings.Split(loadLeaseChanIDsErr, "%")[0]

	err := all.load()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Failed to return expected error no channel ID list exists."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that actionLeaseList.load returns the expected error when
// no lease messages can be loaded from storage.
func Test_actionLeaseList_load_LeaseMessagesLoadError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	all := newActionLeaseList(kv)
	chanID := newRandomChanID(rand.New(rand.NewSource(32)), t)
	all.messages[*chanID] = make(map[leaseFingerprintKey]*leaseMessage)
	err := all.storeLeaseChannels()
	if err != nil {
		t.Errorf("Failed to store lease channels: %+v", err)
	}

	expectedErr := fmt.Sprintf(loadLeaseMessagesErr, chanID, "")

	err = all.load()
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
	all := newActionLeaseList(kv)
	expectedIDs := make([]*id.ID, n)

	for i := 0; i < n; i++ {
		channelID := newRandomChanID(prng, t)
		all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)
		for j := 0; j < 5; j++ {
			target, action := newRandomTarget(prng, t), newRandomAction(prng, t)
			fp := newLeaseFingerprint(channelID, target, action)
			all.messages[*channelID][fp.key()] = &leaseMessage{
				ChannelID: channelID,
				Target:    target,
				Action:    action,
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
	all := newActionLeaseList(kv)

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
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))
	channelID := newRandomChanID(prng, t)
	all.messages[*channelID] = make(map[leaseFingerprintKey]*leaseMessage)

	for i := 0; i < 15; i++ {
		lm := &leaseMessage{
			ChannelID: channelID,
			Target:    newRandomTarget(prng, t),
			Action:    newRandomAction(prng, t),
			LeaseEnd:  newRandomLeaseEnd(prng, t).UnixNano(),
		}
		fp := newLeaseFingerprint(lm.ChannelID, lm.Target, lm.Action)
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

// Error path: Tests that actionLeaseList.loadLeaseMessages returns an error
// when trying to load when nothing was saved.
func Test_actionLeaseList_loadLeaseMessages_StorageError(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	all := newActionLeaseList(versioned.NewKV(ekv.MakeMemstore()))

	_, err := all.loadLeaseMessages(newRandomChanID(prng, t))
	if err == nil || all.kv.Exists(err) {
		t.Errorf("Failed to return expected error when nothing exists to load."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Tests that a leaseMessage object can be JSON marshalled and unmarshalled.
func Test_leaseMessage_JSON(t *testing.T) {
	prng := rand.New(rand.NewSource(12))
	lm := leaseMessage{
		ChannelID: newRandomChanID(prng, t),
		Target:    newRandomTarget(prng, t),
		Action:    newRandomAction(prng, t),
		LeaseEnd:  newRandomLeaseEnd(prng, t).UnixNano(),
		e:         nil,
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
		"eXOwhMZ3/RUM2uQpQr/wXKbFNeAefLMcoeiyZUjRu5k=",
		"bnd+c9Z6A3b3WxmxtW0GBdl9YamHTeR90gk9gjORurY=",
		"2NGpuU6fDJMYYVq2dMidI6bV3BiMryeC55+YHD79DYc=",
		"VOsyiZeL2X2iFygB6cVY8fpepWhTasRCd8kaunQs0Ms=",
		"xThhdJdmGJeHvYLH2lnXyu680c6N36qcgpO7rwef03E=",
		"/bu1mQn/iw5xTfEDmvY3PXqdc22YNISWja59JD8XFPQ=",
		"TPU4+r3f5UPq7PoGeW/aB/AqqLOycKJQQrnCN18Jhy0=",
		"aNP5R0ugX76+Rj0dWTbYvBUXTVq2mYXhpfFR25DvX9U=",
		"8hbXJW+tz/FjSuDs+CEEuTANQ6/z3/+6H7/DxhxOFjo=",
		"Yfb7TnJS6SSbw9fnthYq04DYkDqLUrcvPT19JcQWnWs=",
		"8/oz0DMO/f/z/nbxvQ24qqY4ec7RCMxZBsgp00NBCgM=",
		"kzqcNXdop0ZsucM2i9LfY+CZjuVMKzoNemfnW7nQ03k=",
		"AlxWSHxHdCFlWk1LMfLRVP+sQ0ilSjbFX47Hr4mo7JQ=",
		"+/PO/1aLKKJGMd/HzD9x4awBx8KksussDgqNl9O3s7Y=",
		"lkSv2o2AGtqtS7q4uJXkaZ7t50QOOE9Blnm/S5nv+AU=",
		"wUkO0HPUaiu8PpBAhM6wQb606YB3TIjME+Aas5rqCBI=",
	}

	for i, expected := range expectedFingerprints {
		fp := newLeaseFingerprint(
			newRandomChanID(prng, t),
			newRandomTarget(prng, t),
			newRandomAction(prng, t),
		)

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
	chanIDs, targets := make([]*id.ID, n), make([][]byte, n)
	for i := 0; i < n; i++ {
		chanIDs[i] = newRandomChanID(rng, t)
		targets[i] = newRandomTarget(rng, t)

	}
	actions := []MessageType{Delete, Pinned, Hidden}

	fingerprints := make(map[string]bool)
	for _, channelID := range chanIDs {
		for _, target := range targets {
			for _, action := range actions {
				fp := newLeaseFingerprint(channelID, target, action)
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

// newRandomTarget creates a new random target for testing.
func newRandomTarget(rng io.Reader, t *testing.T) []byte {
	target := make([]byte, 32)
	n, err := rng.Read(target)
	if err != nil {
		t.Fatalf("Failed to generate new target: %+v", err)
	} else if n != 32 {
		t.Fatalf(
			"Only generated %d bytes when %d bytes required for target.", n, 32)
	}

	return target
}

// newRandomAction creates a new random action MessageType for testing.
func newRandomAction(rng io.Reader, t *testing.T) MessageType {
	b := make([]byte, 4)
	n, err := rng.Read(b)
	if err != nil {
		t.Fatalf("Failed to generate new action bytes: %+v", err)
	} else if n != 4 {
		t.Fatalf(
			"Only generated %d bytes when %d bytes required for action.", n, 4)
	}

	num := binary.LittleEndian.Uint32(b)
	switch num % 3 {
	case 0:
		return Delete
	case 1:
		return Pinned
	case 2:
		return Hidden
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

	lease := time.Duration(binary.LittleEndian.Uint64(b)%1000) * time.Minute

	return netTime.Now().Add(lease).Round(0)
}
