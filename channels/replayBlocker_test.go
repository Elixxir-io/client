////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNewOrLoadReplayBlocker(t *testing.T) {
}

// Tests that NewReplayBlocker returns the expected new ReplayBlocker.
func TestNewReplayBlocker(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	s := NewCommandStore(kv)

	expected := &ReplayBlocker{
		messagesByChannel: make(map[id.ID]map[commandFingerprintKey]*commandMessage),
		store:             s,
		kv:                kv.Prefix(replayBlockerStoragePrefix),
	}

	rb := NewReplayBlocker(nil, s, kv)

	if !reflect.DeepEqual(expected, rb) {
		t.Errorf("New ReplayBlocker does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, rb)
	}
}

////////////////////////////////////////////////////////////////////////////////
// Storage Functions                                                          //
////////////////////////////////////////////////////////////////////////////////

// Tests that ReplayBlocker.load loads a ReplayBlocker from storage that matches
// the original.
func TestReplayBlocker_load(t *testing.T) {
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	s := NewCommandStore(kv)
	rb := NewReplayBlocker(nil, s, kv)

	for i := 0; i < 10; i++ {
		channelID := randChannelID(prng, t)
		rb.messagesByChannel[*channelID] =
			make(map[commandFingerprintKey]*commandMessage)
		for j := 0; j < 5; j++ {
			rm := &commandMessage{
				ChannelID:        channelID,
				Action:           randAction(prng),
				Payload:          randPayload(prng, t),
				OriginatingRound: id.Round(prng.Uint64()),
			}

			fp := newCommandFingerprint(channelID, rm.Action, rm.Payload)
			rb.messagesByChannel[*channelID][fp.key()] = rm
		}

		err := rb.updateStorage(channelID, true)
		if err != nil {
			t.Errorf("Failed to update storage for channel %s (%d): %+v",
				channelID, i, err)
		}
	}


	// Create new list and load old contents into it
	loadedRb := NewReplayBlocker(nil, s, kv)
	err := loadedRb.load()
	if err != nil {
		t.Errorf("Failed to load ReplayBlocker from storage: %+v", err)
	}

	// Check that the loaded message map matches the original
	for chanID, messages := range rb.messagesByChannel {
		loadedMessages, exists := rb.messagesByChannel[chanID]
		if !exists {
			t.Errorf("Channel ID %s does not exist in map.", chanID)
		}

		for fp, rm := range messages {
			loadedRm, exists2 := loadedMessages[fp]
			if !exists2 {
				t.Errorf("Command message does not exist in map: %+v", rm)
			}
			if !reflect.DeepEqual(rm, loadedRm) {
				t.Errorf("commandMessage does not match expected."+
					"\nexpected: %+v\nreceived: %+v", rm, loadedRm)
			}
		}
	}
}

// Error path: Tests that ReplayBlocker.load returns the expected error when no
// channel IDs can be loaded from storage.
func TestReplayBlocker_load_ChannelListLoadError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)
	expectedErr := loadCommandChanIDsErr

	err := rb.load()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Failed to return expected error no channel ID list exists."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: Tests that ReplayBlocker.load returns the expected error when no
// command messages can be loaded from storage.
func TestReplayBlocker_load_CommandMessagesLoadError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)

	channelID := randChannelID(rand.New(rand.NewSource(456)), t)
	rb.messagesByChannel[*channelID] =
		make(map[commandFingerprintKey]*commandMessage)
	err := rb.storeCommandChannelsList()
	if err != nil {
		t.Fatalf("Failed to store channel list: %+v", err)
	}

	expectedErr := fmt.Sprintf(loadCommandMessagesErr, channelID)

	err = rb.load()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Failed to return expected error no command messages exist."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that the list of channel IDs in the message map can be saved and loaded
// to and from storage with ReplayBlocker.storeCommandChannelsList and
// ReplayBlocker.loadCommandChannelsList.
func TestReplayBlocker_storeCommandChannelsList_loadCommandChannelsList(t *testing.T) {
	const n = 10
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)
	expectedIDs := make([]*id.ID, n)

	for i := 0; i < n; i++ {
		channelID := randChannelID(prng, t)
		rb.messagesByChannel[*channelID] =
			make(map[commandFingerprintKey]*commandMessage)
		for j := 0; j < 5; j++ {
			action, payload := randAction(prng), randPayload(prng, t)
			fp := newCommandFingerprint(channelID, action, payload)
			rb.messagesByChannel[*channelID][fp.key()] = &commandMessage{
				ChannelID:        channelID,
				Action:           action,
				Payload:          payload,
				OriginatingRound: id.Round(prng.Uint64()),
			}
		}
		expectedIDs[i] = channelID
	}

	err := rb.storeCommandChannelsList()
	if err != nil {
		t.Errorf("Failed to store channel IDs: %+v", err)
	}

	loadedIDs, err := rb.loadCommandChannelsList()
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

// Error path: Tests that ReplayBlocker.loadCommandChannelsList returns an error
// when trying to load from storage when nothing was saved.
func TestReplayBlocker_loadCommandChannelsList_StorageError(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)

	_, err := rb.loadCommandChannelsList()
	if err == nil || kv.Exists(err) {
		t.Errorf("Failed to return expected error when nothing exists to load."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Tests that a list of commandMessage can be stored and loaded using
// ReplayBlocker.storeCommandMessages and ReplayBlocker.loadCommandMessages.
func TestReplayBlocker_storeCommandMessages_loadCommandMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)
	channelID := randChannelID(prng, t)
	rb.messagesByChannel[*channelID] =
		make(map[commandFingerprintKey]*commandMessage)

	for i := 0; i < 15; i++ {
		lm := &commandMessage{
			ChannelID:        randChannelID(prng, t),
			Action:           randAction(prng),
			Payload:          randPayload(prng, t),
			OriginatingRound: id.Round(prng.Uint64()),
		}
		fp := newCommandFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		rb.messagesByChannel[*channelID][fp.key()] = lm
	}

	err := rb.storeCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	loadedMessages, err := rb.loadCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to load messages: %+v", err)
	}

	if !reflect.DeepEqual(rb.messagesByChannel[*channelID], loadedMessages) {
		t.Errorf("Loaded messages do not match original."+
			"\nexpected: %+v\nreceived: %+v",
			rb.messagesByChannel[*channelID], loadedMessages)
	}
}

// Tests that ReplayBlocker.storeCommandMessages deletes the Command message
// file from storage when the list is empty.
func TestReplayBlocker_storeCommandMessages_EmptyList(t *testing.T) {
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)
	channelID := randChannelID(prng, t)
	rb.messagesByChannel[*channelID] =
		make(map[commandFingerprintKey]*commandMessage)

	for i := 0; i < 15; i++ {
		lm := &commandMessage{
			ChannelID:        randChannelID(prng, t),
			Action:           randAction(prng),
			Payload:          randPayload(prng, t),
			OriginatingRound: id.Round(prng.Uint64()),
		}
		fp := newCommandFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		rb.messagesByChannel[*channelID][fp.key()] = lm
	}

	err := rb.storeCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	rb.messagesByChannel[*channelID] =
		make(map[commandFingerprintKey]*commandMessage)
	err = rb.storeCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	_, err = rb.loadCommandMessages(channelID)
	if err == nil || rb.kv.Exists(err) {
		t.Fatalf("Failed to delete command messages: %+v", err)
	}
}

// Error path: Tests that ReplayBlocker.loadCommandMessages returns an error when
// trying to load from storage when nothing was saved.
func TestReplayBlocker_loadCommandMessages_StorageError(t *testing.T) {
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)

	_, err := rb.loadCommandMessages(randChannelID(prng, t))
	if err == nil || rb.kv.Exists(err) {
		t.Errorf("Failed to return expected error when nothing exists to load."+
			"\nexpected: %v\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Tests that ReplayBlocker.deleteCommandMessages removes the command messages
// from storage.
func TestReplayBlocker_deleteCommandMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(986))
	kv := versioned.NewKV(ekv.MakeMemstore())
	rb := NewReplayBlocker(nil, NewCommandStore(kv), kv)
	channelID := randChannelID(prng, t)
	rb.messagesByChannel[*channelID] =
		make(map[commandFingerprintKey]*commandMessage)

	for i := 0; i < 15; i++ {
		lm := &commandMessage{
			ChannelID:        randChannelID(prng, t),
			Action:           randAction(prng),
			Payload:          randPayload(prng, t),
			OriginatingRound: id.Round(prng.Uint64()),
		}
		fp := newCommandFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		rb.messagesByChannel[*channelID][fp.key()] = lm
	}

	err := rb.storeCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to store messages: %+v", err)
	}

	err = rb.deleteCommandMessages(channelID)
	if err != nil {
		t.Errorf("Failed to delete messages: %+v", err)
	}

	_, err = rb.loadCommandMessages(channelID)
	if err == nil || rb.kv.Exists(err) {
		t.Fatalf("Failed to delete command messages: %+v", err)
	}
}

// Tests that a commandMessage object can be JSON marshalled and unmarshalled.
func Test_commandMessage_JSON(t *testing.T) {
	prng := rand.New(rand.NewSource(9685))

	rm := commandMessage{
		ChannelID:        randChannelID(prng, t),
		Action:           randAction(prng),
		Payload:          randPayload(prng, t),
		OriginatingRound: id.Round(prng.Uint64()),
	}

	data, err := json.Marshal(&rm)
	if err != nil {
		t.Errorf("Failed to JSON marshal commandMessage: %+v", err)
	}

	var loadedRm commandMessage
	err = json.Unmarshal(data, &loadedRm)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal commandMessage: %+v", err)
	}

	if !reflect.DeepEqual(rm, loadedRm) {
		t.Errorf("Loaded commandMessage does not match original."+
			"\nexpected: %#v\nreceived: %#v", rm, loadedRm)
	}
}

// Tests that a map of commandMessage objects can be JSON marshalled and
// unmarshalled.
func Test_commandMessageMap_JSON(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	const n = 15
	messages := make(map[commandFingerprintKey]*commandMessage, n)

	for i := 0; i < n; i++ {
		lm := &commandMessage{
			ChannelID:        randChannelID(prng, t),
			Action:           randAction(prng),
			Payload:          randPayload(prng, t),
			OriginatingRound: id.Round(prng.Uint64()),
		}
		fp := newCommandFingerprint(lm.ChannelID, lm.Action, lm.Payload)
		messages[fp.key()] = lm
	}

	data, err := json.Marshal(&messages)
	if err != nil {
		t.Errorf("Failed to JSON marshal map of commandMessage: %+v", err)
	}

	var loadedMessages map[commandFingerprintKey]*commandMessage
	err = json.Unmarshal(data, &loadedMessages)
	if err != nil {
		t.Errorf("Failed to JSON unmarshal map of commandMessage: %+v", err)
	}

	if !reflect.DeepEqual(messages, loadedMessages) {
		t.Errorf("Loaded map of commandMessage does not match original."+
			"\nexpected: %+v\nreceived: %+v", messages, loadedMessages)
	}
}

// Consistency test of makeChannelCommandMessagesKey.
func Test_makeChannelCommandMessagesKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(4978))

	expectedKeys := []string{
		"42ab84b199deac60a60ffd86874d04af1d225930223f4c1d6dd9e2a9f9d8e6c003",
		"0c9532f8e6ed4285f80ed260e04732a9641e66baa3a7d4d8a88a44cd2f363a8603",
		"623b05551182e5c1cad1a193543e938f5c5f69bce5e4efac1707649421a0934b03",
		"c21fc83c25e502237d2f4faeb3a42b786823ff637f7ba6c6512411186c17b7c303",
		"22b323be76037f9e97d443cc47a0e45884f1b178c0d056b8361ead091cc9ae4003",
		"7da2d0d3ea7004ad57da6d95e6a3ed7f1bb32738ac556a80a2a8c5a6e446014d03",
		"a03b1fe700cae64411c56ef4a1a7de2c641d34f79ce3a6b3940b9648d800cf9603",
		"f61f471981e005d0ef720204bbea600fa1d660f1591f16ca93dc5d61ceaf2af603",
		"ed783b3743e9207cc7651b5f4864d61e8556b4898f42df715e590ed90d24078b03",
		"b634426a3007d4cbf2e103517e04b1e81ead5bbcc5ddb210c75c228cf5acd1d903",
		"721bc300fae39398d82e31972107ab5864e46e8658cd7043dcb0cdcfb161688903",
		"4fcd4542546819ddeca86246a894e824e930ef48627a0277eb7873a086000d6403",
		"1fedb554c4bf5c335860a02d93529a421a213cc0a8494840aa45c78f1d46a58803",
		"e6e161e6620cd74a967a09736a439de7f145fd88f6e422d3e09c075820ce6a4103",
		"8313bda62b20b564611bf018630f472d54149eead4d85dcf2e7da043c70ccf7b03",
		"cf67c35c5f19086098cd7a3bffd2e8975267d65f202f733b29faca624a6ba8cf03",
	}
	for i, expected := range expectedKeys {
		key := makeChannelCommandMessagesKey(randChannelID(prng, t))

		if expected != key {
			t.Errorf("Key does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, key)
		}
	}
}
