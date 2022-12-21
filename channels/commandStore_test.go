////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"encoding/json"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/comms/mixmessages"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

// Tests that NewCommandStore returns the expected CommandStore.
func TestNewCommandStore(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	expected := &CommandStore{kv.Prefix(commandStorePrefix)}

	cs := NewCommandStore(kv)

	if !reflect.DeepEqual(expected, cs) {
		t.Errorf("New CommandStore does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, cs)
	}
}

// Tests that a number of channel messages can be saved and loaded from storage.
func TestCommandStore_SaveCommand_LoadCommand(t *testing.T) {
	prng := rand.New(rand.NewSource(430_956))
	cs := NewCommandStore(versioned.NewKV(ekv.MakeMemstore()))

	expected := make([]CommandMessage, 20)
	for i := range expected {
		nid1 := id.NewIdFromUInt(uint64(i), id.Node, t)
		now := uint64(netTime.Now().UnixNano())
		ri := &mixmessages.RoundInfo{
			ID:        prng.Uint64(),
			UpdateID:  prng.Uint64(),
			State:     prng.Uint32(),
			BatchSize: prng.Uint32(),
			Topology:  [][]byte{nid1.Bytes()},
			Timestamps: []uint64{now - 1000, now - 800, now - 600, now - 400,
				now - 200, now, now + 200},
			Errors: []*mixmessages.RoundError{{
				Id:     prng.Uint64(),
				NodeId: nid1.Bytes(),
				Error:  "Test error",
			}},
			ResourceQueueTimeoutMillis: prng.Uint32(),
			AddressSpaceSize:           prng.Uint32(),
		}
		e := CommandMessage{
			ChannelID:        randChannelID(prng, t),
			MessageID:        randMessageID(prng, t),
			MessageType:      randAction(prng),
			Nickname:         "George",
			Content:          randPayload(prng, t),
			EncryptedPayload: randPayload(prng, t),
			PubKey:           randPayload(prng, t),
			Codeset:          uint8(prng.Uint32()),
			Timestamp:        randTimestamp(prng),
			LocalTimestamp:   randTimestamp(prng),
			Lease:            randLease(prng),
			Round:            rounds.MakeRound(ri),
			Status:           SentStatus(prng.Uint32()),
			FromAdmin:        prng.Int()%2 == 0,
			UserMuted:        prng.Int()%2 == 0,
		}
		expected[i] = e

		err := cs.SaveCommand(e.ChannelID, e.MessageID, e.MessageType,
			e.Nickname, e.Content, e.EncryptedPayload, e.PubKey, e.Codeset,
			e.Timestamp, e.LocalTimestamp, e.Lease, e.Round, e.Status,
			e.FromAdmin, e.UserMuted)
		if err != nil {
			t.Errorf("Failed to save message %d: %+v", i, err)
		}
	}

	for i, e := range expected {
		m, err := cs.LoadCommand(e.ChannelID, e.MessageType, e.Content)
		if err != nil {
			t.Errorf("Failed to load message %d: %+v", i, err)
		}

		if !reflect.DeepEqual(e, m) {
			t.Errorf("Message %d does not match expected."+
				"\nexpected: %+v\nreceived: %+v", i, e, m)
		}
	}
}

// Tests that when no message exists in storage, CommandStore.LoadCommand
// returns an error that signifies the object does not exist, as verified by
// KV.Exists.
func TestCommandStore_LoadCommand_EmptyStorageError(t *testing.T) {
	cs := NewCommandStore(versioned.NewKV(ekv.MakeMemstore()))

	_, err := cs.LoadCommand(&id.ID{1}, Delete, []byte("content"))
	if cs.kv.Exists(err) {
		t.Errorf("Incorrect error when message does not exist: %+v", err)
	}
}

// Tests that CommandStore.DeleteCommand deletes all the command messages.
func TestCommandStore_DeleteCommand(t *testing.T) {
	prng := rand.New(rand.NewSource(430_956))
	cs := NewCommandStore(versioned.NewKV(ekv.MakeMemstore()))

	expected := make([]CommandMessage, 20)
	for i := range expected {
		nid1 := id.NewIdFromUInt(uint64(i), id.Node, t)
		now := uint64(netTime.Now().UnixNano())
		ri := &mixmessages.RoundInfo{
			ID:        prng.Uint64(),
			UpdateID:  prng.Uint64(),
			State:     prng.Uint32(),
			BatchSize: prng.Uint32(),
			Topology:  [][]byte{nid1.Bytes()},
			Timestamps: []uint64{now - 1000, now - 800, now - 600, now - 400,
				now - 200, now, now + 200},
			Errors: []*mixmessages.RoundError{{
				Id:     prng.Uint64(),
				NodeId: nid1.Bytes(),
				Error:  "Test error",
			}},
			ResourceQueueTimeoutMillis: prng.Uint32(),
			AddressSpaceSize:           prng.Uint32(),
		}
		e := CommandMessage{
			ChannelID:        randChannelID(prng, t),
			MessageID:        randMessageID(prng, t),
			MessageType:      randAction(prng),
			Nickname:         "George",
			Content:          randPayload(prng, t),
			EncryptedPayload: randPayload(prng, t),
			PubKey:           randPayload(prng, t),
			Codeset:          uint8(prng.Uint32()),
			Timestamp:        randTimestamp(prng),
			LocalTimestamp:   randTimestamp(prng),
			Lease:            randLease(prng),
			Round:            rounds.MakeRound(ri),
			Status:           SentStatus(prng.Uint32()),
			FromAdmin:        prng.Int()%2 == 0,
			UserMuted:        prng.Int()%2 == 0,
		}
		expected[i] = e

		err := cs.SaveCommand(e.ChannelID, e.MessageID, e.MessageType,
			e.Nickname, e.Content, e.EncryptedPayload, e.PubKey, e.Codeset,
			e.Timestamp, e.LocalTimestamp, e.Lease, e.Round, e.Status,
			e.FromAdmin, e.UserMuted)
		if err != nil {
			t.Errorf("Failed to save message %d: %+v", i, err)
		}
	}

	for i, e := range expected {
		err := cs.DeleteCommand(e.ChannelID, e.MessageType, e.Content)
		if err != nil {
			t.Errorf("Failed to delete message %d: %+v", i, err)
		}
	}

	for i, e := range expected {
		_, err := cs.LoadCommand(e.ChannelID, e.MessageType, e.Content)
		if cs.kv.Exists(err) {
			t.Errorf(
				"Loaded message %d that should have been deleted: %+v", i, err)
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
// Storage Message                                                            //
////////////////////////////////////////////////////////////////////////////////

// Tests that a CommandMessage with a CommandMessage object can be JSON
// marshalled and unmarshalled and that the result matches the original.
func TestCommandMessage_JsonMarshalUnmarshal(t *testing.T) {
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
		ResourceQueueTimeoutMillis: 0,
		AddressSpaceSize:           8,
	}

	m := CommandMessage{
		ChannelID:        id.NewIdFromString("channelID", id.User, t),
		MessageID:        cryptoChannel.MessageID{1, 2, 3},
		MessageType:      Reaction,
		Nickname:         "Nickname",
		Content:          []byte("content"),
		EncryptedPayload: []byte("EncryptedPayload"),
		PubKey:           []byte("PubKey"),
		Codeset:          12,
		Timestamp:        netTime.Now().UTC().Round(0),
		LocalTimestamp:   netTime.Now().UTC().Round(0),
		Lease:            56*time.Second + 6*time.Minute + 12*time.Hour,
		Round:            rounds.MakeRound(ri),
		Status:           Delivered,
		FromAdmin:        true,
		UserMuted:        true,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Failed to JSON marshal CommandMessage: %+v", err)
	}

	var newMessage CommandMessage
	err = json.Unmarshal(data, &newMessage)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal CommandMessage: %+v", err)
	}

	if !reflect.DeepEqual(m, newMessage) {
		t.Errorf("JSON marshalled and unmarshalled CommandMessage does not "+
			"match original.\nexpected: %+v\nreceived: %+v", m, newMessage)
	}
}

// Tests that a CommandMessage, with all of the fields set to nil, can be JSON
// marshalled and unmarshalled and that the result matches the original.
func TestMessage_JsonMarshalUnmarshal_NilFields(t *testing.T) {
	var m CommandMessage

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Failed to JSON marshal empty CommandMessage: %+v", err)
	}

	var newMessage CommandMessage
	err = json.Unmarshal(data, &newMessage)
	if err != nil {
		t.Fatalf("Failed to JSON unmarshal empty CommandMessage: %+v", err)
	}

	if !reflect.DeepEqual(m, newMessage) {
		t.Errorf("JSON marshalled and unmarshalled CommandMessage does not "+
			"match original.\nexpected: %+v\nreceived: %+v", m, newMessage)
	}
}

////////////////////////////////////////////////////////////////////////////////
// Fingerprint                                                                //
////////////////////////////////////////////////////////////////////////////////

// Consistency test of newCommandFingerprint.
func Test_newCommandFingerprint_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(420))
	expectedFingerprints := []string{
		"HPplU+CG9P872SORbI4BeFxgjkuBPUlF3gSNm371U3c=",
		"PU4zKeWyqHwrFMbPUMT7BMIVwAkF8vPFsBB4bLf+Arw=",
		"+OqBwVfOwR1tracbff/TxrlT8AIcO2JD+AZ3pmyEgvQ=",
		"7hVYQ1cvCou0O4tFLcipa2IXZSDbRAs+sPhrlTFiF64=",
		"xzddIIMaEZh9q47YDt7umTZtfFOl6T+dzgzfhpneEB4=",
		"Ls2aePoiD7kYeJmzjb5CKS5KNYSr2LbHnW/7UTvkGh8=",
		"r0pqAaciOdWTpWOirV0xv07uZ8fFNmN+F0I6hbQRMZE=",
		"fDl6jf6l/g2+gOZPz/LepdxlTIwKmeEEaNW5gXrxcQ0=",
		"nS2bu34dC6tfKFz6nZu/w9ORA+bcbfow2qomMh5+2NI=",
		"Q8WhfIucZ4fNSfXjfQT6HRkZfV6HMurSgO2BU917f4E=",
		"nUgCKjHnAEX06S0Gocb5I/H2ADWMeSPKii4PND9Hjm4=",
		"zJFC3E3SZhfPxSY/sxziRG1pX5pp/g7ba9/nP6kTFyU=",
		"u8jPvEekbPEBUZyVN9ra2BqRvjlfHpdQwuu5dZHg7U8=",
		"PWEf6L9yPjeMl/xP0fI62FzCCLQklT28XWTYHDi+1FU=",
		"ntnLOuShjBY2f3clP3Adp5tv7PHJxcs7biernqnXa38=",
		"D1NIRb3FdEJKC3Kh84LDC5wtUwICURcGLeyLXF/c6vw=",
	}

	for i, expected := range expectedFingerprints {
		fp := newCommandFingerprint(randChannelID(prng, t),
			randAction(prng), randPayload(prng, t))

		if expected != fp.String() {
			t.Errorf("leaseFingerprint does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, fp)
		}
	}
}

// Tests that any changes to any of the inputs to newCommandFingerprint result
// in different fingerprints.
func Test_newCommandFingerprint_Uniqueness(t *testing.T) {
	rng := csprng.NewSystemRNG()
	const n = 100
	chanIDs := make([]*id.ID, n)
	payloads, encryptedPayloads := make([][]byte, n), make([][]byte, n)
	for i := 0; i < n; i++ {
		chanIDs[i] = randChannelID(rng, t)
		payloads[i] = randPayload(rng, t)
		encryptedPayloads[i] = randPayload(rng, t)

	}
	commands := []MessageType{Delete, Pinned, Mute}

	fingerprints := make(map[string]bool)
	for _, channelID := range chanIDs {
		for _, payload := range payloads {
			for _, command := range commands {
				fp := newCommandFingerprint(channelID, command, payload)
				if fingerprints[fp.String()] {
					t.Errorf("Fingerprint %s already exists.", fp)
				}

				fingerprints[fp.String()] = true
			}
		}
	}
}
