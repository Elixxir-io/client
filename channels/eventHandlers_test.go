////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"github.com/golang/protobuf/proto"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func Test_events_receiveTextMessage_Message(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: nil,
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatalf("GenerateIdentity error: %+v", err)
	}
	senderNickname := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}

	// Call the handler
	e.receiveTextMessage(ReceiveMessageValues{chID, msgID, Text, senderNickname,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{chID, msgID, cryptoChannel.MessageID{},
		senderNickname, []byte(textPayload.Text), ts, lease, r, Delivered,
		false, false, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

func Test_events_receiveTextMessage_Reply(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: replyMsgId[:],
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler
	e.receiveTextMessage(ReceiveMessageValues{chID, msgID, Text, senderUsername,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{chID, msgID, replyMsgId,
		senderUsername, []byte(textPayload.Text), ts, lease, r, Delivered,
		false, false, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

func Test_events_receiveTextMessage_Reply_BadReply(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	replyMsgId := []byte("blarg")
	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: replyMsgId[:],
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler
	e.receiveTextMessage(ReceiveMessageValues{chID, msgID, Text, senderUsername,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{chID, msgID, cryptoChannel.MessageID{},
		senderUsername, []byte(textPayload.Text), ts, lease, r, Delivered,
		false, false, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

func Test_events_receiveReaction(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "🍆",
		ReactionMessageID: replyMsgId[:],
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler
	e.receiveReaction(ReceiveMessageValues{chID, msgID, Reaction,
		senderUsername, textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts,
		ts, lease, r, r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{chID, msgID, replyMsgId, senderUsername,
		[]byte(textPayload.Reaction), ts, lease, r, Delivered, false, false,
		Reaction, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

func Test_events_receiveReaction_InvalidReactionMessageID(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	replyMsgId := []byte("blarg")
	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "🍆",
		ReactionMessageID: replyMsgId[:],
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler
	e.receiveReaction(ReceiveMessageValues{chID, msgID, Reaction,
		senderUsername, textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts,
		ts, 0, r, r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{nil, cryptoChannel.MessageID{},
		cryptoChannel.MessageID{}, "", nil, time.Time{}, 0, rounds.Round{},
		0, false, false, 0, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

func Test_events_receiveReaction_InvalidReactionContent(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID := &id.ID{1}
	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "I'm not a reaction",
		ReactionMessageID: replyMsgId[:],
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to marshal the message proto: %+v", err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(rand.New(rand.NewSource(64)))
	if err != nil {
		t.Fatal(err)
	}

	// Call the handler
	e.receiveReaction(ReceiveMessageValues{chID, msgID, Reaction,
		senderUsername, textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts,
		ts, lease, r, r.ID, Delivered, false, false})

	// Check the results on the model
	expected := eventReceive{nil, cryptoChannel.MessageID{},
		cryptoChannel.MessageID{}, "", nil, time.Time{}, 0, rounds.Round{},
		0, false, false, 0, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

// Unit test of events.receiveDelete.
func Test_events_receiveDelete(t *testing.T) {
	me, prng := &MockEvent{}, rand.New(rand.NewSource(65))
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID, _ := id.NewRandomID(prng, id.User)
	targetMessageID := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelDelete{
		Version:    0,
		MessageID:  targetMessageID[:],
		UndoAction: false,
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to proto marshal %T: %+v", textPayload, err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(prng)
	if err != nil {
		t.Fatal(err)
	}

	me.eventReceive = eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, textMarshaled, ts, lease, r, Delivered,
		false, false, Text, 0}

	// Call the handler
	e.receiveDelete(ReceiveMessageValues{chID, msgID, Delete, AdminUsername,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, true, false})

	// Check the results on the model
	expected := eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, textMarshaled, ts, lease, r, Delivered,
		false, true, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

// Unit test of events.receivePinned.
func Test_events_receivePinned(t *testing.T) {
	me, prng := &MockEvent{}, rand.New(rand.NewSource(65))
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID, _ := id.NewRandomID(prng, id.User)
	targetMessageID := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelPinned{
		Version:    0,
		MessageID:  targetMessageID[:],
		UndoAction: false,
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to proto marshal %T: %+v", textPayload, err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(prng)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("someTest")
	me.eventReceive = eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, content, ts, lease, r, Delivered,
		false, false, Text, 0}

	// Call the handler
	e.receivePinned(ReceiveMessageValues{chID, msgID, Pinned, senderUsername,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, true, false})

	// Check the results on the model
	expected := eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, content, ts, lease, r, Delivered,
		true, false, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

// Unit test of events.receivePinned.
func Test_events_receiveMute(t *testing.T) {
	me, prng := &MockEvent{}, rand.New(rand.NewSource(65))
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID, _ := id.NewRandomID(prng, id.User)
	targetMessageID := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	pubKey, _, _ := ed25519.GenerateKey(prng)
	textPayload := &CMIXChannelMute{
		Version:    0,
		PubKey:     pubKey,
		UndoAction: false,
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to proto marshal %T: %+v", textPayload, err)
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(prng)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("someTest")
	me.eventReceive = eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, content, ts, lease, r, Delivered,
		false, false, Text, 0}

	// Call the handler
	e.receiveMute(ReceiveMessageValues{chID, msgID, Mute, senderUsername,
		textMarshaled, nil, pi.PubKey, pi.CodesetVersion, ts, ts, lease, r,
		r.ID, Delivered, true, false})

	// Check the results on the model
	expected := eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, content, ts, lease, r, Delivered,
		false, false, Text, 0}
	if !reflect.DeepEqual(expected, me.eventReceive) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, me.eventReceive)
	}
}

// Unit test of events.receiveAdminReplay.
func Test_events_receiveAdminReplay(t *testing.T) {
	me, prng := &MockEvent{}, csprng.NewSystemRNG()
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Craft the input for the event
	chID, _ := id.NewRandomID(prng, id.User)
	targetMessageID := cryptoChannel.MakeMessageID([]byte("blarg"), chID)
	textPayload := &CMIXChannelPinned{
		Version:    0,
		MessageID:  targetMessageID[:],
		UndoAction: false,
	}
	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("Failed to proto marshal %T: %+v", textPayload, err)
	}

	ch, pk, err := newTestChannel("abc", "", prng, cryptoBroadcast.Public)
	if err != nil {
		t.Fatalf("Failed to generate channel: %+v", err)
	}
	cipherText, _, _, _, err :=
		ch.EncryptRSAToPublic(textMarshaled, pk, 3072, prng)
	if err != nil {
		if err != nil {
			t.Fatalf("Failed to encrypt RSAToPublic: %+v", err)
		}
	}
	msgID := cryptoChannel.MakeMessageID(textMarshaled, chID)
	senderUsername := "Alice"
	ts := netTime.Now()
	lease := 69 * time.Minute
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	pi, err := cryptoChannel.GenerateIdentity(prng)
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("someTest")
	me.eventReceive = eventReceive{chID, cryptoChannel.MessageID{},
		targetMessageID, senderUsername, content, ts, lease, r, Delivered,
		false, false, Text, 0}

	c := make(chan []byte)
	e.processors.addProcessor(
		chID, adminProcessor, &testAdminProcessor{adminMsgChan: c})

	// Call the handler
	e.receiveAdminReplay(ReceiveMessageValues{chID, msgID, AdminReplay,
		senderUsername, cipherText, nil, pi.PubKey, pi.CodesetVersion,
		ts, ts, lease, r, r.ID, Delivered, false, false})

	select {
	case encrypted := <-c:
		decrypted, err2 := ch.DecryptRSAToPublicInner(encrypted)
		if err2 != nil {
			t.Errorf("Failed to decrypt message: %+v", err2)
		}

		received := &CMIXChannelPinned{}
		err = proto.Unmarshal(decrypted, received)
		if err != nil {
			t.Errorf("Failed to proto unmarshal message: %+v", err)
		}

		if !proto.Equal(textPayload, received) {
			t.Errorf("Received admin message does not match expected."+
				"\nexpected: %s\nreceived: %s", textPayload, received)
		}

	case <-time.After(15 * time.Millisecond):
		t.Errorf("Timed out waiting for processor to be called.")
	}
}
