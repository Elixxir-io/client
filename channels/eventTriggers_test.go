////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"gitlab.com/elixxir/client/v4/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
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

type dummyMessageTypeHandler struct {
	triggered        bool
	channelID        *id.ID
	messageID        cryptoChannel.MessageID
	messageType      MessageType
	nickname         string
	content          []byte
	encryptedPayload []byte
	timestamp        time.Time
	lease            time.Duration
	round            rounds.Round
}

func (dh *dummyMessageTypeHandler) dummyMessageTypeReceiveMessage(
	v ReceiveMessageValues) uint64 {
	dh.triggered = true
	dh.channelID = v.ChannelID
	dh.messageID = v.MessageID
	dh.messageType = v.MessageType
	dh.nickname = v.Nickname
	dh.content = v.Content
	dh.encryptedPayload = v.EncryptedPayload
	dh.timestamp = v.Timestamp
	dh.lease = v.Lease
	dh.round = v.Round
	return rand.Uint64()
}

func Test_events_triggerEvents(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	dummy := &dummyMessageTypeHandler{}

	// Register the handler
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, NewReceiveMessageHandler(
		"dummy", dummy.dummyMessageTypeReceiveMessage, true, false, true))
	if err != nil {
		t.Fatalf("Error on registration, should not have happened: %+v", err)
	}

	// Craft the input for the event
	chID := &id.ID{1}
	umi, _, _ := builtTestUMI(t, mt)
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}

	// Call the trigger
	_, err = e.triggerEvent(chID, umi, nil, netTime.Now(),
		receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatal(err)
	}

	// Check the data is stored in the dummy
	expected := &dummyMessageTypeHandler{true, chID, umi.GetMessageID(), mt,
		umi.channelMessage.Nickname, umi.GetChannelMessage().Payload, nil,
		dummy.timestamp, time.Duration(umi.GetChannelMessage().Lease), r}
	if !reflect.DeepEqual(expected, dummy) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, dummy)
	}

	if !withinMutationWindow(r.Timestamps[states.QUEUED], dummy.timestamp) {
		t.Errorf("Incorrect timestamp.\nexpected: %s\nreceived: %s",
			r.Timestamps[states.QUEUED], dummy.timestamp)
	}
}

func Test_events_triggerEvents_noChannel(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	dummy := &dummyMessageTypeHandler{}

	// skip handler registration
	mt := MessageType(1)

	// Craft the input for the event
	chID := &id.ID{1}

	umi, _, _ := builtTestUMI(t, mt)

	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}

	// call the trigger
	_, err := e.triggerEvent(chID, umi, nil, netTime.Now(),
		receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatal(err)
	}

	// check that the event was triggered
	if dummy.triggered {
		t.Errorf("The event was triggered when it is unregistered")
	}
}

func Test_events_triggerAdminEvents(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	dummy := &dummyMessageTypeHandler{}

	// Register the handler
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, NewReceiveMessageHandler(
		"dummy", dummy.dummyMessageTypeReceiveMessage, false, true, false))
	if err != nil {
		t.Fatalf("Error on registration: %+v", err)
	}

	// Craft the input for the event
	chID := &id.ID{1}
	u, _, cm := builtTestUMI(t, mt)
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	msgID := cryptoChannel.MakeMessageID(u.userMessage.Message, chID)

	// Call the trigger
	_, err = e.triggerAdminEvent(chID, cm, nil, netTime.Now(), msgID,
		receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatal(err)
	}

	// Check the data is stored in the dummy
	expected := &dummyMessageTypeHandler{true, chID, msgID, mt, AdminUsername,
		cm.Payload, nil, dummy.timestamp, time.Duration(cm.Lease), r}
	if !reflect.DeepEqual(expected, dummy) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, dummy)
	}

	if !withinMutationWindow(r.Timestamps[states.QUEUED], dummy.timestamp) {
		t.Errorf("Incorrect timestamp.\nexpected: %s\nreceived: %s",
			r.Timestamps[states.QUEUED], dummy.timestamp)
	}
}

func Test_events_triggerAdminEvents_noChannel(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	dummy := &dummyMessageTypeHandler{}
	mt := AdminText

	// Craft the input for the event
	chID := &id.ID{1}
	u, _, cm := builtTestUMI(t, mt)
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	msgID := cryptoChannel.MakeMessageID(u.userMessage.Message, chID)

	// Call the trigger
	_, err := e.triggerAdminEvent(chID, cm, nil, netTime.Now(), msgID,
		receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the event was not triggered
	if dummy.triggered {
		t.Errorf("The admin event was triggered when unregistered")
	}
}
func TestEvents_triggerActionEvent(t *testing.T) {
	e := initEvents(&MockEvent{}, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))
	dummy := &dummyMessageTypeHandler{}

	// Register the handler
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, NewReceiveMessageHandler(
		"dummy", dummy.dummyMessageTypeReceiveMessage, false, true, false))
	if err != nil {
		t.Fatalf("Error on registration: %+v", err)
	}

	// Craft the input for the event
	chID := &id.ID{1}
	u, _, cm := builtTestUMI(t, mt)
	r := rounds.Round{ID: 420,
		Timestamps: map[states.Round]time.Time{states.QUEUED: netTime.Now()}}
	msgID := cryptoChannel.MakeMessageID(u.userMessage.Message, chID)

	// Call the trigger
	_, err = e.triggerActionEvent(chID, msgID, MessageType(cm.PayloadType),
		cm.Nickname, cm.Payload, nil, netTime.Now(), netTime.Now(),
		time.Duration(cm.Lease), r, r.ID, Delivered, true, false)
	if err != nil {
		t.Fatal(err)
	}

	// Check the data is stored in the dummy
	expected := &dummyMessageTypeHandler{true, chID, msgID, mt, cm.Nickname,
		cm.Payload, nil, dummy.timestamp, time.Duration(cm.Lease), r}
	if !reflect.DeepEqual(expected, dummy) {
		t.Errorf("Did not receive expected values."+
			"\nexpected: %+v\nreceived: %+v", expected, dummy)
	}

	if !withinMutationWindow(r.Timestamps[states.QUEUED], dummy.timestamp) {
		t.Errorf("Incorrect timestamp.\nexpected: %s\nreceived: %s",
			r.Timestamps[states.QUEUED], dummy.timestamp)
	}
}
