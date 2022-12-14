////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func Test_initEvents(t *testing.T) {
	me := &MockEvent{}
	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// verify the model is registered
	if e.model != me {
		t.Errorf("Event model is not registered")
	}

	// check registered channels was created
	if e.registered == nil {
		t.Fatalf("Registered handlers is not registered")
	}

	// check that all the default callbacks are registered
	if len(e.registered) != 7 {
		t.Errorf("The correct number of default handlers are not "+
			"registered; %d vs %d", len(e.registered), 7)
		// If this fails, is means the default handlers have changed. edit the
		// number here and add tests below. be suspicious if it goes down.
	}

	if getFuncName(e.registered[Text].listener) != getFuncName(e.receiveTextMessage) {
		t.Errorf("Text does not have recieveTextMessageRegistred")
	}

	if getFuncName(e.registered[AdminText].listener) != getFuncName(e.receiveTextMessage) {
		t.Errorf("AdminText does not have recieveTextMessageRegistred")
	}

	if getFuncName(e.registered[Reaction].listener) != getFuncName(e.receiveReaction) {
		t.Errorf("Reaction does not have recieveReaction")
	}
}

// Unit test of NewReceiveMessageHandler.
func TestNewReceiveMessageHandler(t *testing.T) {
	expected := &ReceiveMessageHandler{
		name:       "handlerName",
		userSpace:  true,
		adminSpace: true,
		mutedSpace: true,
	}

	received := NewReceiveMessageHandler(expected.name, expected.listener,
		expected.userSpace, expected.adminSpace, expected.mutedSpace)

	if !reflect.DeepEqual(expected, received) {
		t.Errorf("New ReceiveMessageHandler does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, received)
	}
}

// Tests that ReceiveMessageHandler.CheckSpace returns the expected output for
// every possible combination of user, admin, and muted space.
func TestReceiveMessageHandler_CheckSpace(t *testing.T) {
	handlers := []struct {
		*ReceiveMessageHandler
		expected []bool
	}{
		{NewReceiveMessageHandler("0", nil, true, true, true),
			[]bool{true, true, true, true, true, true, false, false}},
		{NewReceiveMessageHandler("1", nil, true, true, false),
			[]bool{false, true, false, true, false, true, false, false}},
		{NewReceiveMessageHandler("2", nil, true, false, true),
			[]bool{true, true, true, true, false, false, false, false}},
		{NewReceiveMessageHandler("3", nil, true, false, false),
			[]bool{false, true, false, true, false, false, false, false}},
		{NewReceiveMessageHandler("4", nil, false, true, true),
			[]bool{true, true, false, false, true, true, false, false}},
		{NewReceiveMessageHandler("5", nil, false, true, false),
			[]bool{false, true, false, false, false, true, false, false}},
		{NewReceiveMessageHandler("6", nil, false, false, true),
			[]bool{false, false, false, false, false, false, false, false}},
		{NewReceiveMessageHandler("7", nil, false, false, false),
			[]bool{false, false, false, false, false, false, false, false}},
	}

	tests := []struct{ user, admin, muted bool }{
		{true, true, true},    // 0
		{true, true, false},   // 1
		{true, false, true},   // 2
		{true, false, false},  // 3
		{false, true, true},   // 4
		{false, true, false},  // 5
		{false, false, true},  // 6
		{false, false, false}, // 7
	}

	for i, handler := range handlers {
		for j, tt := range tests {
			err := handler.CheckSpace(tt.user, tt.admin, tt.muted)
			if handler.expected[j] && err != nil {
				t.Errorf("Handler %d failed test %d: %s", i, j, err)
			} else if !handler.expected[j] && err == nil {
				t.Errorf("Handler %s (#%d) did not fail test #%d when it "+
					"should have.\nhandler: %s\ntest:    %+v",
					handler.name, i, j, handler.SpaceString(), tt)
			}
		}
	}
}

func Test_events_RegisterReceiveHandler(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me, 512, versioned.NewKV(ekv.MakeMemstore()),
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG))

	// Test that a new reception handler can be registered.
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, NewReceiveMessageHandler(
		"reaction", e.receiveReaction, true, false, true))
	if err != nil {
		t.Fatalf("Failed to register '%s' when it should be "+
			"sucesfull: %+v", mt, err)
	}

	// check that it is written
	returnedHandler, exists := e.registered[mt]
	if !exists {
		t.Fatalf("Failed to get handler '%s' after registration", mt)
	}

	// check that the correct function is written
	if getFuncName(e.receiveReaction) != getFuncName(returnedHandler.listener) {
		t.Fatalf("Failed to get correct handler for '%s' after "+
			"registration, %s vs %s", mt, getFuncName(e.receiveReaction),
			getFuncName(returnedHandler.listener))
	}

	// test that writing to the same receive handler fails
	err = e.RegisterReceiveHandler(mt, NewReceiveMessageHandler(
		"userTextMessage", e.receiveTextMessage, true, false, true))
	if err == nil {
		t.Fatalf("Failed to register '%s' when it should be "+
			"sucesfull: %+v", mt, err)
	} else if err != MessageTypeAlreadyRegistered {
		t.Fatalf("Wrong error returned when reregierting message "+
			"tyle '%s': %+v", mt, err)
	}

	// check that it is still written
	returnedHandler, exists = e.registered[mt]
	if !exists {
		t.Fatalf("Failed to get handler '%s' after second "+
			"registration", mt)
	}

	// check that the correct function is written
	if getFuncName(e.receiveReaction) != getFuncName(returnedHandler.listener) {
		t.Fatalf("Failed to get correct handler for '%s' after "+
			"second registration, %s vs %s", mt, getFuncName(e.receiveReaction),
			getFuncName(returnedHandler.listener))
	}
}

func getFuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

////////////////////////////////////////////////////////////////////////////////
// Mock Event Model                                                           //
////////////////////////////////////////////////////////////////////////////////
type eventReceive struct {
	channelID   *id.ID
	messageID   cryptoChannel.MessageID
	reactionTo  cryptoChannel.MessageID
	nickname    string
	content     []byte
	timestamp   time.Time
	lease       time.Duration
	round       rounds.Round
	status      SentStatus
	pinned      bool
	hidden      bool
	messageType MessageType
	codeset     uint8
}

type MockEvent struct {
	uuid uint64
	eventReceive
}

func (m *MockEvent) getUUID() uint64 {
	old := m.uuid
	m.uuid++
	return old
}

func (*MockEvent) JoinChannel(*cryptoBroadcast.Channel) {}
func (*MockEvent) LeaveChannel(*id.ID)                  {}
func (m *MockEvent) ReceiveMessage(channelID *id.ID,
	messageID cryptoChannel.MessageID, nickname, text string,
	_ ed25519.PublicKey, codeset uint8, timestamp time.Time,
	lease time.Duration, round rounds.Round, messageType MessageType,
	status SentStatus, hidden bool) uint64 {
	m.eventReceive = eventReceive{
		channelID:   channelID,
		messageID:   messageID,
		reactionTo:  cryptoChannel.MessageID{},
		nickname:    nickname,
		content:     []byte(text),
		timestamp:   timestamp,
		lease:       lease,
		round:       round,
		status:      status,
		pinned:      false,
		hidden:      hidden,
		messageType: messageType,
		codeset:     codeset,
	}
	return m.getUUID()
}
func (m *MockEvent) ReceiveReply(channelID *id.ID, messageID,
	reactionTo cryptoChannel.MessageID, nickname, text string,
	_ ed25519.PublicKey, codeset uint8, timestamp time.Time,
	lease time.Duration, round rounds.Round, messageType MessageType,
	status SentStatus, hidden bool) uint64 {
	m.eventReceive = eventReceive{
		channelID:   channelID,
		messageID:   messageID,
		reactionTo:  reactionTo,
		nickname:    nickname,
		content:     []byte(text),
		timestamp:   timestamp,
		lease:       lease,
		round:       round,
		status:      status,
		pinned:      false,
		hidden:      hidden,
		messageType: messageType,
		codeset:     codeset,
	}
	return m.getUUID()
}
func (m *MockEvent) ReceiveReaction(channelID *id.ID, messageID,
	reactionTo cryptoChannel.MessageID, nickname, reaction string,
	_ ed25519.PublicKey, codeset uint8, timestamp time.Time,
	lease time.Duration, round rounds.Round, messageType MessageType,
	status SentStatus, hidden bool) uint64 {
	m.eventReceive = eventReceive{
		channelID:   channelID,
		messageID:   messageID,
		reactionTo:  reactionTo,
		nickname:    nickname,
		content:     []byte(reaction),
		timestamp:   timestamp,
		lease:       lease,
		round:       round,
		status:      status,
		pinned:      false,
		hidden:      hidden,
		messageType: messageType,
		codeset:     codeset,
	}
	return m.getUUID()
}

func (m *MockEvent) UpdateFromUUID(_ uint64, messageID *cryptoChannel.MessageID,
	timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
	status *SentStatus) {

	if messageID != nil {
		m.eventReceive.messageID = *messageID
	}
	if timestamp != nil {
		m.eventReceive.timestamp = *timestamp
	}
	if round != nil {
		m.eventReceive.round = *round
	}
	if status != nil {
		m.eventReceive.status = *status
	}
	if pinned != nil {
		m.eventReceive.pinned = *pinned
	}
	if hidden != nil {
		m.eventReceive.hidden = *hidden
	}
}

func (m *MockEvent) UpdateFromMessageID(_ cryptoChannel.MessageID,
	timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
	status *SentStatus) uint64 {

	if timestamp != nil {
		m.eventReceive.timestamp = *timestamp
	}
	if round != nil {
		m.eventReceive.round = *round
	}
	if status != nil {
		m.eventReceive.status = *status
	}
	if pinned != nil {
		m.eventReceive.pinned = *pinned
	}
	if hidden != nil {
		m.eventReceive.hidden = *hidden
	}

	return m.getUUID()
}

func (m *MockEvent) GetMessage(cryptoChannel.MessageID) (ModelMessage, error) {
	return ModelMessage{
		UUID:            m.getUUID(),
		Nickname:        m.eventReceive.nickname,
		MessageID:       m.eventReceive.messageID,
		ChannelID:       m.eventReceive.channelID,
		ParentMessageID: m.reactionTo,
		Timestamp:       m.eventReceive.timestamp,
		Lease:           m.eventReceive.lease,
		Status:          m.status,
		Hidden:          m.hidden,
		Pinned:          m.pinned,
		Content:         m.eventReceive.content,
		Type:            m.messageType,
		Round:           m.round.ID,
		PubKey:          nil,
		CodesetVersion:  m.codeset,
	}, nil
}
