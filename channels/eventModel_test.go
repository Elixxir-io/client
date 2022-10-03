////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"gitlab.com/elixxir/client/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/cmix/rounds"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"runtime"
	"testing"
	"time"
)

type eventReceive struct {
	channelID  *id.ID
	messageID  cryptoChannel.MessageID
	reactionTo cryptoChannel.MessageID
	nickname   string
	content    []byte
	timestamp  time.Time
	lease      time.Duration
	round      rounds.Round
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

func (m *MockEvent) UpdateSentStatus(uuid uint64, messageID cryptoChannel.MessageID,
	timestamp time.Time, round rounds.Round, status SentStatus) {
	//TODO implement me
	panic("implement me")
}

func (*MockEvent) JoinChannel(channel *cryptoBroadcast.Channel) {}
func (*MockEvent) LeaveChannel(channelID *id.ID)                {}
func (m *MockEvent) ReceiveMessage(channelID *id.ID, messageID cryptoChannel.MessageID,
	nickname, text string, identity cryptoChannel.Identity,
	timestamp time.Time, lease time.Duration, round rounds.Round,
	mType MessageType, status SentStatus) uint64 {
	m.eventReceive = eventReceive{
		channelID:  channelID,
		messageID:  messageID,
		reactionTo: cryptoChannel.MessageID{},
		nickname:   nickname,
		content:    []byte(text),
		timestamp:  timestamp,
		lease:      lease,
		round:      round,
	}
	return m.getUUID()
}
func (m *MockEvent) ReceiveReply(channelID *id.ID, messageID cryptoChannel.MessageID,
	reactionTo cryptoChannel.MessageID, nickname, text string,
	identity cryptoChannel.Identity, timestamp time.Time,
	lease time.Duration, round rounds.Round, mType MessageType, status SentStatus) uint64 {
	fmt.Println(reactionTo)
	m.eventReceive = eventReceive{
		channelID:  channelID,
		messageID:  messageID,
		reactionTo: reactionTo,
		nickname:   nickname,
		content:    []byte(text),
		timestamp:  timestamp,
		lease:      lease,
		round:      round,
	}
	return m.getUUID()
}
func (m *MockEvent) ReceiveReaction(channelID *id.ID, messageID cryptoChannel.MessageID,
	reactionTo cryptoChannel.MessageID, nickname, reaction string,
	identity cryptoChannel.Identity, timestamp time.Time,
	lease time.Duration, round rounds.Round, mType MessageType, status SentStatus) uint64 {
	m.eventReceive = eventReceive{
		channelID:  channelID,
		messageID:  messageID,
		reactionTo: reactionTo,
		nickname:   nickname,
		content:    []byte(reaction),
		timestamp:  timestamp,
		lease:      lease,
		round:      round,
	}
	return m.getUUID()
}

func Test_initEvents(t *testing.T) {

	me := &MockEvent{}

	e := initEvents(me)

	// verify the model is registered
	if e.model != me {
		t.Errorf("Event model is not registered")
	}

	// check registered channels was created
	if e.registered == nil {
		t.Fatalf("Registered handlers is not registered")
	}

	// check that all the default callbacks are registered
	if len(e.registered) != 3 {
		t.Errorf("The correct number of default handlers are not "+
			"registered; %d vs %d", len(e.registered), 3)
		//If this fails, is means the default handlers have changed. edit the
		//number here and add tests below. be suspicious if it goes down.
	}

	if getFuncName(e.registered[Text]) != getFuncName(e.receiveTextMessage) {
		t.Errorf("Text does not have recieveTextMessageRegistred")
	}

	if getFuncName(e.registered[AdminText]) != getFuncName(e.receiveTextMessage) {
		t.Errorf("AdminText does not have recieveTextMessageRegistred")
	}

	if getFuncName(e.registered[Reaction]) != getFuncName(e.receiveReaction) {
		t.Errorf("Reaction does not have recieveReaction")
	}
}

func TestEvents_RegisterReceiveHandler(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//test that a new receive handler can be registered.
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, e.receiveReaction)
	if err != nil {
		t.Fatalf("Failed to register '%s' when it should be "+
			"sucesfull: %+v", mt, err)
	}

	//check that it is written
	returnedHandler, exists := e.registered[mt]
	if !exists {
		t.Fatalf("Failed to get handler '%s' after registration", mt)
	}

	//check that the correct function is written
	if getFuncName(e.receiveReaction) != getFuncName(returnedHandler) {
		t.Fatalf("Failed to get correct handler for '%s' after "+
			"registration, %s vs %s", mt, getFuncName(e.receiveReaction),
			getFuncName(returnedHandler))
	}

	//test that writing to the same receive handler fails
	err = e.RegisterReceiveHandler(mt, e.receiveTextMessage)
	if err == nil {
		t.Fatalf("Failed to register '%s' when it should be "+
			"sucesfull: %+v", mt, err)
	} else if err != MessageTypeAlreadyRegistered {
		t.Fatalf("Wrong error returned when reregierting message "+
			"tyle '%s': %+v", mt, err)
	}

	//check that it is still written
	returnedHandler, exists = e.registered[mt]
	if !exists {
		t.Fatalf("Failed to get handler '%s' after second "+
			"registration", mt)
	}

	//check that the correct function is written
	if getFuncName(e.receiveReaction) != getFuncName(returnedHandler) {
		t.Fatalf("Failed to get correct handler for '%s' after "+
			"second registration, %s vs %s", mt, getFuncName(e.receiveReaction),
			getFuncName(returnedHandler))
	}
}

type dummyMessageTypeHandler struct {
	triggered   bool
	channelID   *id.ID
	messageID   cryptoChannel.MessageID
	messageType MessageType
	nickname    string
	content     []byte
	timestamp   time.Time
	lease       time.Duration
	round       rounds.Round
}

func (dmth *dummyMessageTypeHandler) dummyMessageTypeReceiveMessage(channelID *id.ID,
	messageID cryptoChannel.MessageID, messageType MessageType,
	nickname string, content []byte, identity cryptoChannel.Identity,
	timestamp time.Time, lease time.Duration, round rounds.Round,
	status SentStatus) uint64 {
	dmth.triggered = true
	dmth.channelID = channelID
	dmth.messageID = messageID
	dmth.messageType = messageType
	dmth.nickname = nickname
	dmth.content = content
	dmth.timestamp = timestamp
	dmth.lease = lease
	dmth.round = round
	return rand.Uint64()
}

func TestEvents_triggerEvents(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	dummy := &dummyMessageTypeHandler{}

	//register the handler
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, dummy.dummyMessageTypeReceiveMessage)
	if err != nil {
		t.Fatalf("Error on registration, should not have happened: "+
			"%+v", err)
	}

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	umi, _, _ := builtTestUMI(t, mt)

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	//call the trigger
	_, err = e.triggerEvent(chID, umi, time.Now(), receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//check that the event was triggered
	if !dummy.triggered {
		t.Errorf("The event was not triggered")
	}

	//check the data is stored in the dummy
	if !dummy.channelID.Cmp(chID) {
		t.Errorf("The channel IDs do not match %s vs %s",
			dummy.channelID, chID)
	}

	if !dummy.messageID.Equals(umi.GetMessageID()) {
		t.Errorf("The message IDs do not match %s vs %s",
			dummy.messageID, umi.GetMessageID())
	}

	if dummy.messageType != mt {
		t.Errorf("The message types do not match %s vs %s",
			dummy.messageType, mt)
	}

	if dummy.nickname != umi.channelMessage.Nickname {
		t.Errorf("The usernames do not match %s vs %s",
			dummy.nickname, umi.channelMessage.Nickname)
	}

	if !bytes.Equal(dummy.content, umi.GetChannelMessage().Payload) {
		t.Errorf("The payloads do not match %s vs %s",
			dummy.content, umi.GetChannelMessage().Payload)
	}

	if !withinMutationWindow(r.Timestamps[states.QUEUED], dummy.timestamp) {
		t.Errorf("The timestamps do not match %s vs %s",
			dummy.timestamp, r.Timestamps[states.QUEUED])
	}

	if dummy.lease != time.Duration(umi.GetChannelMessage().Lease) {
		t.Errorf("The messge lease durations do not match %s vs %s",
			dummy.lease, time.Duration(umi.GetChannelMessage().Lease))
	}

	if dummy.round.ID != r.ID {
		t.Errorf("The messge round does not match %s vs %s",
			dummy.round.ID, r.ID)
	}
}

func TestEvents_triggerEvents_noChannel(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	dummy := &dummyMessageTypeHandler{}

	//skip handler registration
	mt := MessageType(1)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	umi, _, _ := builtTestUMI(t, mt)

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	//call the trigger
	_, err := e.triggerEvent(chID, umi, time.Now(), receptionID.EphemeralIdentity{}, r, Delivered)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that the event was triggered
	if dummy.triggered {
		t.Errorf("The event was triggered when it is unregistered")
	}
}

func TestEvents_triggerAdminEvents(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	dummy := &dummyMessageTypeHandler{}

	//register the handler
	mt := MessageType(42)
	err := e.RegisterReceiveHandler(mt, dummy.dummyMessageTypeReceiveMessage)
	if err != nil {
		t.Fatalf("Error on registration, should not have happened: "+
			"%+v", err)
	}

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	u, _, cm := builtTestUMI(t, mt)

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	msgID := cryptoChannel.MakeMessageID(u.userMessage.Message)

	//call the trigger
	_, err = e.triggerAdminEvent(chID, cm, time.Now(), msgID, receptionID.EphemeralIdentity{}, r,
		Delivered)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that the event was triggered
	if !dummy.triggered {
		t.Errorf("The admin event was not triggered")
	}

	//check the data is stored in the dummy
	if !dummy.channelID.Cmp(chID) {
		t.Errorf("The channel IDs do not match %s vs %s",
			dummy.channelID, chID)
	}

	if !dummy.messageID.Equals(msgID) {
		t.Errorf("The message IDs do not match %s vs %s",
			dummy.messageID, msgID)
	}

	if dummy.messageType != mt {
		t.Errorf("The message types do not match %s vs %s",
			dummy.messageType, mt)
	}

	if dummy.nickname != AdminUsername {
		t.Errorf("The usernames do not match %s vs %s",
			dummy.nickname, AdminUsername)
	}

	if !bytes.Equal(dummy.content, cm.Payload) {
		t.Errorf("The payloads do not match %s vs %s",
			dummy.content, cm.Payload)
	}

	if !withinMutationWindow(r.Timestamps[states.QUEUED], dummy.timestamp) {
		t.Errorf("The timestamps do not match %s vs %s",
			dummy.timestamp, r.Timestamps[states.QUEUED])
	}

	if dummy.lease != time.Duration(cm.Lease) {
		t.Errorf("The messge lease durations do not match %s vs %s",
			dummy.lease, time.Duration(cm.Lease))
	}

	if dummy.round.ID != r.ID {
		t.Errorf("The messge round does not match %s vs %s",
			dummy.round.ID, r.ID)
	}
}

func TestEvents_triggerAdminEvents_noChannel(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	dummy := &dummyMessageTypeHandler{}

	mt := MessageType(1)
	//skip handler registration

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	u, _, cm := builtTestUMI(t, mt)

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	msgID := cryptoChannel.MakeMessageID(u.userMessage.Message)

	//call the trigger
	_, err := e.triggerAdminEvent(chID, cm, time.Now(), msgID, receptionID.EphemeralIdentity{}, r,
		Delivered)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//check that the event was triggered
	if dummy.triggered {
		t.Errorf("The admin event was triggered when unregistered")
	}
}

func TestEvents_receiveTextMessage_Message(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: nil,
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	senderNickname := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	//call the handler
	e.receiveTextMessage(chID, msgID, 0, senderNickname,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if !me.eventReceive.channelID.Cmp(chID) {
		t.Errorf("Channel ID did not propogate correctly, %s vs %s",
			me.eventReceive.channelID, chID)
	}

	if !me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID did not propogate correctly, %s vs %s",
			me.eventReceive.messageID, msgID)
	}

	if !me.eventReceive.reactionTo.Equals(cryptoChannel.MessageID{}) {
		t.Errorf("Reaction ID is not blank, %s",
			me.eventReceive.reactionTo)
	}

	if me.eventReceive.nickname != senderNickname {
		t.Errorf("SenderID propogate correctly, %s vs %s",
			me.eventReceive.nickname, senderNickname)
	}

	if me.eventReceive.timestamp != ts {
		t.Errorf("Message timestamp did not propogate correctly, %s vs %s",
			me.eventReceive.timestamp, ts)
	}

	if me.eventReceive.lease != lease {
		t.Errorf("Message lease did not propogate correctly, %s vs %s",
			me.eventReceive.lease, lease)
	}

	if me.eventReceive.round.ID != r.ID {
		t.Errorf("Message round did not propogate correctly, %d vs %d",
			me.eventReceive.round.ID, r.ID)
	}
}

func TestEvents_receiveTextMessage_Reply(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"))

	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: replyMsgId[:],
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	senderUsername := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//call the handler
	e.receiveTextMessage(chID, msgID, Text, senderUsername,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if !me.eventReceive.channelID.Cmp(chID) {
		t.Errorf("Channel ID did not propogate correctly, %s vs %s",
			me.eventReceive.channelID, chID)
	}

	if !me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID did not propogate correctly, %s vs %s",
			me.eventReceive.messageID, msgID)
	}

	if !me.eventReceive.reactionTo.Equals(replyMsgId) {
		t.Errorf("Reaction ID is not equal to what was passed in, "+
			"%s vs %s", me.eventReceive.reactionTo, replyMsgId)
	}

	if me.eventReceive.nickname != senderUsername {
		t.Errorf("SenderID propogate correctly, %s vs %s",
			me.eventReceive.nickname, senderUsername)
	}

	if me.eventReceive.timestamp != ts {
		t.Errorf("Message timestamp did not propogate correctly, "+
			"%s vs %s", me.eventReceive.timestamp, ts)
	}

	if me.eventReceive.lease != lease {
		t.Errorf("Message lease did not propogate correctly, %s vs %s",
			me.eventReceive.lease, lease)
	}

	if me.eventReceive.round.ID != r.ID {
		t.Errorf("Message round did not propogate correctly, %d vs %d",
			me.eventReceive.round.ID, r.ID)
	}
}

func TestEvents_receiveTextMessage_Reply_BadReply(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	replyMsgId := []byte("blarg")

	textPayload := &CMIXChannelText{
		Version:        0,
		Text:           "They Don't Think It Be Like It Is, But It Do",
		ReplyMessageID: replyMsgId[:],
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	senderUsername := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//call the handler
	e.receiveTextMessage(chID, msgID, 0, senderUsername,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if !me.eventReceive.channelID.Cmp(chID) {
		t.Errorf("Channel ID did not propogate correctly, %s vs %s",
			me.eventReceive.channelID, chID)
	}

	if !me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID did not propogate correctly, %s vs %s",
			me.eventReceive.messageID, msgID)
	}

	if !me.eventReceive.reactionTo.Equals(cryptoChannel.MessageID{}) {
		t.Errorf("Reaction ID is not blank, %s",
			me.eventReceive.reactionTo)
	}

	if me.eventReceive.nickname != senderUsername {
		t.Errorf("SenderID propogate correctly, %s vs %s",
			me.eventReceive.nickname, senderUsername)
	}

	if me.eventReceive.timestamp != ts {
		t.Errorf("Message timestamp did not propogate correctly, "+
			"%s vs %s", me.eventReceive.timestamp, ts)
	}

	if me.eventReceive.lease != lease {
		t.Errorf("Message lease did not propogate correctly, %s vs %s",
			me.eventReceive.lease, lease)
	}

	if me.eventReceive.round.ID != r.ID {
		t.Errorf("Message round did not propogate correctly, %d vs %d",
			me.eventReceive.round.ID, r.ID)
	}
}

func TestEvents_receiveReaction(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"))

	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "🍆",
		ReactionMessageID: replyMsgId[:],
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	senderUsername := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//call the handler
	e.receiveReaction(chID, msgID, 0, senderUsername,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if !me.eventReceive.channelID.Cmp(chID) {
		t.Errorf("Channel ID did not propogate correctly, %s vs %s",
			me.eventReceive.channelID, chID)
	}

	if !me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID did not propogate correctly, %s vs %s",
			me.eventReceive.messageID, msgID)
	}

	if !me.eventReceive.reactionTo.Equals(replyMsgId) {
		t.Errorf("Reaction ID is not equal to what was passed in, "+
			"%s vs %s", me.eventReceive.reactionTo, replyMsgId)
	}

	if me.eventReceive.nickname != senderUsername {
		t.Errorf("SenderID propogate correctly, %s vs %s",
			me.eventReceive.nickname, senderUsername)
	}

	if me.eventReceive.timestamp != ts {
		t.Errorf("Message timestamp did not propogate correctly, "+
			"%s vs %s", me.eventReceive.timestamp, ts)
	}

	if me.eventReceive.lease != lease {
		t.Errorf("Message lease did not propogate correctly, %s vs %s",
			me.eventReceive.lease, lease)
	}

	if me.eventReceive.round.ID != r.ID {
		t.Errorf("Message round did not propogate correctly, %d vs %d",
			me.eventReceive.round.ID, r.ID)
	}
}

func TestEvents_receiveReaction_InvalidReactionMessageID(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	replyMsgId := []byte("blarg")

	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "🍆",
		ReactionMessageID: replyMsgId[:],
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	senderUsername := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}

	//call the handler
	e.receiveReaction(chID, msgID, 0, senderUsername,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if me.eventReceive.channelID != nil {
		t.Errorf("Channel ID did propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID propogated correctly when the reaction is " +
			"bad")
	}

	if !me.eventReceive.reactionTo.Equals(cryptoChannel.MessageID{}) {
		t.Errorf("Reaction ID propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.nickname != "" {
		t.Errorf("SenderID propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.lease != 0 {
		t.Errorf("Message lease propogated correctly when the " +
			"reaction is bad")
	}
}

func TestEvents_receiveReaction_InvalidReactionContent(t *testing.T) {
	me := &MockEvent{}

	e := initEvents(me)

	//craft the input for the event
	chID := &id.ID{}
	chID[0] = 1

	replyMsgId := cryptoChannel.MakeMessageID([]byte("blarg"))

	textPayload := &CMIXChannelReaction{
		Version:           0,
		Reaction:          "I'm not a reaction",
		ReactionMessageID: replyMsgId[:],
	}

	textMarshaled, err := proto.Marshal(textPayload)
	if err != nil {
		t.Fatalf("failed to marshael the message proto: %+v", err)
	}

	msgID := cryptoChannel.MakeMessageID(textMarshaled)

	senderUsername := "Alice"
	ts := time.Now()

	lease := 69 * time.Minute

	r := rounds.Round{ID: 420, Timestamps: make(map[states.Round]time.Time)}
	r.Timestamps[states.QUEUED] = time.Now()

	rng := rand.New(rand.NewSource(64))

	pi, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf(err.Error())
	}
	//call the handler
	e.receiveReaction(chID, msgID, 0, senderUsername,
		textMarshaled, pi.Identity, ts, lease, r, Delivered)

	//check the results on the model
	if me.eventReceive.channelID != nil {
		t.Errorf("Channel ID did propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.messageID.Equals(msgID) {
		t.Errorf("Message ID propogated correctly when the reaction is " +
			"bad")
	}

	if !me.eventReceive.reactionTo.Equals(cryptoChannel.MessageID{}) {
		t.Errorf("Reaction ID propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.nickname != "" {
		t.Errorf("SenderID propogated correctly when the reaction " +
			"is bad")
	}

	if me.eventReceive.lease != 0 {
		t.Errorf("Message lease propogated correctly when the " +
			"reaction is bad")
	}
}

func getFuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
