///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"bytes"
	"encoding/base64"
	gs "gitlab.com/elixxir/client/groupChat/groupStore"
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/crypto/group"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// Unit test of Manager.Send.
func TestManager_Send(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManagerWithStore(prng, 10, 0, nil, nil, t)
	message := []byte("Group chat message.")
	sender := m.gs.GetUser().DeepCopy()

	_, err := m.Send(g.ID, message)
	if err != nil {
		t.Errorf("Send() returned an error: %+v", err)
	}

	// Get messages sent with or return an error if no messages were sent
	var messages map[id.ID]format.Message
	if len(m.net.(*testNetworkManager).messages) > 0 {
		messages = m.net.(*testNetworkManager).GetMsgMap(0)
	} else {
		t.Error("No group cMix messages received.")
	}

	timeNow := netTime.Now()

	// Loop through each message and make sure the recipient ID matches a member
	// in the group and that each message can be decrypted and have the expected
	// values
	for rid, msg := range messages {
		// Check if recipient ID is in member list
		var foundMember group.Member
		for _, mem := range g.Members {
			if rid.Cmp(mem.ID) {
				foundMember = mem
			}
		}

		// Error if the recipient ID is not found in the member list
		if foundMember == (group.Member{}) {
			t.Errorf("Failed to find ID %s in memorship list.", rid)
			continue
		}

		publicMsg, err := unmarshalPublicMsg(msg.GetContents())
		if err != nil {
			t.Errorf("Failed to unmarshal publicMsg: %+v", err)
		}
		// Attempt to read the message
		messageID, timestamp, senderID, readMsg, err := m.decryptMessage(
			g, msg, publicMsg, timeNow)
		if err != nil {
			t.Errorf("Failed to read message for %s: %+v", rid.String(), err)
		}

		internalMsg, _ := newInternalMsg(publicMsg.GetPayloadSize())
		internalMsg.SetTimestamp(timestamp)
		internalMsg.SetSenderID(m.gs.GetUser().ID)
		internalMsg.SetPayload(message)
		expectedMsgID := group.NewMessageID(g.ID, internalMsg.Marshal())

		if expectedMsgID != messageID {
			t.Errorf("Message ID received for %s too different from expected."+
				"\nexpected: %s\nreceived: %s", &rid, expectedMsgID, messageID)
		}

		if !timestamp.Round(5 * time.Second).Equal(timeNow.Round(5 * time.Second)) {
			t.Errorf("Timestamp received for %s too different from expected."+
				"\nexpected: %s\nreceived: %s", &rid, timeNow, timestamp)
		}

		if !senderID.Cmp(sender.ID) {
			t.Errorf("Sender ID received for %s incorrect."+
				"\nexpected: %s\nreceived: %s", &rid, sender.ID, senderID)
		}

		if !bytes.Equal(readMsg, message) {
			t.Errorf("Message received for %s incorrect."+
				"\nexpected: %q\nreceived: %q", &rid, message, readMsg)
		}
	}
}

// Error path: error is returned when the message is too large.
func TestManager_Send_CmixMessageError(t *testing.T) {
	// Set up new test manager that will make SendManyCMIX error
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManagerWithStore(prng, 10, 0, nil, nil, t)
	expectedErr := strings.SplitN(newCmixMsgErr, "%", 2)[0]

	// Send message
	_, err := m.Send(g.ID, make([]byte, 400))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Send() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: SendManyCMIX returns an error.
func TestManager_Send_SendManyCMIXError(t *testing.T) {
	// Set up new test manager that will make SendManyCMIX error
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManagerWithStore(prng, 10, 1, nil, nil, t)
	expectedErr := strings.SplitN(sendManyCmixErr, "%", 2)[0]

	// Send message
	_, err := m.Send(g.ID, []byte("message"))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Send() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}

	// If messages were added, then error
	if len(m.net.(*testNetworkManager).messages) > 0 {
		t.Error("Group cMix messages received when SendManyCMIX errors.")
	}
}

// Tests that Manager.createMessages generates the messages for the correct
// group.
func TestManager_createMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManagerWithStore(prng, 10, 0, nil, nil, t)

	message := []byte("Test group message.")
	sender := m.gs.GetUser()
	messages, err := m.createMessages(g.ID, message)
	if err != nil {
		t.Errorf("createMessages() returned an error: %+v", err)
	}

	recipients := append(g.Members[:2], g.Members[3:]...)

	i := 0
	for rid, msg := range messages {
		for _, recipient := range recipients {
			if !rid.Cmp(recipient.ID) {
				continue
			}

			publicMsg, err := unmarshalPublicMsg(msg.GetContents())
			if err != nil {
				t.Errorf("Failed to unmarshal publicMsg: %+v", err)
			}

			messageID, timestamp, testSender, testMessage, err := m.decryptMessage(
				g, msg, publicMsg, netTime.Now())
			if err != nil {
				t.Errorf("Failed to find member to read message %d: %+v", i, err)
			}

			internalMsg, _ := newInternalMsg(publicMsg.GetPayloadSize())
			internalMsg.SetTimestamp(timestamp)
			internalMsg.SetSenderID(m.gs.GetUser().ID)
			internalMsg.SetPayload(message)
			expectedMsgID := group.NewMessageID(g.ID, internalMsg.Marshal())

			if messageID != expectedMsgID {
				t.Errorf("Failed to read correct message ID for message %d."+
					"\nexpected: %s\nreceived: %s", i, expectedMsgID, messageID)
			}

			if !sender.ID.Cmp(testSender) {
				t.Errorf("Failed to read correct sender ID for message %d."+
					"\nexpected: %s\nreceived: %s", i, sender.ID, testSender)
			}

			if !bytes.Equal(message, testMessage) {
				t.Errorf("Failed to read correct message for message %d."+
					"\nexpected: %s\nreceived: %s", i, message, testMessage)
			}
		}
		i++
	}
}

// Error path: test that an error is returned when the group ID does not match a
// group in storage.
func TestManager_createMessages_InvalidGroupIdError(t *testing.T) {
	expectedErr := strings.SplitN(newNoGroupErr, "%", 2)[0]

	// Create new test Manager and Group
	prng := rand.New(rand.NewSource(42))
	m, _ := newTestManagerWithStore(prng, 10, 0, nil, nil, t)

	// Read message and make sure the error is expected
	_, err := m.createMessages(id.NewIdFromString("invalidID", id.Group, t), nil)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("createMessages() did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that Manager.newMessage returns messages with correct data.
func TestGroup_newMessages(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManager(prng, t)

	message := []byte("Test group message.")
	sender := m.gs.GetUser()
	timestamp := netTime.Now()
	messages, err := m.newMessages(g, message, timestamp)
	if err != nil {
		t.Errorf("newMessages() returned an error: %+v", err)
	}

	recipients := append(g.Members[:2], g.Members[3:]...)

	i := 0
	for rid, msg := range messages {
		for _, recipient := range recipients {
			if !rid.Cmp(recipient.ID) {
				continue
			}

			publicMsg, err := unmarshalPublicMsg(msg.GetContents())
			if err != nil {
				t.Errorf("Failed to unmarshal publicMsg: %+v", err)
			}

			messageID, testTimestamp, testSender, testMessage, err := m.decryptMessage(
				g, msg, publicMsg, netTime.Now())
			if err != nil {
				t.Errorf("Failed to find member to read message %d.", i)
			}

			internalMsg, _ := newInternalMsg(publicMsg.GetPayloadSize())
			internalMsg.SetTimestamp(timestamp)
			internalMsg.SetSenderID(m.gs.GetUser().ID)
			internalMsg.SetPayload(message)
			expectedMsgID := group.NewMessageID(g.ID, internalMsg.Marshal())

			if messageID != expectedMsgID {
				t.Errorf("Failed to read correct message ID for message %d."+
					"\nexpected: %s\nreceived: %s", i, expectedMsgID, messageID)
			}

			if !timestamp.Equal(testTimestamp) {
				t.Errorf("Failed to read correct timeout for message %d."+
					"\nexpected: %s\nreceived: %s", i, timestamp, testTimestamp)
			}

			if !sender.ID.Cmp(testSender) {
				t.Errorf("Failed to read correct sender ID for message %d."+
					"\nexpected: %s\nreceived: %s", i, sender.ID, testSender)
			}

			if !bytes.Equal(message, testMessage) {
				t.Errorf("Failed to read correct message for message %d."+
					"\nexpected: %s\nreceived: %s", i, message, testMessage)
			}
		}
		i++
	}
}

// Error path: an error is returned when Manager.neCmixMsg returns an error.
func TestGroup_newMessages_NewCmixMsgError(t *testing.T) {
	expectedErr := strings.SplitN(newCmixErr, "%", 2)[0]
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManager(prng, t)

	_, err := m.newMessages(g, make([]byte, 1000), netTime.Now())
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newMessages() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that the message returned by newCmixMsg has all the expected parts.
func TestGroup_newCmixMsg(t *testing.T) {
	// Create new test Manager and Group
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManager(prng, t)

	// Create test parameters
	message := []byte("Test group message.")
	mem := g.Members[3]
	timeNow := netTime.Now()

	// Create cMix message
	prng = rand.New(rand.NewSource(42))
	msg, err := m.newCmixMsg(g, message, timeNow, mem, prng)
	if err != nil {
		t.Errorf("newCmixMsg() returned an error: %+v", err)
	}

	// Create expected salt
	prng = rand.New(rand.NewSource(42))
	var salt [group.SaltLen]byte
	prng.Read(salt[:])

	// Create expected key
	key, _ := group.NewKdfKey(g.Key, group.ComputeEpoch(timeNow), salt)

	// Create expected messages
	cmixMsg := format.NewMessage(m.store.Cmix().GetGroup().GetP().ByteLen())
	publicMsg, _ := newPublicMsg(cmixMsg.ContentsSize())
	internalMsg, _ := newInternalMsg(publicMsg.GetPayloadSize())
	internalMsg.SetTimestamp(timeNow)
	internalMsg.SetSenderID(m.gs.GetUser().ID)
	internalMsg.SetPayload(message)
	payload := internalMsg.Marshal()

	// Check if key fingerprint is correct
	expectedFp := group.NewKeyFingerprint(g.Key, salt, mem.ID)
	if expectedFp != msg.GetKeyFP() {
		t.Errorf("newCmixMsg() returned message with wrong key fingerprint."+
			"\nexpected: %s\nreceived: %s", expectedFp, msg.GetKeyFP())
	}

	// Check if key MAC is correct
	encryptedPayload := group.Encrypt(key, expectedFp, payload)
	expectedMAC := group.NewMAC(key, encryptedPayload, g.DhKeys[*mem.ID])
	if !bytes.Equal(expectedMAC, msg.GetMac()) {
		t.Errorf("newCmixMsg() returned message with wrong MAC."+
			"\nexpected: %+v\nreceived: %+v", expectedMAC, msg.GetMac())
	}

	// Attempt to unmarshal public group message
	publicMsg, err = unmarshalPublicMsg(msg.GetContents())
	if err != nil {
		t.Errorf("Failed to unmarshal cMix message contents: %+v", err)
	}

	// Attempt to decrypt payload
	decryptedPayload := group.Decrypt(key, expectedFp, publicMsg.GetPayload())
	internalMsg, err = unmarshalInternalMsg(decryptedPayload)
	if err != nil {
		t.Errorf("Failed to unmarshal decrypted payload contents: %+v", err)
	}

	// Check for expected values in internal message
	if !internalMsg.GetTimestamp().Equal(timeNow) {
		t.Errorf("Internal message has wrong timestamp."+
			"\nexpected: %s\nreceived: %s", timeNow, internalMsg.GetTimestamp())
	}
	sid, err := internalMsg.GetSenderID()
	if err != nil {
		t.Fatalf("Failed to get sender ID from internal message: %+v", err)
	}
	if !sid.Cmp(m.gs.GetUser().ID) {
		t.Errorf("Internal message has wrong sender ID."+
			"\nexpected: %s\nreceived: %s", m.gs.GetUser().ID, sid)
	}
	if !bytes.Equal(internalMsg.GetPayload(), message) {
		t.Errorf("Internal message has wrong payload."+
			"\nexpected: %s\nreceived: %s", message, internalMsg.GetPayload())
	}
}

// Error path: reader returns an error.
func TestGroup_newCmixMsg_SaltReaderError(t *testing.T) {
	expectedErr := strings.SplitN(saltReadErr, "%", 2)[0]
	m := &Manager{store: storage.InitTestingSession(t)}

	_, err := m.newCmixMsg(gs.Group{},
		[]byte{}, time.Time{}, group.Member{}, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newCmixMsg() failed to return the expected error"+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: size of message is too large for the internalMsg.
func TestGroup_newCmixMsg_InternalMsgSizeError(t *testing.T) {
	expectedErr := strings.SplitN(messageLenErr, "%", 2)[0]

	// Create new test Manager and Group
	prng := rand.New(rand.NewSource(42))
	m, g := newTestManager(prng, t)

	// Create test parameters
	message := make([]byte, 341)
	mem := group.Member{ID: id.NewIdFromString("memberID", id.User, t)}

	// Create cMix message
	prng = rand.New(rand.NewSource(42))
	_, err := m.newCmixMsg(g, message, netTime.Now(), mem, prng)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newCmixMsg() failed to return the expected error"+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: payload size too small to fit publicMsg.
func Test_newMessageParts_PublicMsgSizeErr(t *testing.T) {
	expectedErr := strings.SplitN(newPublicMsgErr, "%", 2)[0]

	_, _, err := newMessageParts(publicMinLen - 1)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newMessageParts() did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: payload size too small to fit internalMsg.
func Test_newMessageParts_InternalMsgSizeErr(t *testing.T) {
	expectedErr := strings.SplitN(newInternalMsgErr, "%", 2)[0]

	_, _, err := newMessageParts(publicMinLen)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newMessageParts() did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests the consistency of newSalt.
func Test_newSalt_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedSalts := []string{
		"U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=",
		"39ebTXZCm2F6DJ+fDTulWwzA1hRMiIU1hBrL4HCbB1g=",
		"CD9h03W8ArQd9PkZKeGP2p5vguVOdI6B555LvW/jTNw=",
		"uoQ+6NY+jE/+HOvqVG2PrBPdGqwEzi6ih3xVec+ix44=",
		"GwuvrogbgqdREIpC7TyQPKpDRlp4YgYWl4rtDOPGxPM=",
		"rnvD4ElbVxL+/b4MECiH4QDazS2IX2kstgfaAKEcHHA=",
		"ceeWotwtwlpbdLLhKXBeJz8FySMmgo4rBW44F2WOEGE=",
		"SYlH/fNEQQ7UwRYCP6jjV2tv7Sf/iXS6wMr9mtBWkrE=",
		"NhnnOJZN/ceejVNDc2Yc/WbXT+weG4lJGrcjbkt1IWI=",
	}

	for i, expected := range expectedSalts {
		salt, err := newSalt(prng)
		if err != nil {
			t.Errorf("newSalt() returned an error (%d): %+v", i, err)
		}

		saltString := base64.StdEncoding.EncodeToString(salt[:])

		if expected != saltString {
			t.Errorf("newSalt() did not return the expected salt (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, saltString)
		}

		// fmt.Printf("\"%s\",\n", saltString)
	}
}

// Error path: reader returns an error.
func Test_newSalt_ReadError(t *testing.T) {
	expectedErr := strings.SplitN(saltReadErr, "%", 2)[0]

	_, err := newSalt(strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newSalt() failed to return the expected error"+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: reader fails to return enough bytes.
func Test_newSalt_ReadLengthError(t *testing.T) {
	expectedErr := strings.SplitN(saltReadLengthErr, "%", 2)[0]

	_, err := newSalt(strings.NewReader("A"))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("newSalt() failed to return the expected error"+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that the marshaled internalMsg can be unmarshaled and has all the
// original values.
func Test_setInternalPayload(t *testing.T) {
	internalMsg, err := newInternalMsg(internalMinLen * 2)
	if err != nil {
		t.Errorf("Failed to create a new internalMsg: %+v", err)
	}

	timestamp := netTime.Now()
	sender := id.NewIdFromString("sender ID", id.User, t)
	message := []byte("This is an internal message.")

	payload := setInternalPayload(internalMsg, timestamp, sender, message)
	if err != nil {
		t.Errorf("setInternalPayload() returned an error: %+v", err)
	}

	// Attempt to unmarshal and check all values
	unmarshalled, err := unmarshalInternalMsg(payload)
	if err != nil {
		t.Errorf("Failed to unmarshal internalMsg: %+v", err)
	}

	if !timestamp.Equal(unmarshalled.GetTimestamp()) {
		t.Errorf("Timestamp does not match original.\nexpected: %s\nreceived: %s",
			timestamp, unmarshalled.GetTimestamp())
	}

	testSender, err := unmarshalled.GetSenderID()
	if err != nil {
		t.Errorf("Failed to get sender ID: %+v", err)
	}
	if !sender.Cmp(testSender) {
		t.Errorf("Sender ID does not match original.\nexpected: %s\nreceived: %s",
			sender, testSender)
	}

	if !bytes.Equal(message, unmarshalled.GetPayload()) {
		t.Errorf("Payload does not match original.\nexpected: %v\nreceived: %v",
			message, unmarshalled.GetPayload())
	}
}

// Tests that the marshaled publicMsg can be unmarshaled and has all the
// original values.
func Test_setPublicPayload(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	publicMsg, err := newPublicMsg(publicMinLen * 2)
	if err != nil {
		t.Errorf("Failed to create a new publicMsg: %+v", err)
	}

	var salt [group.SaltLen]byte
	prng.Read(salt[:])
	encryptedPayload := make([]byte, publicMsg.GetPayloadSize())
	copy(encryptedPayload, "This is an internal message.")

	payload := setPublicPayload(publicMsg, salt, encryptedPayload)
	if err != nil {
		t.Errorf("setPublicPayload() returned an error: %+v", err)
	}

	// Attempt to unmarshal and check all values
	unmarshalled, err := unmarshalPublicMsg(payload)
	if err != nil {
		t.Errorf("Failed to unmarshal publicMsg: %+v", err)
	}

	if salt != unmarshalled.GetSalt() {
		t.Errorf("Salt does not match original.\nexpected: %v\nreceived: %v",
			salt, unmarshalled.GetSalt())
	}

	if !bytes.Equal(encryptedPayload, unmarshalled.GetPayload()) {
		t.Errorf("Payload does not match original.\nexpected: %v\nreceived: %v",
			encryptedPayload, unmarshalled.GetPayload())
	}
}
