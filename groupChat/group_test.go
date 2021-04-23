///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"bytes"
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/group"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"testing"
	"time"
)

// Tests that the message returned by newCmixMsg has all the expected parts.
func TestGroup_newCmixMsg(t *testing.T) {
	// Create new test Group
	prng := rand.New(rand.NewSource(42))
	g := &Group{
		id:    id.NewIdFromString("testGroupID", id.Group, t),
		key:   []byte("key"),
		store: storage.InitTestingSession(t),
	}

	// Create test parameters
	message := []byte("Test group message.")
	m := &group.Member{
		ID:    id.NewIdFromString("memberID", id.User, t),
		DhKey: randCycInt(prng),
	}
	senderID := id.NewIdFromString("senderID", id.User, t)
	timeNow := time.Now()

	// Create cMix message
	prng = rand.New(rand.NewSource(42))
	msg, err := g.newCmixMsg(message, m, senderID, timeNow, prng)
	if err != nil {
		t.Errorf("newCmixMsg() returned an error: %+v", err)
	}

	// Create expected salt
	prng = rand.New(rand.NewSource(42))
	salt := make([]byte, group.SaltLen)
	prng.Read(salt)

	// Create expected key
	key, _ := group.NewKdfKey(g.key, salt)

	// Create expected messages
	cmixMsg := format.NewMessage(g.store.Cmix().GetGroup().GetP().ByteLen())
	publicMsg, _ := newPublicMsg(cmixMsg.ContentsSize())
	internalMsg, _ := newInternalMsg(publicMsg.GetPayloadMaxSize())
	internalMsg.SetTimestamp(timeNow)
	internalMsg.SetSenderID(senderID)
	_ = internalMsg.SetPayload(message)
	payload := internalMsg.Marshal()

	// Check if key fingerprint is correct
	expectedFp, _ := group.NewKeyFingerprint(g.key, salt, m.ID)
	if expectedFp != msg.GetKeyFP() {
		t.Errorf("newCmixMsg() returned message with wrong key fingerprint."+
			"\nexpected: %s\nreceived: %s", expectedFp, msg.GetKeyFP())
	}

	// Check if key MAC is correct
	encryptedPayload := group.Encrypt(key, expectedFp[:], payload)
	expectedMAC := group.NewMAC(key, encryptedPayload, m.DhKey)
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
	decryptedPayload := group.Decrypt(key, expectedFp[:], publicMsg.GetPayload())
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
	if !sid.Cmp(senderID) {
		t.Errorf("Internal message has wrong sender ID."+
			"\nexpected: %s\nreceived: %s", senderID, sid)
	}
	if !bytes.Equal(internalMsg.GetPayload(), message) {
		t.Errorf("Internal message has wrong payload."+
			"\nexpected: %s\nreceived: %s", message, internalMsg.GetPayload())
	}
}

// randCycInt returns a random cyclic int.
func randCycInt(rng *rand.Rand) *cyclic.Int {
	return getGroup().NewInt(rng.Int63())
}

func getGroup() *cyclic.Group {
	return cyclic.NewGroup(
		large.NewIntFromString("E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D4941"+
			"3394C049B7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688"+
			"B55B3DD2AEDF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861"+
			"575E745D31F8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC"+
			"718DD2A3E041023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FF"+
			"B1BC51DADDF453B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBC"+
			"A23EAC5ACE92096EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD"+
			"161C7738F32BF29A841698978825B4111B4BC3E1E198455095958333D776D8B2B"+
			"EEED3A1A1A221A6E37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C"+
			"4F50D7D7803D2D4F278DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F"+
			"1390B5D3FEACAF1696015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F"+
			"96789C38E89D796138E6319BE62E35D87B1048CA28BE389B575E994DCA7554715"+
			"84A09EC723742DC35873847AEF49F66E43873", 16),
		large.NewIntFromString("2", 16))
}
