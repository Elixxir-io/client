////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"gitlab.com/privategrity/client/globals"
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/format"
	"gitlab.com/privategrity/crypto/forward"
	"strconv"
	"testing"
	"gitlab.com/privategrity/client/parse"
)

func TestRegistrationGob(t *testing.T) {
	// Put some user data into a gob
	globals.InitStorage(&globals.RamStorage{}, "")

	huid, _ := strconv.ParseUint("be50nhqpqjtjj", 32, 64)

	// populate a gob in the store
	Register(huid, gwAddress, 1)

	// get the gob out of there again
	sessionGob := globals.LocalStorage.Load()
	var sessionBytes bytes.Buffer
	sessionBytes.Write(sessionGob)
	dec := gob.NewDecoder(&sessionBytes)
	Session = globals.SessionObj{}
	dec.Decode(&Session)

	VerifyRegisterGobAddress(t)
	VerifyRegisterGobKeys(t)
	VerifyRegisterGobUserID(t)
}

func VerifyRegisterGobAddress(t *testing.T) {

	if Session.GetGWAddress() != gwAddress {
		t.Errorf("GetNodeAddress() returned %v, expected %v",
			Session.GetGWAddress(), gwAddress)
	}
}

func VerifyRegisterGobUserID(t *testing.T) {
	if Session.GetCurrentUser().UserID != 5 {
		t.Errorf("User's ID was %v, expected %v",
			Session.GetCurrentUser().UserID, 5)
	}
}

func VerifyRegisterGobKeys(t *testing.T) {
	if Session.GetKeys()[0].PublicKey.Cmp(cyclic.NewInt(0)) != 0 {
		t.Errorf("Public key was %v, expected %v",
			Session.GetKeys()[0].PublicKey.Text(16), "0")
	}
	h := sha256.New()
	h.Write([]byte(string(30000 + Session.GetCurrentUser().UserID)))
	expectedTransmissionRecursiveKey := cyclic.NewIntFromBytes(h.Sum(nil))
	if Session.GetKeys()[0].TransmissionKeys.Recursive.Cmp(
		expectedTransmissionRecursiveKey) != 0 {
		t.Errorf("Transmission recursive key was %v, expected %v",
			Session.GetKeys()[0].TransmissionKeys.Recursive.Text(16),
			expectedTransmissionRecursiveKey.Text(16))
	}
	h = sha256.New()
	h.Write([]byte(string(20000 + Session.GetCurrentUser().UserID)))
	expectedTransmissionBaseKey := cyclic.NewIntFromBytes(h.Sum(nil))
	if Session.GetKeys()[0].TransmissionKeys.Base.Cmp(
		expectedTransmissionBaseKey) != 0 {
		t.Errorf("Transmission base key was %v, expected %v",
			Session.GetKeys()[0].TransmissionKeys.Base.Text(16),
			expectedTransmissionBaseKey.Text(16))
	}
	h = sha256.New()
	h.Write([]byte(string(50000 + Session.GetCurrentUser().UserID)))
	expectedReceptionRecursiveKey := cyclic.NewIntFromBytes(h.Sum(nil))
	if Session.GetKeys()[0].ReceptionKeys.Recursive.Cmp(
		expectedReceptionRecursiveKey) != 0 {
		t.Errorf("Reception recursive key was %v, expected %v",
			Session.GetKeys()[0].ReceptionKeys.Recursive.Text(16),
			expectedReceptionRecursiveKey.Text(16))
	}
	h = sha256.New()
	h.Write([]byte(string(40000 + Session.GetCurrentUser().UserID)))
	expectedReceptionBaseKey := cyclic.NewIntFromBytes(h.Sum(nil))
	if Session.GetKeys()[0].ReceptionKeys.Base.Cmp(
		expectedReceptionBaseKey) != 0 {
		t.Errorf("Reception base key was %v, expected %v",
			Session.GetKeys()[0].ReceptionKeys.Base.Text(16),
			expectedReceptionBaseKey.Text(16))
	}

	if Session.GetKeys()[0].ReturnKeys.Recursive == nil {
		t.Logf("warning: return recursive key is nil")
	} else {
		t.Logf("return recursive key is not nil. " +
			"update gob test to ensure that it's serialized to storage, " +
			"if needed")
	}
	if Session.GetKeys()[0].ReturnKeys.Base == nil {
		t.Logf("warning: return base key is nil")
	} else {
		t.Logf("return base key is not nil. " +
			"update gob test to ensure that it's serialized to storage, " +
			"if needed")
	}
	if Session.GetKeys()[0].ReceiptKeys.Recursive == nil {
		t.Logf("warning: receipt recursive key is nil")
	} else {
		t.Logf("receipt recursive key is not nil. " +
			"update gob test to ensure that it's serialized to storage, " +
			"if needed")
	}
	if Session.GetKeys()[0].ReceiptKeys.Base == nil {
		t.Logf("warning: receipt recursive key is nil")
	} else {
		t.Logf("receipt base key is not nil. " +
			"update gob test to ensure that it's serialized to storage, " +
			"if needed")
	}
}

// Function to test if Api/client DisableRatchet() works
// calls generateSharedKey and sees if that function reacts accordingly
// since it has a specific return for when the Ratchet is off
func TestDisableRatchet(t *testing.T) {

	prime := cyclic.NewIntFromString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
			"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"+
			"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"+
			"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"+
			"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"+
			"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"+
			"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"+
			"FFFFFFFFFFFFFFFF", 16)

	tests := 1
	pass := 0

	g := cyclic.NewGroup(prime, cyclic.NewInt(55), cyclic.NewInt(33),
		cyclic.NewRandom(cyclic.NewInt(2), cyclic.NewInt(1000)))

	// 65536 bits for the long key
	outSharedKeyStorage := make([]byte, 0, 8192)

	recursiveKeys := cyclic.NewIntFromString("ef9ab83927cd2349f98b1237889909002b897231ae9c927d1792ea0879287ea3",
		16)

	outSharedKey := cyclic.NewMaxInt()

	baseKey := cyclic.NewIntFromString("da9f8137821987b978164932015c105263ae769310269b510937c190768e2930",
		16)

	DisableRatchet()

	// If Ratchet is Disabled, then the return of Generate() needs to be equal to outSharedKey
	if forward.GenerateSharedKey(&g, baseKey, recursiveKeys, outSharedKey, outSharedKeyStorage) != outSharedKey {
		t.Errorf("GenerateSharedKey() did not run properly with ratchet set to false")
	} else {
		pass++
	}

	println("API disable ratchet test", pass, "out of", tests, "tests passed.")
}

// TODO remove this with TryReceive
func TestTryReceive(t *testing.T) {
	listenCh = make(chan *format.Message, 10)

	huid, _ := strconv.ParseUint("be50nhqpqjtjj", 32, 64)

	Register(huid, gwAddress, 1)
	expectEmpty, err := TryReceive()
	if expectEmpty.GetPayload() != "" || err != nil {
		t.Errorf("Expected empty message, but got %s", expectEmpty.GetPayload())
	}
	body := parse.Pack(&parse.TypedBody{
		BodyType: 1, // normal text message
		Body:     []byte("Hello"),
	})
	m, _ := format.NewMessage(13, 1, string(body))
	listenCh <- &m[0]
	something, err := TryReceive()
	if err != nil {
		t.Errorf("Got error when expecting message: %s", err.Error())
	}
	if something.GetPayload() != "Hello" {
		t.Errorf("Did not get expected message, got %s", something.GetPayload())
	}
}
