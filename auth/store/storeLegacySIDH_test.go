////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package store

import (
	"bytes"
	"io"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/cloudflare/circl/dh/sidh"

	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"

	sidhinterface "gitlab.com/elixxir/client/interfaces/sidh"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/e2e/auth"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/elixxir/primitives/format"

	util "gitlab.com/elixxir/client/storage/utility"
)

type mockLegacySIDHSentRequestHandler struct{}

func (msrh *mockLegacySIDHSentRequestHandler) AddLegacySIDH(sr SentRequestInterface) {}
func (msrh *mockLegacySIDHSentRequestHandler) Add(sr SentRequestInterface)           {}
func (msrh *mockLegacySIDHSentRequestHandler) Delete(sr SentRequestInterface)        {}

// Happy path.
func TestNewOrLoadStoreLegacySIDH(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	grp := cyclic.NewGroup(large.NewInt(173), large.NewInt(2))

	_, err := NewOrLoadStoreLegacySIDH(kv, grp, &mockLegacySIDHSentRequestHandler{})
	if err != nil {
		t.Errorf("NewStore() returned an error: %+v", err)
	}
}

// Happy path.
func TestLoadStoreLegacySIDH(t *testing.T) {
	rng := csprng.NewSystemRNG()

	// Create a random storage object + keys
	s, kv := makeTestStoreLegacySIDH(t)

	// Generate random contact information and add it to the store
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	_, sidhPubKey := genSidhAKeys(rng)
	r := makeTestRound(t)
	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	// Create a sent request object and add it to the store
	privSidh, pubSidh := genSidhAKeys(rng)
	var sr *SentRequestLegacySIDH
	var err error
	if sr, err = s.AddSentLegacySIDH(id.NewIdFromUInt(rand.Uint64(),
		id.User, t),
		s.grp.NewInt(5), s.grp.NewInt(6),
		s.grp.NewInt(7), privSidh, pubSidh,
		format.Fingerprint{42}, false); err != nil {
		t.Fatalf("AddSent() produced an error: %+v", err)
	}

	s.CheckIfNegotiationIsNew(
		sr.partner, auth.CreateNegotiationFingerprint(sr.myPrivKey,
			sidhPubKey))

	err = s.saveLegacySIDH()
	if err != nil {
		t.Errorf("Failed to save: %+v", err)
	}

	// Attempt to load the store
	store, err := NewOrLoadStoreLegacySIDH(kv, s.grp, &mockLegacySIDHSentRequestHandler{})
	if err != nil {
		t.Errorf("LoadStore() returned an error: %+v", err)
	}

	srLoaded, ok := store.storeLegacySIDH.sentByID[*sr.partner]
	if !ok {
		t.Fatal("Sent request could not be found")
	}

	if sr.myPrivKey == srLoaded.myPrivKey &&
		sr.mySidHPrivKeyA == srLoaded.mySidHPrivKeyA &&
		sr.mySidHPubKeyA == srLoaded.mySidHPubKeyA &&
		sr.fingerprint == srLoaded.fingerprint &&
		sr.partnerHistoricalPubKey == sr.partnerHistoricalPubKey {
		t.Errorf("GetReceivedRequest() returned incorrect send req."+
			"\n\texpected: %+v\n\treceived: %+v", sr, srLoaded)
	}

	if s.storeLegacySIDH.receivedByID[*c.ID] == nil {
		t.Errorf("AddSent() failed to add request to map for "+
			"partner ID %s.", c.ID)
	}
}

// Happy path: tests that the correct SentRequest is added to the map.
func TestStore_AddSentLegacySIDH(t *testing.T) {
	rng := csprng.NewSystemRNG()
	s, _ := makeTestStoreLegacySIDH(t)

	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)

	partner := id.NewIdFromUInt(rand.Uint64(), id.User, t)

	var sr *SentRequestLegacySIDH
	sr, err := s.AddSentLegacySIDH(partner, s.grp.NewInt(5), s.grp.NewInt(6),
		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
		format.Fingerprint{42}, false)
	if err != nil {
		t.Errorf("AddSent() produced an error: %+v", err)
	}

	if s.storeLegacySIDH.sentByID[*partner] == nil {
		t.Fatalf("AddSent() failed to add request to map for "+
			"partner ID %s.", partner)
	} else if !reflect.DeepEqual(sr, s.storeLegacySIDH.sentByID[*partner]) {
		t.Fatalf("AddSent() failed store the correct SentRequest."+
			"\n\texpected: %+v\n\treceived: %+v",
			sr, s.storeLegacySIDH.sentByID[*partner])
	}

	if _, exists := s.storeLegacySIDH.sentByID[*sr.partner]; !exists {
		t.Fatalf("AddSent() failed to add fingerprint to map for "+
			"fingerprint %s.", sr.fingerprint)
	} else if !reflect.DeepEqual(sr,
		s.storeLegacySIDH.sentByID[*sr.partner]) {
		t.Fatalf("AddSent() failed store the correct fingerprint."+
			"\n\texpected: %+v\n\treceived: %+v",
			sr, s.storeLegacySIDH.sentByID[*sr.partner])
	}
}

// // Error path: request with request already exists in map.
// func TestStore_AddSent_PartnerAlreadyExistsError(t *testing.T) {
// 	s, _ := makeTestStoreLegacySIDH(t)

// 	rng := csprng.NewSystemRNG()
// 	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)

// 	partner := id.NewIdFromUInt(rand.Uint64(), id.User, t)

// 	_, err := s.AddSent(partner, s.grp.NewInt(5), s.grp.NewInt(6),
// 		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
// 		format.Fingerprint{42}, true)
// 	if err != nil {
// 		t.Errorf("AddSent() produced an error: %+v", err)
// 	}

// 	_, err = s.AddSent(partner, s.grp.NewInt(5), s.grp.NewInt(6),
// 		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
// 		format.Fingerprint{42}, true)
// 	if err == nil {
// 		t.Errorf("AddSent() did not produce the expected error for " +
// 			"a request that already exists.")
// 	}
// }

// Happy path.
func TestStore_AddReceivedLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)

	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	r := makeTestRound(t)

	err := s.AddReceivedLegacySIDH(c, sidhPubKey, r)
	if err != nil {
		t.Errorf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}
	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*c.ID] == nil {
		t.Errorf("AddReceivedLegacySIDH() failed to add request to "+
			"map for partner ID %s.", c.ID)
	} else if !reflect.DeepEqual(r, legacy.receivedByID[*c.ID].round) {
		t.Errorf("AddReceivedLegacySIDH() failed store "+
			"the correct round."+
			"\n\texpected: %+v\n\treceived: %+v", r,
			legacy.receivedByID[*c.ID].round)
	}
}

// Error path: request with request already exists in map.
func TestStore_AddReceivedLegacySIDH_PartnerAlreadyExistsError(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}

	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	err := s.AddReceivedLegacySIDH(c, sidhPubKey, r)
	if err != nil {
		t.Errorf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	err = s.AddReceivedLegacySIDH(c, sidhPubKey, r)
	if err == nil {
		t.Errorf("AddReceivedLegacySIDH() did not produce the expected error " +
			"for a request that already exists.")
	}
}

// Happy path.
func TestStore_GetReceivedRequestLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	testC, err := s.GetReceivedRequestLegacySIDH(c.ID)
	if err != nil {
		t.Errorf("GetReceivedRequest() returned an error: %+v", err)
	}

	if !reflect.DeepEqual(c, testC) {
		t.Errorf("GetReceivedRequest() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", c, testC)
	}

	keyBytes := make([]byte, sidhinterface.PubKeyByteSize)
	sidhPubKey.Export(keyBytes)
	expKeyBytes := make([]byte, sidhinterface.PubKeyByteSize)
	legacy := s.storeLegacySIDH
	legacy.receivedByID[*c.ID].theirSidHPubKeyA.Export(expKeyBytes)
	if !reflect.DeepEqual(keyBytes, expKeyBytes) {
		t.Errorf("GetReceivedRequest did not send proper sidh bytes")
	}
}

// Error path: request is deleted between first and second check.
func TestStore_GetReceivedRequest_RequestDeletedLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}
	legacy := s.storeLegacySIDH

	rr := legacy.receivedByID[*c.ID]
	rr.mux.Lock()

	delete(legacy.receivedByID, *c.ID)
	rr.mux.Unlock()

	testC, err := s.GetReceivedRequest(c.ID)
	if err == nil {
		t.Errorf("GetReceivedRequest() did not return an error " +
			"when the request should not exist.")
	}

	if !reflect.DeepEqual(contact.Contact{}, testC) {
		t.Errorf("GetReceivedRequest() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
			testC)
	}

	// Check if the request's mutex is locked
	if reflect.ValueOf(&rr.mux).Elem().FieldByName("state").Int() != 0 {
		t.Errorf("GetReceivedRequest() did not unlock mutex.")
	}
}

// Error path: request does not exist.
func TestStore_GetReceivedRequest_RequestNotInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)

	testC, err := s.GetReceivedRequest(
		id.NewIdFromUInt(rand.Uint64(),
			id.User, t))
	if err == nil {
		t.Errorf("GetReceivedRequest() did not return an error " +
			"when the request should not exist.")
	}

	if !reflect.DeepEqual(contact.Contact{}, testC) {
		t.Errorf("GetReceivedRequest() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
			testC)
	}
}

// Happy path.
func TestStore_GetReceivedRequestDataLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	testC, err := s.GetReceivedRequestLegacySIDH(c.ID)
	if err != nil {
		t.Errorf("GetReceivedRequestData() returned an error: %+v", err)
	}

	if !reflect.DeepEqual(c, testC) {
		t.Errorf("GetReceivedRequestData() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", c, testC)
	}
}

// Error path: request does not exist.
func TestStore_GetReceivedRequestData_RequestNotInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)

	testC, err := s.GetReceivedRequest(id.NewIdFromUInt(
		rand.Uint64(),
		id.User, t))
	if err == nil {
		t.Errorf("GetReceivedRequestData() did not return an error " +
			"when the request should not exist.")
	}

	if !reflect.DeepEqual(contact.Contact{}, testC) {
		t.Errorf("GetReceivedRequestData() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
			testC)
	}
}

// Happy path: request is of type Receive.
func TestStore_GetRequest_ReceiveRequestLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	con, err := s.GetReceivedRequestLegacySIDH(c.ID)
	if err != nil {
		t.Errorf("GetRequest() returned an error: %+v", err)
	}
	if !reflect.DeepEqual(c, con) {
		t.Errorf("GetRequest() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", c, con)
	}
}

// // Happy path: request is of type Sent.

// func TestStore_GetRequest_SentRequest(t *testing.T) {
// 	s, _ := makeTestStoreLegacySIDH(t)
// 	partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
// 	rng := csprng.NewSystemRNG()
// 	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)

// 	var sr *SentRequestLegacySIDH
// 	var err error
// 	if sr, err = s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5), s.grp.NewInt(6),
// 		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
// 		format.Fingerprint{42}, false); err != nil {
// 		t.Fatalf("AddSent() returned an error: %+v", err)
// 	}

// 	rType, request, con, err := s.GetRequest(sr.partner)
// 	if err != nil {
// 		t.Errorf("GetRequest() returned an error: %+v", err)
// 	}
// 	if rType != Sent {
// 		t.Errorf("GetRequest() returned incorrect RequestType."+
// 			"\n\texpected: %d\n\treceived: %d", Sent, rType)
// 	}
// 	if !reflect.DeepEqual(sr, request) {
// 		t.Errorf("GetRequest() returned incorrect SentRequest."+
// 			"\n\texpected: %+v\n\treceived: %+v", sr, request)
// 	}
// 	if !reflect.DeepEqual(contact.Contact{}, con) {
// 		t.Errorf("GetRequest() returned incorrect Contact."+
// 			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
// 			con)
// 	}
// }

// Error path: request type is invalid.
// func TestStore_GetRequest_InvalidType(t *testing.T) {
// 	s, _, _ := makeTestStoreLegacySIDH(t)
// 	uid := id.NewIdFromUInt(rand.Uint64(), id.User, t)
// 	s.receivedByIDLegacySIDH[*uid] = &ReceivedRequest{rt: 42}

// 	rType, request, con, err := s.GetRequest(uid)
// 	if err == nil {
// 		t.Errorf("GetRequest() did not return an error " +
// 			"when the request type should be invalid.")
// 	}
// 	if rType != 0 {
// 		t.Errorf("GetRequest() returned incorrect RequestType."+
// 			"\n\texpected: %d\n\treceived: %d", 0, rType)
// 	}
// 	if request != nil {
// 		t.Errorf("GetRequest() returned incorrect SentRequest."+
// 			"\n\texpected: %+v\n\treceived: %+v", nil, request)
// 	}
// 	if !reflect.DeepEqual(contact.Contact{}, con) {
// 		t.Errorf("GetRequest() returned incorrect Contact."+
// 			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
// 			con)
// 	}
// }

// Error path: request does not exist in map.
func TestStore_GetRequest_RequestNotInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	uid := id.NewIdFromUInt(rand.Uint64(), id.User, t)

	con, err := s.GetReceivedRequest(uid)
	if err == nil {
		t.Errorf("GetRequest() did not return an error " +
			"when the request was not in the map.")
	}
	if !reflect.DeepEqual(contact.Contact{}, con) {
		t.Errorf("GetRequest() returned incorrect Contact."+
			"\n\texpected: %+v\n\treceived: %+v", contact.Contact{},
			con)
	}
}

// Happy path.
//func TestStore_Fail(t *testing.T) {
//	s, _ := makeTestStoreLegacySIDH(t)
//	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
//	rng := csprng.NewSystemRNG()
//	_, sidhPubKey := genSidhAKeys(rng)
//
//  r := makeTestRound()
//
//	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
//		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
//	}
//	if _, err := s.GetReceivedRequest(c.ID); err != nil {
//		t.Fatalf("GetReceivedRequest() returned an error: %+v", err)
//	}
//
//	defer func() {
//		if r := recover(); r != nil {
//			t.Errorf("The code did not panic")
//		}
//	}()
//
//	s.Done(c.ID)
//
//	// Check if the request's mutex is locked
//	if reflect.ValueOf(&s.receivedByIDLegacySIDH[*c.ID].mux).Elem().FieldByName(
//		"state").Int() != 0 {
//		t.Errorf("Done() did not unlock mutex.")
//	}
//}

// Error path: request does not exist.
//func TestStore_Fail_RequestNotInMap(t *testing.T) {
//	s,, _ := makeTestStoreLegacySIDH(t)
//
//	defer func() {
//		if r := recover(); r == nil {
//			t.Errorf("Done() did not panic when the " +
//				"request is not in map.")
//		}
//	}()
//
//	s.Done(id.NewIdFromUInt(rand.Uint64(), id.User, t))
//}

// Happy path: partner request.
func TestStore_Delete_ReceiveRequestLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}
	if _, err := s.GetReceivedRequestLegacySIDH(c.ID); err != nil {
		t.Fatalf("GetReceivedRequest() returned an error: %+v", err)
	}

	err := s.DeleteRequestLegacySIDH(c.ID)
	if err != nil {
		t.Errorf("delete() returned an error: %+v", err)
	}
	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*c.ID] != nil {
		t.Errorf("delete() failed to delete request for user %s.", c.ID)
	}
}

// Happy path: sent request.
func TestStore_Delete_SentRequestLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
	rng := csprng.NewSystemRNG()
	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
	sr := &SentRequestLegacySIDH{
		kv:                      s.kv,
		partner:                 partnerID,
		partnerHistoricalPubKey: s.grp.NewInt(1),
		myPrivKey:               s.grp.NewInt(2),
		myPubKey:                s.grp.NewInt(3),
		mySidHPrivKeyA:          sidhPrivKey,
		mySidHPubKeyA:           sidhPubKey,
		fingerprint:             format.Fingerprint{5},
	}
	if _, err := s.AddSentLegacySIDH(sr.partner, s.grp.NewInt(5),
		s.grp.NewInt(6),
		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
		format.Fingerprint{42}, false); err != nil {
		t.Fatalf("AddSent() returned an error: %+v", err)
	}

	//if _, _, _, err := s.GetFingerprint(sr.fingerprint); err != nil {  // TODO legacy
	//	t.Fatalf("GetFingerprint() returned an error: %+v", err)
	//}

	err := s.DeleteRequestLegacySIDH(sr.partner)
	if err != nil {
		t.Errorf("delete() returned an error: %+v", err)
	}

	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*sr.partner] != nil {
		t.Errorf("delete() failed to delete request for user %s.",
			sr.partner)
	}

	if _, exists := legacy.sentByID[*sr.partner]; exists {
		t.Errorf("delete() failed to delete fingerprint for fp %v.",
			sr.fingerprint)
	}
}

// Error path: request does not exist.
func TestStore_Delete_RequestNotInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)

	err := s.DeleteRequestLegacySIDH(id.NewIdFromUInt(rand.Uint64(), id.User, t))
	if err == nil {
		t.Errorf("delete() did not return an error when the request " +
			"was not in the map.")
	}
}

// Unit test of Store.GetAllReceived.
func TestStore_GetAllReceivedLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	numReceived := 10

	expectContactList := make([]contact.Contact, 0, numReceived)
	// Add multiple received contact receivedByID
	for i := 0; i < numReceived; i++ {
		c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
		rng := csprng.NewSystemRNG()
		_, sidhPubKey := genSidhAKeys(rng)

		r := makeTestRound(t)

		if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
			t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
		}

		expectContactList = append(expectContactList, c)
	}

	// Check that GetAllReceived returns all contacts
	receivedRequestList := s.GetAllReceivedRequestsLegacySIDH()
	var receivedContactList = make([]contact.Contact, len(receivedRequestList))
	for i, req := range receivedRequestList {
		receivedContactList[i] = req.GetContact()
	}

	if len(receivedContactList) != numReceived {
		t.Errorf("GetAllReceived did not return expected amount of contacts."+
			"\nExpected: %d"+
			"\nReceived: %d", numReceived, len(receivedContactList))
	}

	// Sort expected and received lists so that they are in the same order
	// since extraction from a map does not maintain order
	sort.Slice(expectContactList, func(i, j int) bool {
		return bytes.Compare(expectContactList[i].ID.Bytes(), expectContactList[j].ID.Bytes()) == -1
	})
	sort.Slice(receivedContactList, func(i, j int) bool {
		return bytes.Compare(receivedContactList[i].ID.Bytes(), receivedContactList[j].ID.Bytes()) == -1
	})

	// Check validity of contacts
	if !reflect.DeepEqual(expectContactList, receivedContactList) {
		t.Errorf("GetAllReceived did not return expected contact list."+
			"\nExpected: %+v"+
			"\nReceived: %+v", expectContactList, receivedContactList)
	}

}

// Tests that Store.GetAllReceived returns an empty list when there are no
// received receivedByID.
func TestStore_GetAllReceived_EmptyListLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)

	// Check that GetAllReceived returns all contacts
	receivedContactList := s.GetAllReceivedRequests()
	if len(receivedContactList) != 0 {
		t.Errorf("GetAllReceived did not return expected amount of contacts."+
			"\nExpected: %d"+
			"\nReceived: %d", 0, len(receivedContactList))
	}

	// Add Sent and Receive receivedByID
	for i := 0; i < 10; i++ {
		partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
		rng := csprng.NewSystemRNG()
		sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
		if _, err := s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5),
			s.grp.NewInt(6),
			s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
			format.Fingerprint{42}, false); err != nil {
			t.Fatalf("AddSent() returned an error: %+v", err)
		}
	}

	// Check that GetAllReceived returns all contacts
	receivedContactList = s.GetAllReceivedRequests()
	if len(receivedContactList) != 0 {
		t.Errorf("GetAllReceived did not return expected amount "+
			"of contacts. It may be pulling from Sent Requests."+
			"\nExpected: %d"+
			"\nReceived: %d", 0, len(receivedContactList))
	}

}

// Tests that Store.GetAllReceived returns only Sent receivedByID when there
// are both Sent and Receive receivedByID in Store.
func TestStore_GetAllReceived_MixSentReceivedLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	numReceived := 10

	// Add multiple received contact receivedByID
	for i := 0; i < numReceived; i++ {
		// Add received request
		c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
		rng := csprng.NewSystemRNG()
		_, sidhPubKey := genSidhAKeys(rng)

		r := makeTestRound(t)

		if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
			t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
		}

		// Add sent request
		partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
		sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
		if _, err := s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5),
			s.grp.NewInt(6),
			s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
			format.Fingerprint{42}, false); err != nil {
			t.Fatalf("AddSent() returned an error: %+v", err)
		}
	}

	// Check that GetAllReceived returns all contacts
	receivedContactList := s.GetAllReceivedRequestsLegacySIDH()
	if len(receivedContactList) != numReceived {
		t.Errorf("GetAllReceived did not return expected amount of contacts. "+
			"It may be pulling from Sent Requests."+
			"\nExpected: %d"+
			"\nReceived: %d", numReceived, len(receivedContactList))
	}

}

// Error case: Call DeleteRequest on a request that does
// not exist.
func TestStore_DeleteRequest_NonexistantRequestLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}
	if _, err := s.GetReceivedRequestLegacySIDH(c.ID); err != nil {
		t.Fatalf("GetReceivedRequest() returned an error: %+v", err)
	}

	err := s.DeleteRequestLegacySIDH(c.ID)
	if err != nil {
		t.Errorf("DeleteRequest should return an error " +
			"when trying to delete a partner request")
	}

}

// Unit test.
func TestStore_DeleteReceiveRequestsLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}
	if _, err := s.GetReceivedRequestLegacySIDH(c.ID); err != nil {
		t.Fatalf("GetReceivedRequest() returned an error: %+v", err)
	}

	err := s.DeleteReceiveRequestsLegacySIDH()
	if err != nil {
		t.Fatalf("DeleteReceiveRequests returned an error: %+v", err)
	}

	legacy := s.storeLegacySIDH
	if legacy.receivedByID[*c.ID] != nil {
		t.Errorf("delete() failed to delete request for user %s.", c.ID)
	}
}

// Unit test.
func TestStore_DeleteSentRequestsLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
	rng := csprng.NewSystemRNG()
	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
	var sr *SentRequestLegacySIDH
	var err error
	if sr, err = s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5),
		s.grp.NewInt(6),
		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
		format.Fingerprint{42}, false); err != nil {
		t.Fatalf("AddSent() returned an error: %+v", err)
	}

	err = s.DeleteSentRequestsLegacySIDH()
	if err != nil {
		t.Fatalf("DeleteSentRequests returned an error: %+v", err)
	}
	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*sr.partner] != nil {
		t.Errorf("delete() failed to delete request for user %s.",
			sr.partner)
	}

	if _, exists := s.sentByID[*sr.partner]; exists {
		t.Errorf("delete() failed to delete fingerprint for fp %v.",
			sr.fingerprint)
	}
}

// Tests that DeleteSentRequests does not affect partner receivedByID in map
func TestStore_DeleteSentRequests_ReceiveInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	rng := csprng.NewSystemRNG()
	_, sidhPubKey := genSidhAKeys(rng)

	r := makeTestRound(t)

	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	err := s.DeleteSentRequestsLegacySIDH()
	if err != nil {
		t.Fatalf("DeleteSentRequests returned an error: %+v", err)
	}

	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*c.ID] == nil {
		t.Fatalf("DeleteSentRequests removes partner receivedByID!")
	}

}

// Tests that DeleteReceiveRequests does not affect sentByID in map
func TestStore_DeleteReceiveRequests_SentInMapLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
	rng := csprng.NewSystemRNG()
	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
	var err error
	if _, err = s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5),
		s.grp.NewInt(6),
		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
		format.Fingerprint{42}, false); err != nil {
		t.Fatalf("AddSent() returned an error: %+v", err)
	}

	err = s.DeleteReceiveRequestsLegacySIDH()
	if err != nil {
		t.Fatalf("DeleteSentRequests returned an error: %+v", err)
	}

	if s.storeLegacySIDH.sentByID[*partnerID] == nil {
		t.Fatalf("DeleteReceiveRequests removes sent receivedByID!")
	}

}

// Unit test.
func TestStore_DeleteAllRequestsLegacySIDH(t *testing.T) {
	s, _ := makeTestStoreLegacySIDH(t)
	partnerID := id.NewIdFromUInt(rand.Uint64(), id.User, t)
	rng := csprng.NewSystemRNG()
	sidhPrivKey, sidhPubKey := genSidhAKeys(rng)
	var sr *SentRequestLegacySIDH
	var err error
	if sr, err = s.AddSentLegacySIDH(partnerID, s.grp.NewInt(5),
		s.grp.NewInt(6),
		s.grp.NewInt(7), sidhPrivKey, sidhPubKey,
		format.Fingerprint{42}, false); err != nil {
		t.Fatalf("AddSent() returned an error: %+v", err)
	}

	c := contact.Contact{ID: id.NewIdFromUInt(rand.Uint64(), id.User, t)}
	_, sidhPubKey = genSidhAKeys(rng)
	r := makeTestRound(t)
	if err := s.AddReceivedLegacySIDH(c, sidhPubKey, r); err != nil {
		t.Fatalf("AddReceivedLegacySIDH() returned an error: %+v", err)
	}

	err = s.DeleteAllRequestsLegacySIDH()
	if err != nil {
		t.Fatalf("DeleteAllRequests returned an error: %+v", err)
	}

	legacy := s.storeLegacySIDH

	if legacy.receivedByID[*sr.partner] != nil {
		t.Errorf("delete() failed to delete request for user %s.",
			sr.partner)
	}

	if _, exists := legacy.sentByID[*sr.partner]; exists {
		t.Errorf("delete() failed to delete fingerprint for fp %v.",
			sr.fingerprint)
	}

	if legacy.receivedByID[*c.ID] != nil {
		t.Errorf("delete() failed to delete request for user %s.", c.ID)
	}

}

func makeTestStoreLegacySIDH(t *testing.T) (*Store, *versioned.KV) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	grp := cyclic.NewGroup(large.NewInt(173), large.NewInt(0))

	store, err := NewOrLoadStoreLegacySIDH(kv, grp, &mockLegacySIDHSentRequestHandler{})
	if err != nil {
		t.Fatalf("Failed to create new Store: %+v", err)
	}

	return store, kv
}

func genSidhAKeys(rng io.Reader) (*sidh.PrivateKey, *sidh.PublicKey) {
	sidHPrivKeyA := util.NewSIDHPrivateKey(sidh.KeyVariantSidhA)
	sidHPubKeyA := util.NewSIDHPublicKey(sidh.KeyVariantSidhA)

	if err := sidHPrivKeyA.Generate(rng); err != nil {
		panic("failure to generate SidH A private key")
	}
	sidHPrivKeyA.GeneratePublicKey(sidHPubKeyA)

	return sidHPrivKeyA, sidHPubKeyA
}

func genSidhBKeys(rng io.Reader) (*sidh.PrivateKey, *sidh.PublicKey) {
	sidHPrivKeyB := util.NewSIDHPrivateKey(sidh.KeyVariantSidhB)
	sidHPubKeyB := util.NewSIDHPublicKey(sidh.KeyVariantSidhB)

	if err := sidHPrivKeyB.Generate(rng); err != nil {
		panic("failure to generate SidH A private key")
	}
	sidHPrivKeyB.GeneratePublicKey(sidHPubKeyB)

	return sidHPrivKeyB, sidHPubKeyB
}