////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package storage

import (
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"testing"
)

// Show that all fields of a searched user record get stored
func TestSession_Contact(t *testing.T) {
	store := make(ekv.Memstore)
	session := &Session{kv: NewVersionedKV(store)}
	session.loadAllContacts()

	expectedRecord := &Contact{
		Id:        id.NewIdFromUInt(24601, id.User, t),
		PublicKey: []byte("not a real public key"),
	}

	name := "niamh@elixxir.io"
	err := session.SetContactByEmail(name, expectedRecord)
	if err != nil {
		t.Fatal(err)
	}
	retrievedRecord, err := session.GetContactByEmail(name)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedRecord, retrievedRecord) {
		t.Error("Expected and retrieved records were different")
	}
}
