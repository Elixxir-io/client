///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package utility

import (
	"fmt"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
)

const currentContactVersion = 0

func StoreContact(kv *versioned.KV, c contact.Contact) error {
	now := netTime.Now()

	obj := versioned.Object{
		Version:   currentContactVersion,
		Timestamp: now,
		Data:      c.Marshal(),
	}

	return kv.Set(makeContactKey(c.ID), currentContactVersion, &obj)
}

func LoadContact(kv *versioned.KV, cid *id.ID) (contact.Contact, error) {
	vo, err := kv.Get(makeContactKey(cid), currentContactVersion)
	if err != nil {
		return contact.Contact{}, err
	}

	return contact.Unmarshal(vo.Data)
}

func DeleteContact(kv *versioned.KV, cid *id.ID) error {
	return kv.Delete(makeContactKey(cid), currentContactVersion)
}

func makeContactKey(cid *id.ID) string {
	return fmt.Sprintf("Contact:%s", cid)
}
