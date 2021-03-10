///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package utility

import (
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/cyclic"
	"time"
)

const currentCyclicVersion = 0

func StoreCyclicKey(kv *versioned.KV, cy *cyclic.Int, key string) error {
	now := time.Now()

	data, err := cy.GobEncode()
	if err != nil {
		return err
	}

	obj := versioned.Object{
		Version:   currentCyclicVersion,
		Timestamp: now,
		Data:      data,
	}

	return kv.Set(key, currentCyclicVersion, &obj)
}

func LoadCyclicKey(kv *versioned.KV, key string) (*cyclic.Int, error) {
	vo, err := kv.Get(key, currentCyclicVersion)
	if err != nil {
		return nil, err
	}

	cy := &cyclic.Int{}

	return cy, cy.GobDecode(vo.Data)
}
