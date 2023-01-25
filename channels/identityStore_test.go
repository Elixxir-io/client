////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"bytes"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

func TestStoreLoadIdentity(t *testing.T) {
	rng := &csprng.SystemRNG{}
	privIdentity, err := cryptoChannel.GenerateIdentity(rng)
	if err != nil {
		t.Fatalf("GenerateIdentity error: %+v", err)
	}

	kv := versioned.NewKV(ekv.MakeMemstore())
	err = storeIdentity(kv, privIdentity)
	if err != nil {
		t.Fatalf("storeIdentity error: %+v", err)
	}

	loadedIdentity, err := loadIdentity(kv)
	if err != nil {
		t.Fatalf("loadIdentity error: %+v", err)
	}

	if !bytes.Equal(loadedIdentity.Marshal(), privIdentity.Marshal()) {
		t.Fatalf("Failed to load private identity.\nexpected: %x\nreceived: %x",
			privIdentity.Marshal(), loadedIdentity.Marshal())
	}
}
