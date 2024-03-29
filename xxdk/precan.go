////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package xxdk

import (
	"encoding/binary"
	"math/rand"

	"github.com/cloudflare/circl/dh/sidh"
	"gitlab.com/elixxir/client/v4/e2e/ratchet/partner/session"
	util "gitlab.com/elixxir/client/v4/storage/utility"
	"gitlab.com/elixxir/crypto/contact"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/storage"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/xx_network/crypto/csprng"
)

// NewPrecannedCmix creates an insecure user with predetermined keys with
// nodes. It creates client storage, generates keys, connects, and registers
// with the network. Note that this does not register a username/identity, but
// merely creates a new cryptographic identity for adding such information at a
// later date.
func NewPrecannedCmix(precannedID uint, defJSON, storageDir string,
	password []byte) error {
	jww.INFO.Printf("NewPrecannedCmix()")
	rngStreamGen := fastRNG.NewStreamGenerator(12, 1024,
		csprng.NewSystemRNG)
	rngStream := rngStreamGen.GetStream()
	defer rngStream.Close()

	def, err := ParseNDF(defJSON)
	if err != nil {
		return err
	}
	cmixGrp, e2eGrp := DecodeGroups(def)

	kv, err := LocalKV(storageDir, password, rngStreamGen)
	if err != nil {
		return err
	}

	userInfo := createPrecannedUser(precannedID, rngStream, e2eGrp)
	store, err := CheckVersionAndSetupStorage(def, kv,
		userInfo, cmixGrp, e2eGrp, "", rngStreamGen)
	if err != nil {
		return err
	}

	// Mark the precanned user as finished with permissioning and registered
	// with the network.
	err = store.ForwardRegistrationStatus(storage.PermissioningComplete)
	if err != nil {
		return err
	}

	return err
}

// MakePrecannedAuthenticatedChannel creates an insecure E2E relationship with a
// precanned user.
func (m *E2e) MakePrecannedAuthenticatedChannel(precannedID uint) (
	contact.Contact, error) {

	rng := m.GetRng().GetStream()
	precanUserInfo := createPrecannedUser(precannedID, rng, m.GetStorage().GetE2EGroup())
	rng.Close()
	precanRecipient, err := buildReceptionIdentity(precanUserInfo.ReceptionID,
		precanUserInfo.ReceptionSalt, precanUserInfo.ReceptionRSA,
		m.GetStorage().GetE2EGroup(), precanUserInfo.E2eDhPrivateKey)
	if err != nil {
		return contact.Contact{}, err
	}
	precanContact := precanRecipient.GetContact()

	myID := binary.BigEndian.Uint64(m.GetReceptionIdentity().ID[:])
	// Pick a variant based on if their ID is bigger than mine.
	myVariant := sidh.KeyVariantSidhA
	theirVariant := sidh.KeyVariant(sidh.KeyVariantSidhB)
	if myID > uint64(precannedID) {
		myVariant = sidh.KeyVariantSidhB
		theirVariant = sidh.KeyVariantSidhA
	}
	prng1 := rand.New(rand.NewSource(int64(precannedID)))
	theirSIDHPrivKey := util.NewSIDHPrivateKey(theirVariant)
	theirSIDHPubKey := util.NewSIDHPublicKey(theirVariant)
	err = theirSIDHPrivKey.Generate(prng1)
	if err != nil {
		return contact.Contact{}, err
	}
	theirSIDHPrivKey.GeneratePublicKey(theirSIDHPubKey)

	prng2 := rand.New(rand.NewSource(int64(myID)))
	mySIDHPrivKey := util.NewSIDHPrivateKey(myVariant)
	mySIDHPubKey := util.NewSIDHPublicKey(myVariant)
	err = mySIDHPrivKey.Generate(prng2)
	if err != nil {
		return contact.Contact{}, err
	}
	mySIDHPrivKey.GeneratePublicKey(mySIDHPubKey)

	// Add the precanned user as a e2e contact
	// FIXME: these params need to be threaded through...
	sesParam := session.GetDefaultParams()
	_, err = m.e2e.AddPartner(precanContact.ID, precanContact.DhPubKey,
		m.e2e.GetHistoricalDHPrivkey(), theirSIDHPubKey,
		mySIDHPrivKey, sesParam, sesParam)

	// Check garbled messages in case any messages arrived before creating
	// the channel
	m.GetCmix().CheckInProgressMessages()

	return precanContact, err
}
