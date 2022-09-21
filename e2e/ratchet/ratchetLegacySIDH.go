////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package ratchet

import (
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/e2e/ratchet/partner"
	"gitlab.com/elixxir/client/e2e/ratchet/partner/session"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/primitives/id"
)

// AddPartner adds a partner. Automatically creates both send and receive
// sessions using the passed cryptographic data and per the parameters sent
func (r *Ratchet) AddPartnerLegacySIDH(partnerID *id.ID,
	partnerPubKey, myPrivKey *cyclic.Int, partnerSIDHPubKey *sidh.PublicKey,
	mySIDHPrivKey *sidh.PrivateKey, sendParams,
	receiveParams session.Params) (partner.ManagerLegacySIDH, error) {
	r.mux.Lock()
	defer r.mux.Unlock()

	myID := r.myID

	myPubKey := diffieHellman.GeneratePublicKey(myPrivKey, r.grp)
	jww.INFO.Printf("Adding Partner %s:\n\tMy Public Key: %s"+
		"\n\tPartner Public Key: %s to %s",
		partnerID,
		myPubKey.TextVerbose(16, 0),
		partnerPubKey.TextVerbose(16, 0), myID)

	mid := *partnerID

	if _, ok := r.managers[mid]; ok {
		return nil, errors.New("Cannot overwrite existing partner")
	}
	m := partner.NewManagerLegacySIDH(r.kv, r.myID, partnerID, myPrivKey,
		partnerPubKey, mySIDHPrivKey, partnerSIDHPubKey,
		sendParams, receiveParams, r.cyHandlerLegacySIDH, r.grp, r.rng)

	r.managersLegacySIDH[mid] = m
	if err := r.save(); err != nil {
		jww.FATAL.Printf("Failed to add Partner %s: Save of store failed: %s",
			partnerID, err)
	}

	// Add services for the manager
	r.add(m)

	return m, nil
}

// GetPartnerLegacySIDH returns the partner per its ID, if it exists
func (r *Ratchet) GetPartnerLegacySIDH(partnerID *id.ID) (partner.ManagerLegacySIDH, error) {
	r.mux.RLock()
	defer r.mux.RUnlock()

	m, ok := r.managersLegacySIDH[*partnerID]

	if !ok {
		jww.WARN.Printf("%s: %s", NoPartnerErrorStr, partnerID)
		return nil, errors.New(NoPartnerErrorStr)
	}

	return m, nil
}

// DeletePartner removes the associated contact from the E2E store
func (r *Ratchet) DeletePartnerLegacySIDH(partnerID *id.ID) error {
	m, ok := r.managersLegacySIDH[*partnerID]
	if !ok {
		jww.WARN.Printf("%s: %s", NoPartnerErrorStr, partnerID)
		return errors.New(NoPartnerErrorStr)
	}

	if err := m.Delete(); err != nil {
		return errors.WithMessagef(err,
			"Could not remove partner %s from store",
			partnerID)
	}

	// Delete services
	r.delete(m)

	delete(r.managersLegacySIDH, *partnerID)
	return r.save()

}

// GetAllPartnerIDs returns a list of all partner IDs that the user has
// an E2E relationship with.
func (r *Ratchet) GetAllPartnerIDsLegacySIDH() []*id.ID {
	r.mux.RLock()
	defer r.mux.RUnlock()

	partnerIDs := make([]*id.ID, 0, len(r.managersLegacySIDH))

	for _, m := range r.managersLegacySIDH {
		partnerIDs = append(partnerIDs, m.PartnerId())
	}

	return partnerIDs
}
