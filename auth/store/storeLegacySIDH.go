////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package store

import (
	"encoding/json"

	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"

	"gitlab.com/elixxir/client/cmix/rounds"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

// These are the legacy SIDH elements and functions
type storeLegacySIDH struct {
	receivedByID map[id.ID]*ReceivedRequestLegacySIDH
	sentByID     map[id.ID]*SentRequestLegacySIDH
}

// NewOrLoadStore loads an extant new store. All passed in private
// keys are added as sentByFingerprints so they can be used to trigger
// receivedByID.  If no store can be found, it creates a new one
func NewOrLoadStoreLegacySIDH(kv *versioned.KV, grp *cyclic.Group,
	srh SentRequestHandler) (*Store, error) {
	kv = kv.Prefix(storePrefix)

	s := newStore(kv, grp, srh)

	var requestList []requestDisk

	//load all receivedByID
	sentObj, err := kv.Get(requestMapKey, requestMapVersion)
	if err != nil {
		//no store can be found, lets make a new one
		jww.WARN.Printf("No auth store found, making a new one")
		s := newStore(kv, grp, srh)
		return s, s.save()
	}

	if err := json.Unmarshal(sentObj.Data, &requestList); err != nil {
		return nil, errors.WithMessagef(err, "Failed to "+
			"unmarshal SentRequestMap")
	}

	jww.TRACE.Printf("%d found when loading AuthStore, prefix %s",
		len(requestList), kv.GetPrefix())

	for _, rDisk := range requestList {

		requestType := RequestType(rDisk.T)

		partner, err := id.Unmarshal(rDisk.ID)
		if err != nil {
			jww.FATAL.Panicf("Failed to load stored id: %+v", err)
		}

		// FIXME: This will need to handle legacy and current
		// sent requests/received requests. I recommend we drop
		// this coding pattern entirely in favor of something that
		// will upgrade more cleanly but we can ignore that for
		// PoC purposes.
		switch requestType {
		case Sent:
			sr, err := loadSentRequestLegacySIDH(kv, partner, grp)
			if err != nil {
				jww.FATAL.Panicf("Failed to load stored sentRequest: %+v", err)
			}

			s.storeLegacySIDH.sentByID[*sr.GetPartner()] = sr
			s.srh.AddLegacySIDH(sr)
		case Receive:
			rr, err := loadReceivedRequestLegacySIDH(kv, partner)
			if err != nil {
				jww.FATAL.Panicf("Failed to load stored receivedRequest: %+v", err)
			}

			s.storeLegacySIDH.receivedByID[*rr.GetContact().ID] = rr

		default:
			jww.FATAL.Panicf("Unknown request type: %d", requestType)
		}
	}

	// Load previous negotiations from storage
	s.previousNegotiations, err = s.newOrLoadPreviousNegotiations()
	if err != nil {
		return nil, errors.Errorf("failed to load list of previouse "+
			"negotation partner IDs: %+v", err)
	}

	return s, s.saveLegacySIDH()
}

func (s *Store) saveLegacySIDH() error {
	requestIDList := make([]requestDisk, 0, len(s.receivedByID)+len(s.sentByID))
	for _, rr := range s.storeLegacySIDH.receivedByID {
		rDisk := requestDisk{
			T:  uint(rr.getType()),
			ID: rr.partner.ID.Marshal(),
		}
		requestIDList = append(requestIDList, rDisk)
	}

	for _, rr := range s.storeLegacySIDH.receivedByID {
		rDisk := requestDisk{
			T:  uint(rr.getType()),
			ID: rr.partner.ID.Marshal(),
		}
		requestIDList = append(requestIDList, rDisk)
	}

	for _, sr := range s.storeLegacySIDH.sentByID {
		rDisk := requestDisk{
			T:  uint(sr.getType()),
			ID: sr.partner.Marshal(),
		}
		requestIDList = append(requestIDList, rDisk)
	}

	data, err := json.Marshal(&requestIDList)
	if err != nil {
		return err
	}
	obj := versioned.Object{
		Version:   requestMapVersion,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	err = s.savePreviousNegotiations()
	if err != nil {
		return err
	}

	return s.kv.Set(requestMapKey, &obj)
}

// HandleReceivedRequest handles the request singly, only a single operator
// operates on the same request at a time. It will delete the request if no
// error is returned from the handler
func (s *Store) HandleReceivedRequestLegacySIDH(partner *id.ID,
	handler func(*ReceivedRequestLegacySIDH) error) error {

	legacy := s.storeLegacySIDH

	s.mux.RLock()
	rr, ok := legacy.receivedByID[*partner]
	s.mux.RUnlock()

	if !ok {
		return errors.Errorf("Received request not "+
			"found: %s", partner)
	}

	// Take the lock to ensure there is only one operator at a time
	rr.mux.Lock()
	defer rr.mux.Unlock()

	// Check that the request still exists; it could have been
	// deleted while the lock was taken
	s.mux.RLock()
	_, ok = legacy.receivedByID[*partner]
	s.mux.RUnlock()

	if !ok {
		return errors.Errorf("Received request not "+
			"found: %s", partner)
	}

	//run the handler
	handleErr := handler(rr)
	if handleErr != nil {
		return errors.WithMessage(handleErr, "Received error from handler")
	}

	delete(legacy.receivedByID, *partner)
	err := s.save()
	rr.delete()

	return err
}

func (s *Store) AddReceivedLegacySIDH(c contact.Contact, key *sidh.PublicKey,
	round rounds.Round) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	legacy := s.storeLegacySIDH
	jww.DEBUG.Printf("AddReceived new contact: %s, prefix: %s",
		c.ID, s.kv.GetPrefix())

	if _, ok := legacy.receivedByID[*c.ID]; ok {
		return errors.Errorf("Cannot add contact for partner "+
			"%s, one already exists", c.ID)
	}
	if _, ok := legacy.sentByID[*c.ID]; ok {
		return errors.Errorf("Cannot add contact for partner "+
			"%s, one already exists", c.ID)
	}
	r := newReceivedRequestLegacySIDH(s.kv, c, key, round)

	legacy.receivedByID[*r.GetContact().ID] = r
	if err := s.save(); err != nil {
		jww.FATAL.Panicf("Failed to save Sent Request Map after adding "+
			"partner %s", c.ID)
	}

	return nil
}

// GetAllReceivedRequests returns a slice of all recieved requests.
func (s *Store) GetAllReceivedRequestsLegacySIDH() []*ReceivedRequestLegacySIDH {

	s.mux.RLock()
	legacy := s.storeLegacySIDH
	rr := make([]*ReceivedRequestLegacySIDH, 0, len(legacy.receivedByID))

	for _, r := range legacy.receivedByID {
		rr = append(rr, r)
	}
	s.mux.RUnlock()

	return rr
}

func (s *Store) AddSentLegacySIDH(partner *id.ID, partnerHistoricalPubKey, myPrivKey,
	myPubKey *cyclic.Int, sidHPrivA *sidh.PrivateKey,
	sidHPubA *sidh.PublicKey, fp format.Fingerprint,
	reset bool) (*SentRequestLegacySIDH, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	legacy := s.storeLegacySIDH

	if !reset {
		if sentRq, ok := legacy.sentByID[*partner]; ok {
			return sentRq, errors.Errorf("sent request "+
				"already exists for partner %s",
				partner)
		}
		if _, ok := legacy.receivedByID[*partner]; ok {
			return nil, errors.Errorf("received request "+
				"already exists for partner %s",
				partner)
		}
	}

	sr, err := newSentRequestLegacySIDH(s.kv, partner,
		partnerHistoricalPubKey, myPrivKey, myPubKey, sidHPrivA,
		sidHPubA, fp, reset)

	if err != nil {
		return nil, err
	}

	legacy.sentByID[*sr.GetPartner()] = sr
	s.srh.AddLegacySIDH(sr)
	if err = s.save(); err != nil {
		jww.FATAL.Panicf("Failed to save Sent Request Map after "+
			"adding partner %s", partner)
	}

	return sr, nil
}

// GetReceivedRequest returns the contact representing the partner request
// if it exists. It does not take the lock. It is only meant to return the
// contact to an external API user.
func (s *Store) GetReceivedRequestLegacySIDH(partner *id.ID) (contact.Contact, error) {
	s.mux.RLock()
	r, ok := s.storeLegacySIDH.receivedByID[*partner]
	s.mux.RUnlock()

	if !ok {
		return contact.Contact{}, errors.Errorf("Received request not "+
			"found: %s", partner)
	}

	return r.partner, nil
}