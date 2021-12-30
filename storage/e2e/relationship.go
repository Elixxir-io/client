///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/interfaces/params"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/netTime"
	"sync"
)

const maxUnconfirmed uint = 3
const currentRelationshipVersion = 0
const currentRelationshipFingerprintVersion = 0
const relationshipKey = "relationship"
const relationshipFingerprintKey = "relationshipFingerprint"

type relationship struct {
	manager *Manager
	t       RelationshipType

	kv versioned.KV

	sessions    []*Session
	sessionByID map[SessionID]*Session

	fingerprint []byte

	mux     sync.RWMutex
	sendMux sync.Mutex
}

func NewRelationship(manager *Manager, t RelationshipType,
	initialParams params.E2ESessionParams) *relationship {

	kv := manager.kv.Prefix(t.prefix())

	// build the fingerprint
	fingerprint := makeRelationshipFingerprint(t, manager.ctx.grp,
		manager.originMyPrivKey, manager.originPartnerPubKey, manager.ctx.myID,
		manager.partner)

	if err := storeRelationshipFingerprint(fingerprint, kv); err != nil {
		jww.FATAL.Panicf("Failed to store relationship fingerpint "+
			"for new relationship: %+v", err)
	}

	r := &relationship{
		manager:     manager,
		t:           t,
		sessions:    make([]*Session, 0),
		sessionByID: make(map[SessionID]*Session),
		fingerprint: fingerprint,
		kv:          kv,
	}

	// set to confirmed because the first session is always confirmed as a
	// result of the negotiation before creation
	s := newSession(r, r.t, manager.originMyPrivKey,
		manager.originPartnerPubKey, nil, manager.originMySIDHPrivKey,
		manager.originPartnerSIDHPubKey, SessionID{},
		r.fingerprint, Confirmed, initialParams)

	if err := s.save(); err != nil {
		jww.FATAL.Panicf("Failed to Send session after setting to "+
			"confirmed: %+v", err)
	}

	r.addSession(s)

	if err := r.save(); err != nil {
		jww.FATAL.Printf("Failed to save Relationship %s after "+
			"adding session %s: %s", relationshipKey, s, err)
	}

	return r
}

// DeleteRelationship removes all relationship and
// relationship adjacent information from storage
func DeleteRelationship(manager *Manager) error {

	// Delete the send information
	sendKv := manager.kv.Prefix(Send.prefix())
	manager.send.Delete()
	if err := deleteRelationshipFingerprint(sendKv); err != nil {
		return err
	}
	if err := sendKv.Delete(relationshipKey, currentRelationshipVersion); err != nil {
		return errors.Errorf("Could not delete send relationship: %v", err)
	}

	// Delete the receive information
	receiveKv := manager.kv.Prefix(Receive.prefix())
	manager.receive.Delete()
	if err := deleteRelationshipFingerprint(receiveKv); err != nil {
		return err
	}
	if err := receiveKv.Delete(relationshipKey, currentRelationshipVersion); err != nil {
		return errors.Errorf("Could not delete receive relationship: %v", err)
	}

	return nil
}

func LoadRelationship(manager *Manager, t RelationshipType) (*relationship, error) {

	kv := manager.kv.Prefix(t.prefix())

	r := &relationship{
		t:           t,
		manager:     manager,
		sessionByID: make(map[SessionID]*Session),
		kv:          kv,
	}

	obj, err := kv.Get(relationshipKey, currentRelationshipVersion)
	if err != nil {
		return nil, err
	}

	err = r.unmarshal(obj.Data)

	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *relationship) save() error {

	now := netTime.Now()

	data, err := r.marshal()
	if err != nil {
		return err
	}

	obj := versioned.Object{
		Version:   currentRelationshipVersion,
		Timestamp: now,
		Data:      data,
	}

	return r.kv.Set(relationshipKey, currentRelationshipVersion, &obj)
}

// ekv functions
func (r *relationship) marshal() ([]byte, error) {
	sessions := make([]SessionID, len(r.sessions))

	index := 0
	for sid := range r.sessionByID {
		sessions[index] = sid
		index++
	}

	return json.Marshal(&sessions)
}

func (r *relationship) unmarshal(b []byte) error {
	var sessions []SessionID

	err := json.Unmarshal(b, &sessions)

	if err != nil {
		return err
	}

	// load the fingerprint
	r.fingerprint = loadRelationshipFingerprint(r.kv)

	// load all the sessions
	for _, sid := range sessions {
		sessionKV := r.kv.Prefix(makeSessionPrefix(sid))
		session, err := loadSession(r, sessionKV, r.fingerprint)
		if err != nil {
			jww.FATAL.Panicf("Failed to load session %s for %s: %+v",
				makeSessionPrefix(sid), r.manager.partner, err)
		}
		r.addSession(session)
	}

	return nil
}

func (r *relationship) Delete() {
	r.mux.Lock()
	defer r.mux.Unlock()
	for _, s := range r.sessions {
		delete(r.sessionByID, s.GetID())
		s.Delete()
	}

}

func (r *relationship) AddSession(myPrivKey, partnerPubKey, baseKey *cyclic.Int,
	mySIDHPrivKey *sidh.PrivateKey, partnerSIDHPubKey *sidh.PublicKey,
	trigger SessionID, negotiationStatus Negotiation,
	e2eParams params.E2ESessionParams) *Session {
	r.mux.Lock()
	defer r.mux.Unlock()

	s := newSession(r, r.t, myPrivKey, partnerPubKey, baseKey,
		mySIDHPrivKey, partnerSIDHPubKey, trigger,
		r.fingerprint, negotiationStatus, e2eParams)

	r.addSession(s)
	if err := r.save(); err != nil {
		jww.FATAL.Printf("Failed to save Relationship %s after "+
			"adding session %s: %s", relationshipKey, s, err)
	}

	return s
}

func (r *relationship) addSession(s *Session) {
	r.sessions = append([]*Session{s}, r.sessions...)
	r.sessionByID[s.GetID()] = s
	return
}

func (r *relationship) GetNewest() *Session {
	r.mux.RLock()
	defer r.mux.RUnlock()
	if len(r.sessions) == 0 {
		return nil
	}
	return r.sessions[0]
}

// returns the key  which is most likely to be successful for sending
func (r *relationship) getKeyForSending() (*Key, error) {
	r.sendMux.Lock()
	defer r.sendMux.Unlock()
	s := r.getSessionForSending()
	if s == nil {
		return nil, errors.New("Failed to find a session for sending")
	}

	return s.PopKey()
}

// returns the session which is most likely to be successful for sending
func (r *relationship) getSessionForSending() *Session {
	sessions := r.sessions

	var confirmedRekey []*Session
	var unconfirmedActive []*Session
	var unconfirmedRekey []*Session

	jww.TRACE.Printf("[REKEY] Sessions Available: %d", len(sessions))

	for _, s := range sessions {
		status := s.Status()
		confirmed := s.IsConfirmed()
		jww.TRACE.Printf("[REKEY] Session Status/Confirmed: %v, %v",
			status, confirmed)
		if status == Active && confirmed {
			// always return the first confirmed active, happy path
			return s
		} else if status == RekeyNeeded && confirmed {
			confirmedRekey = append(confirmedRekey, s)
		} else if status == Active && !confirmed {
			unconfirmedActive = append(unconfirmedActive, s)
		} else if status == RekeyNeeded && !confirmed {
			unconfirmedRekey = append(unconfirmedRekey, s)
		}
	}

	// return the newest based upon priority
	if len(confirmedRekey) > 0 {
		return confirmedRekey[0]
	} else if len(unconfirmedActive) > 0 {
		return unconfirmedActive[0]
	} else if len(unconfirmedRekey) > 0 {
		return unconfirmedRekey[0]
	}

	jww.INFO.Printf("[REKEY] Details about %v sessions which are invalid:", len(sessions))
	for i, s := range sessions {
		if s == nil {
			jww.INFO.Printf("[REKEY]\tSession %v is nil", i)
		} else {
			jww.INFO.Printf("[REKEY]\tSession %v: status: %v,"+
				" confirmed: %v", i, s.Status(), s.IsConfirmed())
		}
	}

	return nil
}

// returns a list of session that need rekeys. Nil instances mean a new rekey
// from scratch
func (r *relationship) TriggerNegotiation() []*Session {
	// dont need to take the lock due to the use of a copy of the buffer
	sessions := r.getInternalBufferShallowCopy()
	var instructions []*Session
	for _, ses := range sessions {
		if ses.triggerNegotiation() {
			instructions = append(instructions, ses)
		}
	}
	return instructions
}

// returns a key which should be used for rekeying
func (r *relationship) getKeyForRekey() (*Key, error) {
	r.sendMux.Lock()
	defer r.sendMux.Unlock()
	s := r.getNewestRekeyableSession()
	if s == nil {
		return nil, errors.New("Failed to find a session for rekeying")
	}

	return s.PopReKey()
}

// returns the newest session which can be used to start a key negotiation
func (r *relationship) getNewestRekeyableSession() *Session {
	// dont need to take the lock due to the use of a copy of the buffer
	sessions := r.getInternalBufferShallowCopy()
	if len(sessions) == 0 {
		return nil
	}

	var unconfirmed *Session

	for _, s := range r.sessions {
		jww.TRACE.Printf("[REKEY] Looking at session %s", s)
		// fmt.Println(i)
		// This looks like it might not be thread safe, I think it is because
		// the failure mode is it skips to a lower key to rekey with, which is
		// always valid. It isn't clear it can fail though because we are
		// accessing the data in the same order it would be written (i think)
		if s.Status() != RekeyEmpty {
			if s.IsConfirmed() {
				jww.TRACE.Printf("[REKEY] Selected rekey: %s",
					s)
				return s
			} else if unconfirmed == nil {
				unconfirmed = s
			}
		}
	}
	jww.WARN.Printf("[REKEY] Returning unconfirmed session rekey: %s",
		unconfirmed)
	return unconfirmed
}

func (r *relationship) GetByID(id SessionID) *Session {
	r.mux.RLock()
	defer r.mux.RUnlock()
	return r.sessionByID[id]
}

// sets the passed session ID as confirmed. Call "GetSessionRotation" after
// to get any sessions that are to be deleted and then "DeleteSession" to
// remove them
func (r *relationship) Confirm(id SessionID) error {
	r.mux.Lock()
	defer r.mux.Unlock()

	s, ok := r.sessionByID[id]
	if !ok {
		return errors.Errorf("Could not confirm session %s, does not exist", id)
	}

	s.SetNegotiationStatus(Confirmed)

	r.clean()

	return nil
}

// adding or removing a session is always done via replacing the entire
// slice, this allow us to copy the slice under the read lock and do the
// rest of the work while not taking the lock
func (r *relationship) getInternalBufferShallowCopy() []*Session {
	r.mux.RLock()
	defer r.mux.RUnlock()
	return r.sessions
}

func (r *relationship) clean() {

	numConfirmed := uint(0)

	var newSessions []*Session
	editsMade := false

	for _, s := range r.sessions {
		if s.IsConfirmed() {
			numConfirmed++
			// if the number of newer confirmed is sufficient, delete the confirmed
			if numConfirmed > maxUnconfirmed {
				delete(r.sessionByID, s.GetID())
				s.Delete()
				editsMade = true
				continue
			}
		}
		newSessions = append(newSessions, s)
	}

	// only do the update and save if changes occured
	if editsMade {
		r.sessions = newSessions

		if err := r.save(); err != nil {
			jww.FATAL.Printf("Failed to save Session Buffer %s after "+
				"clean: %s", r.kv.GetFullKey(relationshipKey,
				currentRelationshipVersion), err)
		}
	}
}
