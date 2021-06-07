///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/interfaces/params"
	"gitlab.com/elixxir/client/storage/utility"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/cyclic"
	dh "gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/primitives/id"
	"golang.org/x/crypto/blake2b"
	"sort"
)

const managerPrefix = "Manager{partner:%s}"
const originMyPrivKeyKey = "originMyPrivKey"
const originPartnerPubKey = "originPartnerPubKey"

type Manager struct {
	ctx *context
	kv  *versioned.KV

	partner *id.ID

	originMyPrivKey     *cyclic.Int
	originPartnerPubKey *cyclic.Int

	receive *relationship
	send    *relationship
}

// newManager creates the relationship and its first Send and Receive sessions.
func newManager(ctx *context, kv *versioned.KV, partnerID *id.ID, myPrivKey,
	partnerPubKey *cyclic.Int,
	sendParams, receiveParams params.E2ESessionParams) *Manager {

	kv = kv.Prefix(fmt.Sprintf(managerPrefix, partnerID))

	m := &Manager{
		ctx:                 ctx,
		kv:                  kv,
		originMyPrivKey:     myPrivKey,
		originPartnerPubKey: partnerPubKey,
		partner:             partnerID,
	}

	if err := utility.StoreCyclicKey(kv, myPrivKey, originMyPrivKeyKey); err != nil {
		jww.FATAL.Panicf("Failed to store %s: %+v", originMyPrivKeyKey,
			err)
	}

	if err := utility.StoreCyclicKey(kv, partnerPubKey, originPartnerPubKey); err != nil {
		jww.FATAL.Panicf("Failed to store %s: %+v", originPartnerPubKey,
			err)
	}

	m.send = NewRelationship(m, Send, sendParams)
	m.receive = NewRelationship(m, Receive, receiveParams)

	return m
}

//loads a relationship and all buffers and sessions from disk
func loadManager(ctx *context, kv *versioned.KV, partnerID *id.ID) (*Manager, error) {

	kv = kv.Prefix(fmt.Sprintf(managerPrefix, partnerID))

	m := &Manager{
		ctx:     ctx,
		partner: partnerID,
		kv:      kv,
	}

	var err error
	m.originMyPrivKey, err = utility.LoadCyclicKey(kv, originMyPrivKeyKey)
	if err != nil {
		jww.FATAL.Panicf("Failed to load %s: %+v", originMyPrivKeyKey,
			err)
	}

	m.originPartnerPubKey, err = utility.LoadCyclicKey(kv, originPartnerPubKey)
	if err != nil {
		jww.FATAL.Panicf("Failed to load %s: %+v", originPartnerPubKey,
			err)
	}

	m.send, err = LoadRelationship(m, Send)
	if err != nil {
		return nil, errors.WithMessage(err,
			"Failed to load partner key relationship due to failure to "+
				"load the Send session buffer")
	}

	m.receive, err = LoadRelationship(m, Receive)
	if err != nil {
		return nil, errors.WithMessage(err,
			"Failed to load partner key relationship due to failure to "+
				"load the Receive session buffer")
	}

	return m, nil
}

// NewReceiveSession creates a new Receive session using the latest private key
// this user has sent and the new public key received from the partner. If the
// session already exists, then it will not be overwritten and the extant
// session will be returned with the bool set to true denoting a duplicate. This
// allows for support of duplicate key exchange triggering.
func (m *Manager) NewReceiveSession(partnerPubKey *cyclic.Int, e2eParams params.E2ESessionParams,
	source *Session) (*Session, bool) {

	// Check if the session already exists
	baseKey := dh.GenerateSessionKey(source.myPrivKey, partnerPubKey, m.ctx.grp)
	sessionID := getSessionIDFromBaseKey(baseKey)

	if s := m.receive.GetByID(sessionID); s != nil {
		return s, true
	}

	// Add the session to the buffer
	session := m.receive.AddSession(source.myPrivKey, partnerPubKey, baseKey,
		source.GetID(), Confirmed, e2eParams)

	return session, false
}

// NewSendSession creates a new Receive session using the latest public key
// received from the partner and a new private key for the user. Passing in a
// private key is optional. A private key will be generated if none is passed.
func (m *Manager) NewSendSession(myPrivKey *cyclic.Int, e2eParams params.E2ESessionParams) *Session {
	// Find the latest public key from the other party
	sourceSession := m.receive.getNewestRekeyableSession()

	// Add the session to the Send session buffer and return
	return m.send.AddSession(myPrivKey, sourceSession.partnerPubKey, nil,
		sourceSession.GetID(), Sending, e2eParams)
}

// GetKeyForSending gets the correct session to Send with depending on the type
// of Send.
func (m *Manager) GetKeyForSending(st params.SendType) (*Key, error) {
	switch st {
	case params.Standard:
		return m.send.getKeyForSending()
	case params.KeyExchange:
		return m.send.getKeyForRekey()
	default:
	}

	return nil, errors.Errorf("Cannot get session for invalid Send Type: %s", st)
}

// GetPartnerID returns a copy of the ID of the partner.
func (m *Manager) GetPartnerID() *id.ID {
	return m.partner.DeepCopy()
}

// GetSendSession gets the Send session of the passed ID. Returns nil if no
// session is found.
func (m *Manager) GetSendSession(sid SessionID) *Session {
	return m.send.GetByID(sid)
}

// GetSendSession gets the Send session of the passed ID. Returns nil if no
// session is found.
func (m *Manager) GetSendRelationshipFingerprint() []byte {
	return m.send.fingerprint
}

// GetReceiveSession gets the Receive session of the passed ID. Returns nil if
// no session is found.
func (m *Manager) GetReceiveSession(sid SessionID) *Session {
	return m.receive.GetByID(sid)
}

// Confirm confirms a Send session is known about by the partner.
func (m *Manager) Confirm(sid SessionID) error {
	return m.send.Confirm(sid)
}

// TriggerNegotiations returns a list of key exchange operations if any are
// necessary.
func (m *Manager) TriggerNegotiations() []*Session {
	return m.send.TriggerNegotiation()
}

func (m *Manager) GetMyOriginPrivateKey() *cyclic.Int {
	return m.originMyPrivKey.DeepCopy()
}

func (m *Manager) GetPartnerOriginPublicKey() *cyclic.Int {
	return m.originPartnerPubKey.DeepCopy()
}

const relationshipFpLength = 15

// GetRelationshipFingerprint returns a unique fingerprint for an E2E
// relationship. The fingerprint is a base 64 encoded hash of of the two
// relationship fingerprints truncated to 15 characters.
func (m *Manager) GetRelationshipFingerprint() string {
	// Sort fingerprints
	fps := [][]byte{m.receive.fingerprint, m.send.fingerprint}
	less := func(i, j int) bool { return bytes.Compare(fps[i], fps[j]) == -1 }
	sort.Slice(fps, less)

	// Hash fingerprints
	h, _ := blake2b.New256(nil)
	for _, fp := range fps {
		h.Write(fp)
	}

	// Base 64 encode hash and truncate
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:relationshipFpLength]
}
