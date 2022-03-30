///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package rekey

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/catalog"
	"gitlab.com/elixxir/client/e2e/ratchet/partner"
	session "gitlab.com/elixxir/client/e2e/ratchet/partner/session"
	"gitlab.com/elixxir/client/event"
	"gitlab.com/elixxir/client/network"
	"gitlab.com/elixxir/client/stoppable"
	util "gitlab.com/elixxir/client/storage/utility"
	commsNetwork "gitlab.com/elixxir/comms/network"
	ds "gitlab.com/elixxir/comms/network/dataStructures"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/states"
	"time"
)

func CheckKeyExchanges(instance *commsNetwork.Instance, grp *cyclic.Group,
	sendE2E E2eSender, events event.Manager, manager *partner.Manager,
	sendTimeout time.Duration, stop *stoppable.Single) {
	sessions := manager.TriggerNegotiations()
	for _, sess := range sessions {
		go trigger(instance, grp, sendE2E, events, manager, sess,
			sendTimeout, stop)
	}
}

// There are two types of key negotiations that can be triggered, creating a new
// session and negotiation, or resetting a negotiation for an already created
// session. They run the same negotiation, the former does it on a newly created
// session while the latter on an extant session
func trigger(instance *commsNetwork.Instance, grp *cyclic.Group, sendE2E E2eSender,
	events event.Manager, manager *partner.Manager, sess *session.Session,
	sendTimeout time.Duration, stop *stoppable.Single) {

	var negotiatingSession *session.Session
	jww.INFO.Printf("[REKEY] Negotiation triggered for session %s with "+
		"status: %s", sess, sess.NegotiationStatus())
	switch sess.NegotiationStatus() {
	// If the passed session is triggering a negotiation on a new session to
	// replace itself, then create the session
	case session.NewSessionTriggered:
		//create the session, pass a nil private key to generate a new one
		negotiatingSession = manager.NewSendSession(nil, nil,
			session.GetDefaultE2ESessionParams())
		//move the state of the triggering session forward
		sess.SetNegotiationStatus(session.NewSessionCreated)

	// If the session is set to send a negotiation
	case session.Sending:
		negotiatingSession = sess
	default:
		jww.FATAL.Panicf("[REKEY] Session %s provided invalid e2e "+
			"negotiating status: %s", sess, sess.NegotiationStatus())
	}

	// send the rekey notification to the partner
	err := negotiate(instance, grp, sendE2E, negotiatingSession,
		sendTimeout, stop)
	// if sending the negotiation fails, revert the state of the session to
	// unconfirmed so it will be triggered in the future
	if err != nil {
		jww.ERROR.Printf("[REKEY] Failed to do Key Negotiation with "+
			"session %s: %s", sess, err)
		events.Report(1, "Rekey", "NegotiationFailed", err.Error())
	}
}

func negotiate(instance *commsNetwork.Instance, grp *cyclic.Group, sendE2E E2eSender,
	sess *session.Session, sendTimeout time.Duration,
	stop *stoppable.Single) error {

	//generate public key
	pubKey := diffieHellman.GeneratePublicKey(sess.GetMyPrivKey(), grp)

	sidhPrivKey := sess.GetMySIDHPrivKey()
	sidhPubKey := util.NewSIDHPublicKey(sidhPrivKey.Variant())
	sidhPrivKey.GeneratePublicKey(sidhPubKey)
	sidhPubKeyBytes := make([]byte, sidhPubKey.Size()+1)
	sidhPubKeyBytes[0] = byte(sidhPubKey.Variant())
	sidhPubKey.Export(sidhPubKeyBytes[1:])

	//build the payload
	payload, err := proto.Marshal(&RekeyTrigger{
		PublicKey:     pubKey.Bytes(),
		SidhPublicKey: sidhPubKeyBytes,
		SessionID:     sess.GetSource().Marshal(),
	})

	//If the payload cannot be marshaled, panic
	if err != nil {
		jww.FATAL.Printf("[REKEY] Failed to marshal payload for Key "+
			"Negotiation Trigger with %s", sess.GetPartner())
	}

	//send the message under the key exchange
	params := network.GetDefaultCMIXParams()
	params.DebugTag = "kx.Request"
	params.Stop = stop

	rounds, msgID, _, err := sendE2E(catalog.KeyExchangeTrigger, sess.GetPartner(),
		payload, params)
	// If the send fails, returns the error so it can be handled. The caller
	// should ensure the calling session is in a state where the Rekey will
	// be triggered next time a key is used
	if err != nil {
		return errors.Errorf(
			"[REKEY] Failed to send the key negotiation message "+
				"for %s: %s", sess, err)
	}

	//create the runner which will handle the result of sending the messages
	sendResults := make(chan ds.EventReturn, len(rounds))

	//Register the event for all rounds
	roundEvents := instance.GetRoundEvents()
	for _, r := range rounds {
		roundEvents.AddRoundEventChan(r, sendResults, sendTimeout,
			states.COMPLETED, states.FAILED)
	}

	//Wait until the result tracking responds
	success, numRoundFail, numTimeOut := network.TrackResults(sendResults,
		len(rounds))

	// If a single partition of the Key Negotiation request does not
	// transmit, the partner cannot read the result. Log the error and set
	// the session as unconfirmed so it will re-trigger the negotiation
	if !success {
		sess.SetNegotiationStatus(session.Unconfirmed)
		return errors.Errorf("[REKEY] Key Negotiation rekey for %s failed to "+
			"transmit %v/%v paritions: %v round failures, %v timeouts, msgID: %s",
			sess, numRoundFail+numTimeOut, len(rounds), numRoundFail,
			numTimeOut, msgID)
	}

	// otherwise, the transmission is a success and this should be denoted
	// in the session and the log
	jww.INFO.Printf("[REKEY] Key Negotiation rekey transmission for %s, msgID %s successful",
		sess, msgID)
	err = sess.TrySetNegotiationStatus(session.Sent)
	if err != nil {
		if sess.NegotiationStatus() == session.NewSessionTriggered {
			msg := fmt.Sprintf("All channels exhausted for %s, "+
				"rekey impossible.", sess)
			return errors.WithMessage(err, msg)
		}
	}
	return err
}