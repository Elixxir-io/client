///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package message

import (
	"github.com/golang-collections/collections/set"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/interfaces/params"
	"gitlab.com/elixxir/client/network/gateway"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/client/storage"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/netTime"
	"strings"
)

// WARNING: Potentially Unsafe
// Public manager function to send a message over CMIX
func (m *Manager) SendCMIX(sender *gateway.Sender, msg format.Message,
	recipient *id.ID, param params.CMIX, stop *stoppable.Single) (id.Round, ephemeral.Id, error) {
	msgCopy := msg.Copy()
	return sendCmixHelper(sender, msgCopy, recipient, param, m.Instance,
		m.Session, m.nodeRegistration, m.Rng, m.TransmissionID, m.Comms, stop)
}

// Helper function for sendCmix
// NOTE: Payloads send are not End to End encrypted, MetaData is NOT protected with
// this call, see SendE2E for End to End encryption and full privacy protection
// Internal SendCmix which bypasses the network check, will attempt to send to
// the network without checking state. It has a built in retry system which can
// be configured through the params object.
// If the message is successfully sent, the id of the round sent it is returned,
// which can be registered with the network instance to get a callback on
// its status
func sendCmixHelper(sender *gateway.Sender, msg format.Message,
	recipient *id.ID, cmixParams params.CMIX, instance *network.Instance,
	session *storage.Session, nodeRegistration chan network.NodeGateway,
	rng *fastRNG.StreamGenerator, senderId *id.ID, comms sendCmixCommsInterface,
	stop *stoppable.Single) (id.Round, ephemeral.Id, error) {

	timeStart := netTime.Now()
	attempted := set.New()

	jww.INFO.Printf("Looking for round to send cMix message to %s "+
		"(msgDigest: %s)", recipient, msg.Digest())

	for numRoundTries := uint(0); numRoundTries < cmixParams.RoundTries; numRoundTries++ {
		elapsed := netTime.Since(timeStart)

		if elapsed > cmixParams.Timeout {
			jww.INFO.Printf("No rounds to send to %s (msgDigest: %s) "+
				"were found before timeout %s", recipient, msg.Digest(),
				cmixParams.Timeout)
			return 0, ephemeral.Id{}, errors.New("Sending cmix message timed out")
		}
		if numRoundTries > 0 {
			jww.INFO.Printf("Attempt %d to find round to send message "+
				"to %s (msgDigest: %s)", numRoundTries+1, recipient,
				msg.Digest())
		}

		remainingTime := cmixParams.Timeout - elapsed
		//find the best round to send to, excluding attempted rounds
		bestRound, _ := instance.GetWaitingRounds().GetUpcomingRealtime(remainingTime, attempted, sendTimeBuffer)
		if bestRound == nil {
			continue
		}

		//add the round on to the list of attempted so it is not tried again
		attempted.Insert(bestRound)

		// Retrieve host and key information from round
		firstGateway, roundKeys, err := processRound(instance, session, nodeRegistration, bestRound, recipient.String(), msg.Digest())
		if err != nil {
			jww.WARN.Printf("SendCmix failed to process round (will retry): %v", err)
			continue
		}

		// Build the messages to send
		stream := rng.GetStream()

		wrappedMsg, encMsg, ephID, err := buildSlotMessage(msg, recipient,
			firstGateway, stream, senderId, bestRound, roundKeys)
		if err != nil {
			stream.Close()
			return 0, ephemeral.Id{}, err
		}
		stream.Close()

		jww.INFO.Printf("Sending to EphID %d (%s) on round %d, "+
			"(msgDigest: %s, ecrMsgDigest: %s) via gateway %s",
			ephID.Int64(), recipient, bestRound.ID, msg.Digest(),
			encMsg.Digest(), firstGateway.String())

		// Send the payload
		sendFunc := func(host *connect.Host, target *id.ID) (interface{}, bool, error) {
			wrappedMsg.Target = target.Marshal()
			result, err := comms.SendPutMessage(host, wrappedMsg)
			if err != nil {
				// fixme: should we provide as a slice the whole topology?
				warn, err := handlePutMessageError(firstGateway, instance, session, nodeRegistration, recipient.String(), bestRound, err)
				if warn {
					jww.WARN.Printf("SendCmix Failed: %+v", err)
				} else {
					return result, false, errors.WithMessagef(err, "SendCmix %s", unrecoverableError)
				}
			}
			return result, false, err
		}
		result, err := sender.SendToPreferred([]*id.ID{firstGateway}, sendFunc, stop)

		// Exit if the thread has been stopped
		if stoppable.CheckErr(err) {
			return 0, ephemeral.Id{}, err
		}

		//if the comm errors or the message fails to send, continue retrying.
		if err != nil {
			if !strings.Contains(err.Error(), unrecoverableError) {
				jww.ERROR.Printf("SendCmix failed to send to EphID %d (%s) on "+
					"round %d, trying a new round: %+v", ephID.Int64(), recipient,
					bestRound.ID, err)
				continue
			}

			return 0, ephemeral.Id{}, err
		}

		// Return if it sends properly
		gwSlotResp := result.(*pb.GatewaySlotResponse)
		if gwSlotResp.Accepted {
			jww.INFO.Printf("Successfully sent to EphID %v (source: %s) "+
				"in round %d (msgDigest: %s)", ephID.Int64(), recipient, bestRound.ID, msg.Digest())
			return id.Round(bestRound.ID), ephID, nil
		} else {
			jww.FATAL.Panicf("Gateway %s returned no error, but failed "+
				"to accept message when sending to EphID %d (%s) on round %d",
				firstGateway, ephID.Int64(), recipient, bestRound.ID)
		}

	}
	return 0, ephemeral.Id{}, errors.New("failed to send the message, " +
		"unknown error")
}
