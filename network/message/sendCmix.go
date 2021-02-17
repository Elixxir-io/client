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
	"gitlab.com/elixxir/client/storage"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/crypto/fingerprint"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"strings"
	"time"
)

// interface for sendcmix comms; allows mocking this in testing
type sendCmixCommsInterface interface {
	GetHost(hostId *id.ID) (*connect.Host, bool)
	SendPutMessage(host *connect.Host, message *pb.GatewaySlot) (*pb.GatewaySlotResponse, error)
}

const sendTimeBuffer = 100 * time.Millisecond

// WARNING: Potentially Unsafe
// Public manager function to send a message over CMIX
func (m *Manager) SendCMIX(msg format.Message, recipient *id.ID, param params.CMIX) (id.Round, ephemeral.Id, error) {
	return sendCmixHelper(msg, recipient, param, m.Instance, m.Session, m.nodeRegistration, m.Rng, m.TransmissionID, m.Comms)
}

// Payloads send are not End to End encrypted, MetaData is NOT protected with
// this call, see SendE2E for End to End encryption and full privacy protection
// Internal SendCmix which bypasses the network check, will attempt to send to
// the network without checking state. It has a built in retry system which can
// be configured through the params object.
// If the message is successfully sent, the id of the round sent it is returned,
// which can be registered with the network instance to get a callback on
// its status
func sendCmixHelper(msg format.Message, recipient *id.ID, param params.CMIX, instance *network.Instance,
	session *storage.Session, nodeRegistration chan network.NodeGateway, rng *fastRNG.StreamGenerator, senderId *id.ID,
	comms sendCmixCommsInterface) (id.Round, ephemeral.Id, error) {

	timeStart := time.Now()
	attempted := set.New()

	for numRoundTries := uint(0); numRoundTries < param.RoundTries; numRoundTries++ {
		elapsed := time.Now().Sub(timeStart)

		jww.DEBUG.Printf("SendCMIX Send Attempt %d", numRoundTries+1)
		if elapsed > param.Timeout {
			return 0, ephemeral.Id{}, errors.New("Sending cmix message timed out")
		}
		remainingTime := param.Timeout - elapsed
		jww.TRACE.Printf("SendCMIX GetUpcommingRealtime")
		//find the best round to send to, excluding attempted rounds
		bestRound, _ := instance.GetWaitingRounds().GetUpcomingRealtime(remainingTime, attempted)
		if bestRound == nil {
			continue
		}

		roundCutoffTime := time.Unix(0,
			int64(bestRound.Timestamps[states.QUEUED]))
		roundCutoffTime.Add(sendTimeBuffer)
		now := time.Now()

		if now.After(roundCutoffTime) {
			jww.WARN.Printf("Round %d received which has already started" +
				" realtime: \n\t started: %s \n\t now: %s", bestRound.ID,
				roundCutoffTime, now)
			attempted.Insert(bestRound)
			continue
		}

		//set the ephemeral ID
		ephID, _, _, err := ephemeral.GetId(recipient,
			uint(bestRound.AddressSpaceSize),
			int64(bestRound.Timestamps[states.QUEUED]))
		if err != nil {
			jww.FATAL.Panicf("Failed to generate ephemeral ID: %+v", err)
		}

		jww.INFO.Printf("Sending to EphID %v (source: %s)", ephID.Int64(), recipient)

		stream := rng.GetStream()
		ephID, err = ephID.Fill(uint(bestRound.AddressSpaceSize), stream)
		if err != nil {
			jww.FATAL.Panicf("Failed to obviscate the ephemeralID: %+v", err)
		}
		stream.Close()

		msg.SetEphemeralRID(ephID[:])

		//set the identity fingerprint
		ifp, err := fingerprint.IdentityFP(msg.GetContents(), recipient)
		if err != nil {
			jww.FATAL.Panicf("failed to generate the Identity "+
				"fingerprint due to unrecoverable error: %+v", err)
		}

		msg.SetIdentityFP(ifp)

		//build the topology
		idList, err := id.NewIDListFromBytes(bestRound.Topology)
		if err != nil {
			jww.ERROR.Printf("Failed to use topology for round %v: %s", bestRound.ID, err)
			continue
		}
		topology := connect.NewCircuit(idList)
		jww.TRACE.Printf("SendCMIX GetRoundKeys")
		//get they keys for the round, reject if any nodes do not have
		//keying relationships
		roundKeys, missingKeys := session.Cmix().GetRoundKeys(topology)
		if len(missingKeys) > 0 {
			go handleMissingNodeKeys(instance, nodeRegistration, missingKeys)
			time.Sleep(param.RetryDelay)
			continue
		}

		//get the gateway to transmit to
		firstGateway := topology.GetNodeAtIndex(0).DeepCopy()
		firstGateway.SetType(id.Gateway)

		transmitGateway, ok := comms.GetHost(firstGateway)
		if !ok {
			jww.ERROR.Printf("Failed to get host for gateway %s", transmitGateway)
			time.Sleep(param.RetryDelay)
			continue
		}

		//encrypt the message
		stream = rng.GetStream()
		salt := make([]byte, 32)
		_, err = stream.Read(salt)
		stream.Close()

		if err != nil {
			return 0, ephemeral.Id{}, errors.WithMessage(err,
				"Failed to generate salt, this should never happen")
		}

		encMsg, kmacs := roundKeys.Encrypt(msg, salt)

		//build the message payload
		msgPacket := &pb.Slot{
			SenderID: senderId.Bytes(),
			PayloadA: encMsg.GetPayloadA(),
			PayloadB: encMsg.GetPayloadB(),
			Salt:     salt,
			KMACs:    kmacs,
		}

		//create the wrapper to the gateway
		wrappedMsg := &pb.GatewaySlot{
			Message: msgPacket,
			RoundID: bestRound.ID,
		}
		//Add the mac proving ownership
		wrappedMsg.MAC = roundKeys.MakeClientGatewayKey(salt,
			network.GenerateSlotDigest(wrappedMsg))

		//add the round on to the list of attempted so it is not tried again
		attempted.Insert(bestRound)

		jww.DEBUG.Printf("SendCMIX SendPutMessage")
		//Send the payload
		gwSlotResp, err := comms.SendPutMessage(transmitGateway, wrappedMsg)
		//if the comm errors or the message fails to send, continue retrying.
		//return if it sends properly
		if err != nil {
			if strings.Contains(err.Error(),
				"try a different round.") {
				jww.WARN.Printf("could not send: %s",
					err)
				continue
			}
			jww.ERROR.Printf("Failed to send message to %s: %s",
				transmitGateway, err)
		} else if gwSlotResp.Accepted {
			return id.Round(bestRound.ID), ephID, nil
		}
	}
	return 0, ephemeral.Id{}, errors.New("failed to send the message")
}

// Signals to the node registration thread to register a node if keys are
// missing. Identity is triggered automatically when the node is first seen,
// so this should on trigger on rare events.
func handleMissingNodeKeys(instance *network.Instance,
	newNodeChan chan network.NodeGateway, nodes []*id.ID) {
	for _, n := range nodes {
		ng, err := instance.GetNodeAndGateway(n)
		if err != nil {
			jww.ERROR.Printf("Node contained in round cannot be found: %s", err)
			continue
		}
		select {
		case newNodeChan <- ng:
		default:
			jww.ERROR.Printf("Failed to send node registration for %s", n)
		}

	}
}
