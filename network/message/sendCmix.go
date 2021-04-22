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
	"gitlab.com/elixxir/client/storage/cmix"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/crypto/fingerprint"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/netTime"
	"strconv"
	"strings"
	"time"
)

// interface for SendCMIX comms; allows mocking this in testing
type sendCmixCommsInterface interface {
	GetHost(hostId *id.ID) (*connect.Host, bool)
	SendPutMessage(host *connect.Host, message *pb.GatewaySlot) (*pb.GatewaySlotResponse, error)
	SendPutManyMessages(host *connect.Host, messages *pb.GatewaySlots) (*pb.GatewaySlotResponse, error)
}

// 2.5 seconds
const sendTimeBuffer = 2500 * time.Millisecond
const recoverableError = "Recoverable error; try again if possible"

// WARNING: Potentially Unsafe
// SendManyCMIX sends many "raw" CMIX message payloads to each of the
// provided recipients. Used for group chat functionality. Returns the
// round ID of the round the payload was sent or an error if it fails.
func (m *Manager) SendManyCMIX(messages []format.Message,
	recipients []*id.ID, p params.CMIX) (id.Round, []ephemeral.Id, error) {
	// Create message copies
	messagesCopy := make([]format.Message, len(messages))
	for i := 0; i < len(messages); i++ {
		messagesCopy[i] = messages[i].Copy()
	}

	return sendManyCmixHelper(messagesCopy, recipients, p, m.Instance, m.Session, m.nodeRegistration, m.Rng, m.TransmissionID, m.Comms)

}

// WARNING: Potentially Unsafe
// Public manager function to send a message over CMIX
func (m *Manager) SendCMIX(msg format.Message, recipient *id.ID, param params.CMIX) (id.Round, ephemeral.Id, error) {
	msgCopy := msg.Copy()

	return sendCmixHelper(msgCopy, recipient, param, m.Instance, m.Session, m.nodeRegistration, m.Rng, m.TransmissionID, m.Comms)
}

// Helper function for SendManyCmix
// NOTE: Payloads send are not End to End encrypted, MetaData is NOT protected with
// this call, see SendE2E for End to End encryption and full privacy protection
// Internal SendCmix which bypasses the network check, will attempt to send to
// the network without checking state. It has a built in retry system which can
// be configured through the params object.
// If the message is successfully sent, the id of the round sent it is returned,
// which can be registered with the network instance to get a callback on
// its status
func sendManyCmixHelper(msgs []format.Message, recipients []*id.ID, param params.CMIX, instance *network.Instance,
	session *storage.Session, nodeRegistration chan network.NodeGateway, rng *fastRNG.StreamGenerator, senderId *id.ID,
	comms sendCmixCommsInterface) (id.Round, []ephemeral.Id, error) {

	timeStart := netTime.Now()
	attempted := set.New()

	recipientString := idListToString(recipients)

	msgDigest := buildMessageDigestString(msgs)
	jww.INFO.Printf("Looking for round to send cMix messages to [%s] (msgDigest: %s)", recipientString, msgDigest)

	for numRoundTries := uint(0); numRoundTries < param.RoundTries; numRoundTries++ {
		elapsed := netTime.Now().Sub(timeStart)
		var err error
		var transmitGateway *connect.Host
		if elapsed > param.Timeout {
			jww.INFO.Printf("No rounds to send to %s (msgDigest: %s) "+
				"were found before timeout %s", recipientString, msgDigest,
				param.Timeout)
			return 0, []ephemeral.Id{}, errors.New("Sending cmix message timed out")
		}
		if numRoundTries > 0 {
			jww.INFO.Printf("Attempt %d to find round to send message "+
				"to %s (msgDigest: %s)", numRoundTries+1, recipientString, msgDigest)
		}

		remainingTime := param.Timeout - elapsed
		//find the best round to send to, excluding attempted rounds
		bestRound, _ := instance.GetWaitingRounds().GetUpcomingRealtime(remainingTime, attempted, sendTimeBuffer)
		if bestRound == nil {
			continue
		}

		//add the round on to the list of attempted so it is not tried again
		attempted.Insert(bestRound)

		// Retrieve host and key information from round
		transmitGateway, roundKeys, err := processRound(param, instance, session,
			nodeRegistration, comms, bestRound, recipientString, msgDigest)
		if err != nil {
			if strings.Contains(err.Error(), recoverableError) {
				continue
			}

			return 0, []ephemeral.Id{}, errors.WithMessage(err, "Unexpected error processing best round to send")

		}

		// Build a slot for every message and recipient
		slots := make([]*pb.GatewaySlot, len(msgs))
		ephemeralIds := make([]ephemeral.Id, len(recipients))
		encMsgs := make([]format.Message, len(msgs))
		for i := 0; i < len(msgs); i++ {
			slots[i], encMsgs[i], ephemeralIds[i], err = buildSlotMessage(msgs[i], recipients[i], rng, senderId, bestRound, roundKeys)
			if err != nil {
				if strings.Contains(err.Error(), recoverableError) {
					continue
				}
				// If error does not contain recoverable, something unexpected happened
				return 0, []ephemeral.Id{}, err
			}

		}

		// Serialize lists into a printable format
		ephemeralIdsString := ephemeralIdListToString(ephemeralIds)
		encMsgDigest := buildMessageDigestString(encMsgs)

		jww.INFO.Printf("Sending to EphIDs [%s] (%s) on round %d, "+
			"(msgDigest: %s, ecrMsgDigest: %s) via gateway %s",
			ephemeralIdsString, recipientString, bestRound.ID, msgDigest,
			encMsgDigest, transmitGateway.GetId())

		// Wrap slots in the proper message type
		wrappedMessage := &pb.GatewaySlots{
			Messages: slots,
			RoundID:  bestRound.ID,
		}

		//Send the payload
		gwSlotResp, err := comms.SendPutManyMessages(transmitGateway, wrappedMessage)
		//if the comm errors or the message fails to send, continue retrying.
		//return if it sends properly
		if err != nil {
			err = handlePutMessageError(transmitGateway, instance, session, nodeRegistration, recipientString, bestRound, err)
			if err != nil {
				if strings.Contains(err.Error(), recoverableError) {
					continue
				}

				jww.ERROR.Printf("Failed to send to EphID [%s] (%s) on "+
					"round %d, bailing: %+v", ephemeralIdsString, recipientString,
					bestRound.ID, err)

				return 0, []ephemeral.Id{}, err
			}
		} else if gwSlotResp.Accepted {
			jww.INFO.Printf("Successfully sent to EphIDs %v (sources: [%s]) "+
				"in round %d", ephemeralIdsString, recipientString, bestRound.ID)
			return id.Round(bestRound.ID), ephemeralIds, nil
		} else {
			jww.FATAL.Panicf("Gateway %s returned no error, but failed "+
				"to accept message when sending to EphIDs [%s] (%s) on round %d",
				transmitGateway.GetId(), ephemeralIdsString, recipientString, bestRound.ID)
		}

	}
	return 0, []ephemeral.Id{}, errors.New("failed to send the message, " +
		"unknown error")

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
func sendCmixHelper(msg format.Message, recipient *id.ID, param params.CMIX, instance *network.Instance,
	session *storage.Session, nodeRegistration chan network.NodeGateway, rng *fastRNG.StreamGenerator, senderId *id.ID,
	comms sendCmixCommsInterface) (id.Round, ephemeral.Id, error) {

	timeStart := netTime.Now()
	attempted := set.New()

	jww.INFO.Printf("Looking for round to send cMix message to %s "+
		"(msgDigest: %s)", recipient, msg.Digest())

	for numRoundTries := uint(0); numRoundTries < param.RoundTries; numRoundTries++ {
		elapsed := netTime.Now().Sub(timeStart)

		if elapsed > param.Timeout {
			jww.INFO.Printf("No rounds to send to %s (msgDigest: %s) "+
				"were found before timeout %s", recipient, msg.Digest(),
				param.Timeout)
			return 0, ephemeral.Id{}, errors.New("Sending cmix message timed out")
		}
		if numRoundTries > 0 {
			jww.INFO.Printf("Attempt %d to find round to send message "+
				"to %s (msgDigest: %s)", numRoundTries+1, recipient,
				msg.Digest())
		}

		remainingTime := param.Timeout - elapsed
		//find the best round to send to, excluding attempted rounds
		bestRound, _ := instance.GetWaitingRounds().GetUpcomingRealtime(remainingTime, attempted, sendTimeBuffer)
		if bestRound == nil {
			continue
		}

		//add the round on to the list of attempted so it is not tried again
		attempted.Insert(bestRound)

		// Retrieve host and key information from round
		transmitGateway, roundKeys, err := processRound(param, instance, session,
			nodeRegistration, comms, bestRound, recipient.String(), msg.Digest())
		if err != nil {
			if strings.Contains(err.Error(), recoverableError) {
				continue
			}

			return 0, ephemeral.Id{}, errors.WithMessage(err, "Unexpected error processing best round to send")

		}

		wrappedMsg, encMsg, ephID, err := buildSlotMessage(msg, recipient, rng, senderId, bestRound, roundKeys)
		if err != nil {
			if strings.Contains(err.Error(), recoverableError) {
				continue
			}

			return 0, ephemeral.Id{}, err
		}

		jww.INFO.Printf("Sending to EphID %d (%s) on round %d, "+
			"(msgDigest: %s, ecrMsgDigest: %s) via gateway %s",
			ephID.Int64(), recipient, bestRound.ID, msg.Digest(),
			encMsg.Digest(), transmitGateway.GetId())

		//Send the payload
		gwSlotResp, err := comms.SendPutMessage(transmitGateway, wrappedMsg)
		//if the comm errors or the message fails to send, continue retrying.
		//return if it sends properly
		if err != nil {
			err = handlePutMessageError(transmitGateway, instance, session, nodeRegistration, recipient.String(), bestRound, err)
			if err != nil {
				if strings.Contains(err.Error(), recoverableError) {
					continue
				}

				jww.ERROR.Printf("Failed to send to EphID %d (%s) on "+
					"round %d, bailing: %+v", ephID.Int64(), recipient,
					bestRound.ID, err)

				return 0, ephemeral.Id{}, err
			}
		} else if gwSlotResp.Accepted {
			jww.INFO.Printf("Successfully sent to EphID %v (source: %s) "+
				"in round %d", ephID.Int64(), recipient, bestRound.ID)
			return id.Round(bestRound.ID), ephID, nil
		} else {
			jww.FATAL.Panicf("Gateway %s returned no error, but failed "+
				"to accept message when sending to EphID %d (%s) on round %d",
				transmitGateway.GetId(), ephID.Int64(), recipient, bestRound.ID)
		}

	}
	return 0, ephemeral.Id{}, errors.New("failed to send the message, " +
		"unknown error")
}

// processRound is a helper function which determines the gateway to send to for a round
// and retrieves the round keys
func processRound(param params.CMIX, instance *network.Instance, session *storage.Session,
	nodeRegistration chan network.NodeGateway, comms sendCmixCommsInterface,
	bestRound *pb.RoundInfo, recipientString, messageDigest string) (*connect.Host, *cmix.RoundKeys, error) {

	//build the topology
	idList, err := id.NewIDListFromBytes(bestRound.Topology)
	if err != nil {
		jww.ERROR.Printf("Failed to use topology for round %d when "+
			"sending to [%s] (msgDigest(s): %s): %+v", bestRound.ID,
			recipientString, messageDigest, err)
		return nil, nil, errors.New(recoverableError)
	}
	topology := connect.NewCircuit(idList)

	//get they keys for the round, reject if any nodes do not have
	//keying relationships
	roundKeys, missingKeys := session.Cmix().GetRoundKeys(topology)
	if len(missingKeys) > 0 {
		jww.WARN.Printf("Failed to send on round %d to [%s] (msgDigest(s): %s)"+
			"due to missing relationships with nodes: %s",
			bestRound.ID, recipientString, messageDigest, missingKeys)
		go handleMissingNodeKeys(instance, nodeRegistration, missingKeys)
		time.Sleep(param.RetryDelay)
		return nil, nil, errors.New(recoverableError)
	}

	//get the gateway to transmit to
	firstGateway := topology.GetNodeAtIndex(0).DeepCopy()
	firstGateway.SetType(id.Gateway)

	transmitGateway, ok := comms.GetHost(firstGateway)
	if !ok {
		jww.ERROR.Printf("Failed to get host for gateway %s when "+
			"sending to [%s] (msgDigest(s): %s)", transmitGateway, recipientString, messageDigest)
		time.Sleep(param.RetryDelay)
		return nil, nil, errors.New(recoverableError)
	}

	return transmitGateway, roundKeys, nil
}

// buildSlotMessage is a helper function which forms a slotted message to send to a gateway. It encrypts
// passed in message and generates an ephemeral ID for the recipient
func buildSlotMessage(msg format.Message, recipient *id.ID, rng *fastRNG.StreamGenerator, senderId *id.ID,
	bestRound *pb.RoundInfo, roundKeys *cmix.RoundKeys) (*pb.GatewaySlot, format.Message, ephemeral.Id, error) {

	stream := rng.GetStream()

	//set the ephemeral ID
	ephID, _, _, err := ephemeral.GetId(recipient,
		uint(bestRound.AddressSpaceSize),
		int64(bestRound.Timestamps[states.QUEUED]))
	if err != nil {
		jww.FATAL.Panicf("Failed to generate ephemeral ID when "+
			"sending to %s (msgDigest: %s):  %+v", err, recipient,
			msg.Digest())
	}

	ephIdFilled, err := ephID.Fill(uint(bestRound.AddressSpaceSize), stream)
	if err != nil {
		jww.FATAL.Panicf("Failed to obfuscate the ephemeralID when "+
			"sending to %s (msgDigest: %s): %+v", recipient, msg.Digest(),
			err)
	}
	stream.Close()

	msg.SetEphemeralRID(ephIdFilled[:])

	// set the identity fingerprint
	ifp, err := fingerprint.IdentityFP(msg.GetContents(), recipient)
	if err != nil {
		jww.FATAL.Panicf("failed to generate the Identity "+
			"fingerprint due to unrecoverable error when sending to %s "+
			"(msgDigest: %s): %+v", recipient, msg.Digest(), err)
	}

	msg.SetIdentityFP(ifp)

	//encrypt the message
	stream = rng.GetStream()
	salt := make([]byte, 32)
	_, err = stream.Read(salt)
	stream.Close()
	if err != nil {
		jww.ERROR.Printf("Failed to generate salt when sending to "+
			"%s (msgDigest: %s): %+v", recipient, msg.Digest(), err)
		return nil, format.Message{}, ephemeral.Id{}, errors.WithMessage(err,
			"Failed to generate salt, this should never happen")
	}
	encMsg, kmacs := roundKeys.Encrypt(msg, salt, id.Round(bestRound.ID))

	//build the message payload
	msgPacket := &pb.Slot{
		SenderID: senderId.Bytes(),
		PayloadA: encMsg.GetPayloadA(),
		PayloadB: encMsg.GetPayloadB(),
		Salt:     salt,
		KMACs:    kmacs,
	}

	//create the wrapper to the gateway
	slot := &pb.GatewaySlot{
		Message: msgPacket,
		RoundID: bestRound.ID,
	}
	//Add the mac proving ownership
	slot.MAC = roundKeys.MakeClientGatewayKey(salt,
		network.GenerateSlotDigest(slot))

	return slot, encMsg, ephID, nil
}

// Handles errors received from a PutMessage or a PutManyMessage network call
func handlePutMessageError(transmitGateway *connect.Host, instance *network.Instance, session *storage.Session,
	nodeRegistration chan network.NodeGateway, recipientString string, bestRound *pb.RoundInfo, err error) error {
	//if the comm errors or the message fails to send, continue retrying.
	//return if it sends properly
	if strings.Contains(err.Error(),
		"try a different round.") {
		jww.WARN.Printf("Failed to send to [%s] "+
			"due to round error with round %d, retrying: %+v",
			recipientString, bestRound.ID, err)
		return errors.New(recoverableError)
	} else if strings.Contains(err.Error(),
		"Could not authenticate client. Is the client registered "+
			"with this node?") {
		jww.WARN.Printf("Failed to send to %s "+
			"via %s due to failed authentication: %s",
			recipientString, transmitGateway.GetId(), err)
		//if we failed to send due to the gateway not recognizing our
		// authorization, renegotiate with the node to refresh it
		nodeID := transmitGateway.GetId().DeepCopy()
		nodeID.SetType(id.Node)
		//delete the keys
		session.Cmix().Remove(nodeID)
		//trigger
		go handleMissingNodeKeys(instance, nodeRegistration, []*id.ID{nodeID})
		return errors.New(recoverableError)
	}
	return errors.WithMessage(err, "Failed to put cmix message")

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

// Helper function which serializes a list of Ids into a
// printable format
func idListToString(idList []*id.ID) string {
	idString := ""
	for i := 0; i < len(idList); i++ {
		if i == len(idList) {
			idString += idList[i].String()
		} else {
			idString += idList[i].String() + ", "
		}
	}

	return idString
}

// Helper function which serializes a list of ephemeral Ids into a
// printable format
func ephemeralIdListToString(idList []ephemeral.Id) string {
	idString := ""
	for i := 0; i < len(idList); i++ {
		ephIdStr := strconv.FormatInt(idList[i].Int64(), 10)
		if i == len(idList) {
			idString += ephIdStr
		} else {
			idString += ephIdStr + ", "
		}
	}

	return idString

}

// buildMessageDigestString is a helper function which serializes
// a list of messages, returning their digests in a printable format
func buildMessageDigestString(messages []format.Message) string {
	messageDigestString := ""
	for i := 0; i < len(messages); i++ {
		if i == len(messages) {
			messageDigestString += messages[i].Digest()
		} else {
			messageDigestString += messages[i].Digest() + ", "
		}
	}
	return messageDigestString
}
