///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package network

// follow.go tracks the network for:
//   1. The status of the network and its accessibility
//   2. New/Active/Complete rounds and their contact gateways
//   3. Node addition and removal
// This information is tracked by polling a gateway for the network definition
// file (NDF). Once it detects an event it sends it off to the proper channel
// for a worker to update the client state (add/remove a node, check for
// messages at a gateway, etc). See:
//   - /node/register.go for add/remove node events
//   - /rounds/historical.go for old round retrieval
//   - /rounds/retrieve.go for message retrieval
//   - /message/handle.go decryption, partitioning, and signaling of messages
//   - /health/tracker.go - tracks the state of the network through the network
//		instance

import (
	"bytes"
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/interfaces"
	"gitlab.com/elixxir/client/network/rounds"
	"gitlab.com/elixxir/client/stoppable"
	rounds2 "gitlab.com/elixxir/client/storage/rounds"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/primitives/knownRounds"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"sync/atomic"
	"time"
)

const (
	debugTrackPeriod = 1 * time.Minute

	// Estimate the number of rounds per second in the network. Will need updated someday
	// in order to correctly determine how far back to search rounds for messages
	// as the network continues to grow, otherwise message drops occur.
	estimatedRoundsPerSecond = 5
)

//comms interface makes testing easier
type followNetworkComms interface {
	GetHost(hostId *id.ID) (*connect.Host, bool)
	SendPoll(host *connect.Host, message *pb.GatewayPoll) (*pb.GatewayPollResponse, error)
}

// followNetwork polls the network to get updated on the state of nodes, the
// round status, and informs the client when messages can be retrieved.
func (m *manager) followNetwork(report interfaces.ClientErrorReport,
	stop *stoppable.Single) {
	ticker := time.NewTicker(m.param.TrackNetworkPeriod)
	TrackTicker := time.NewTicker(debugTrackPeriod)
	rng := m.Rng.GetStream()

	abandon := func(round id.Round) { return }
	if m.verboseRounds != nil {
		abandon = func(round id.Round) {
			m.verboseRounds.denote(round, Abandoned)
		}
	}

	for {
		select {
		case <-stop.Quit():
			rng.Close()
			stop.ToStopped()
			return
		case <-ticker.C:
			m.follow(report, rng, m.Comms, stop, abandon)
		case <-TrackTicker.C:
			numPolls := atomic.SwapUint64(m.tracker, 0)
			if m.numLatencies != 0 {
				latencyAvg := time.Nanosecond * time.Duration(
					m.latencySum/m.numLatencies)
				m.latencySum, m.numLatencies = 0, 0

				infoMsg := fmt.Sprintf("Polled the network "+
					"%d times in the last %s, with an "+
					"average newest packet latency of %s",
					numPolls, debugTrackPeriod, latencyAvg)

				jww.INFO.Printf(infoMsg)
				m.Internal.Events.Report(1, "Polling",
					"MetricsWithLatency", infoMsg)
			} else {
				infoMsg := fmt.Sprintf("Polled the network "+
					"%d times in the last %s", numPolls,
					debugTrackPeriod)

				jww.INFO.Printf(infoMsg)
				m.Internal.Events.Report(1, "Polling",
					"Metrics", infoMsg)
			}
		}
	}
}

// executes each iteration of the follower
func (m *manager) follow(report interfaces.ClientErrorReport, rng csprng.Source,
	comms followNetworkComms, stop *stoppable.Single, abandon func(round id.Round)) {

	//Get the identity we will poll for
	identity, err := m.Session.Reception().GetIdentity(rng, m.addrSpace.GetWithoutWait())
	if err != nil {
		jww.FATAL.Panicf("Failed to get an identity, this should be "+
			"impossible: %+v", err)
	}

	// While polling with a fake identity, it is necessary to have
	// populated earliestRound data. However, as with fake identities
	// we want the values to be randomly generated rather than based on
	// actual state.
	if identity.Fake {
		fakeEr := &rounds2.EarliestRound{}
		fakeEr.Set(m.GetFakeEarliestRound())
		identity.ER = fakeEr
	}

	atomic.AddUint64(m.tracker, 1)

	// Get client version for poll
	version := m.Session.GetClientVersion()

	// Poll network updates
	pollReq := pb.GatewayPoll{
		Partial: &pb.NDFHash{
			Hash: m.Instance.GetPartialNdf().GetHash(),
		},
		LastUpdate:     uint64(m.Instance.GetLastUpdateID()),
		ReceptionID:    identity.EphId[:],
		StartTimestamp: identity.StartValid.UnixNano(),
		EndTimestamp:   identity.EndValid.UnixNano(),
		ClientVersion:  []byte(version.String()),
		FastPolling:    m.param.FastPolling,
		LastRound:      uint64(identity.ER.Get()),
	}

	result, err := m.GetSender().SendToAny(func(host *connect.Host) (interface{}, error) {
		jww.DEBUG.Printf("Executing poll for %v(%s) range: %s-%s(%s) from %s",
			identity.EphId.Int64(), identity.Source, identity.StartValid,
			identity.EndValid, identity.EndValid.Sub(identity.StartValid), host.GetId())
		return comms.SendPoll(host, &pollReq)
	}, stop)

	// Exit if the thread has been stopped
	if stoppable.CheckErr(err) {
		jww.INFO.Print(err)
		return
	}

	now := netTime.Now()

	if err != nil {
		if report != nil {
			report(
				"NetworkFollower",
				fmt.Sprintf("Failed to poll network, \"%s\":", err.Error()),
				fmt.Sprintf("%+v", err),
			)
		}
		errMsg := fmt.Sprintf("Unable to poll gateway: %+v", err)
		m.Internal.Events.Report(10, "Polling", "Error", errMsg)
		jww.ERROR.Printf(errMsg)
		return
	}

	pollResp := result.(*pb.GatewayPollResponse)

	// ---- Process Network State Update Data ----
	gwRoundsState := &knownRounds.KnownRounds{}
	err = gwRoundsState.Unmarshal(pollResp.KnownRounds)
	if err != nil {
		jww.ERROR.Printf("Failed to unmarshal: %+v", err)
		return
	}

	// ---- Node Events ----
	// NOTE: this updates the structure, AND sends events over the node
	//       update channels about new and removed nodes
	if pollResp.PartialNDF != nil {
		err = m.Instance.UpdatePartialNdf(pollResp.PartialNDF)
		if err != nil {
			jww.ERROR.Printf("Unable to update partial NDF: %+v", err)
			return
		}

		// update gateway connections
		m.GetSender().UpdateNdf(m.GetInstance().GetPartialNdf().Get())
		m.Session.SetNDF(m.GetInstance().GetPartialNdf().Get())
	}

	// Pull rate limiting parameter values from NDF
	ndfRateLimitParam := m.Instance.GetPartialNdf().Get().RateLimits
	ndfCapacity, ndfLeakedTokens, ndfLeakDuration := uint32(ndfRateLimitParam.Capacity),
		uint32(ndfRateLimitParam.LeakedTokens), time.Duration(ndfRateLimitParam.LeakDuration)

	// Pull internal rate limiting parameters from RAM
	internalRateLimitParams := m.Internal.Session.GetBucketParams().Get()

	// If any param value in our internal store does not
	// match the NDF's corresponding value, update our internal store
	if ndfCapacity != internalRateLimitParams.Capacity ||
		ndfLeakedTokens != internalRateLimitParams.LeakedTokens ||
		ndfLeakDuration != internalRateLimitParams.LeakDuration {
		// Update internally stored params
		err = m.Internal.Session.GetBucketParams().
			UpdateParams(ndfCapacity, ndfLeakedTokens, ndfLeakDuration)
		if err != nil {
			jww.ERROR.Printf("%+v", err)
			return
		}
	}

	// Update the address space size
	if len(m.Instance.GetPartialNdf().Get().AddressSpace) != 0 {
		m.addrSpace.Update(m.Instance.GetPartialNdf().Get().AddressSpace[0].Size)
	}

	// NOTE: this updates rounds and updates the tracking of the health of the network
	if pollResp.Updates != nil {
		// TODO: ClientErr needs to know the source of the error and it doesn't yet
		// Iterate over ClientErrors for each RoundUpdate
		for _, update := range pollResp.Updates {

			// Ignore irrelevant updates
			if update.State != uint32(states.COMPLETED) && update.State != uint32(states.FAILED) {
				continue
			}

			for _, clientErr := range update.ClientErrors {
				// If this Client appears in the ClientError
				if bytes.Equal(clientErr.ClientId, m.Session.GetUser().TransmissionID.Marshal()) {

					// Obtain relevant NodeGateway information
					nid, err := id.Unmarshal(clientErr.Source)
					if err != nil {
						jww.ERROR.Printf("Unable to get NodeID: %+v", err)
						return
					}
					nGw, err := m.Instance.GetNodeAndGateway(nid)
					if err != nil {
						jww.ERROR.Printf("Unable to get gateway: %+v", err)
						return
					}

					// Mutate the update to indicate failure due to a ClientError
					// FIXME: Should be able to trigger proper type of round event
					// FIXME: without mutating the RoundInfo. Signature also needs verified
					// FIXME: before keys are deleted
					update.State = uint32(states.FAILED)

					// delete all existing keys and trigger a re-registration with the relevant Node
					m.Session.Cmix().Remove(nid)
					m.Instance.GetAddGatewayChan() <- nGw
				}
			}
		}

		// Trigger RoundEvents for all polled updates, including modified rounds with ClientErrors
		err = m.Instance.RoundUpdates(pollResp.Updates)
		if err != nil {
			jww.ERROR.Printf("%+v", err)
			return
		}

		newestTS := uint64(0)
		for i := 0; i < len(pollResp.Updates[len(pollResp.Updates)-1].Timestamps); i++ {
			if pollResp.Updates[len(pollResp.Updates)-1].Timestamps[i] != 0 {
				newestTS = pollResp.Updates[len(pollResp.Updates)-1].Timestamps[i]
			}
		}

		newest := time.Unix(0, int64(newestTS))

		if newest.After(now) {
			deltaDur := newest.Sub(now)
			m.latencySum = uint64(deltaDur)
			m.numLatencies++
		}
	}

	// ---- Identity Specific Round Processing -----
	if identity.Fake {
		jww.DEBUG.Printf("not processing result, identity.Fake == true")
		return
	}

	if len(pollResp.Filters.Filters) == 0 {
		jww.WARN.Printf("No filters found for the passed ID %d (%s), "+
			"skipping processing.", identity.EphId.Int64(), identity.Source)
		return
	}

	//prepare the filter objects for processing
	filterList := make([]*rounds.RemoteFilter, 0, len(pollResp.Filters.Filters))
	for i := range pollResp.Filters.Filters {
		if len(pollResp.Filters.Filters[i].Filter) != 0 {
			filterList = append(filterList, rounds.NewRemoteFilter(pollResp.Filters.Filters[i]))
		}
	}

	// check rounds using the round checker function which determines if there
	// are messages waiting in rounds and then sends signals to the appropriate
	// handling threads
	roundChecker := func(rid id.Round) bool {
		hasMessage := rounds.Checker(rid, filterList, identity.CR)
		if !hasMessage && m.verboseRounds != nil {
			m.verboseRounds.denote(rid, RoundState(NoMessageAvailable))
		}
		return hasMessage
	}

	// move the earliest unknown round tracker forward to the earliest
	// tracked round if it is behind
	earliestTrackedRound := id.Round(pollResp.EarliestRound)
	m.SetFakeEarliestRound(earliestTrackedRound)
	updatedEarliestRound, old, _ := identity.ER.Set(earliestTrackedRound)

	// If there was no registered rounds for the identity
	if old == 0 {
		lastCheckedRound := gwRoundsState.GetLastChecked()
		// Approximate the earliest possible round that messages could be received on this ID
		// by using an estimate of how many rounds the network runs per second
		roundsDelta := uint(time.Now().Sub(identity.StartValid) / time.Second * estimatedRoundsPerSecond)
		if roundsDelta < m.param.KnownRoundsThreshold {
			roundsDelta = m.param.KnownRoundsThreshold
		}
		if id.Round(roundsDelta) > lastCheckedRound {
			// Handles edge case for new networks to prevent starting at negative rounds
			updatedEarliestRound = 1
		} else {
			updatedEarliestRound = lastCheckedRound - id.Round(roundsDelta)
			earliestFilterRound := filterList[0].FirstRound() // Length of filterList always > 0
			// If the network appears to be moving faster than our estimate, causing
			// earliestFilterRound to be lower, we will instead use the earliestFilterRound
			// which will ensure messages are not dropped as long as contacted gateway has all data
			if updatedEarliestRound > earliestFilterRound {
				updatedEarliestRound = earliestFilterRound
			}
		}
		identity.ER.Set(updatedEarliestRound)
	}

	// loop through all rounds the client does not know about and the gateway
	// does, checking the bloom filter for the user to see if there are
	// messages for the user (bloom not implemented yet)
	//threshold is the earliest round that will not be excluded from earliest remaining
	earliestRemaining, roundsWithMessages, roundsUnknown := gwRoundsState.RangeUnchecked(updatedEarliestRound,
		m.param.KnownRoundsThreshold, roundChecker)
	jww.DEBUG.Printf("Processed RangeUnchecked, Oldest: %d, firstUnchecked: %d, "+
		"last Checked: %d, threshold: %d, NewEarliestRemaning: %d, NumWithMessages: %d, "+
		"NumUnknown: %d", updatedEarliestRound, gwRoundsState.GetFirstUnchecked(), gwRoundsState.GetLastChecked(),
		m.param.KnownRoundsThreshold, earliestRemaining, len(roundsWithMessages), len(roundsUnknown))

	_, _, changed := identity.ER.Set(earliestRemaining)
	if changed {
		jww.TRACE.Printf("External returns of RangeUnchecked: %d, %v, %v", earliestRemaining, roundsWithMessages, roundsUnknown)
		jww.DEBUG.Printf("New Earliest Remaining: %d, Gateways last checked: %d", earliestRemaining, gwRoundsState.GetLastChecked())
	}

	var roundsWithMessages2 []id.Round

	if !m.param.RealtimeOnly{
		roundsWithMessages2 = identity.UR.Iterate(func(rid id.Round) bool {
			if gwRoundsState.Checked(rid) {
				return rounds.Checker(rid, filterList, identity.CR)
			}
			return false
		}, roundsUnknown, abandon)
	}


	for _, rid := range roundsWithMessages {
		//denote that the round has been looked at in the tracking store
		if identity.CR.Check(rid) {
			m.round.GetMessagesFromRound(rid, identity)
		}
	}

	identity.CR.Prune()
	err = identity.CR.SaveCheckedRounds()
	if err != nil {
		jww.ERROR.Printf("Could not save rounds for identity %d (%s): %+v",
			identity.EphId.Int64(), identity.Source, err)
	}

	for _, rid := range roundsWithMessages2 {
		m.round.GetMessagesFromRound(rid, identity)
	}

	if m.verboseRounds != nil {
		trackingStart := updatedEarliestRound
		if uint(earliestRemaining-updatedEarliestRound) > m.param.KnownRoundsThreshold {
			trackingStart = earliestRemaining - id.Round(m.param.KnownRoundsThreshold)
		}
		jww.DEBUG.Printf("Rounds tracked: %v to %v", trackingStart, earliestRemaining)
		for i := trackingStart; i <= earliestRemaining; i++ {
			state := Unchecked
			for _, rid := range roundsWithMessages {
				if rid == i {
					state = MessageAvailable
				}
			}
			for _, rid := range roundsWithMessages2 {
				if rid == i {
					state = MessageAvailable
				}
			}
			for _, rid := range roundsUnknown {
				if rid == i {
					state = Unknown
				}
			}
			m.verboseRounds.denote(i, RoundState(state))
		}
	}

}
