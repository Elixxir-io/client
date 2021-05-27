///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package rounds

import (
	"gitlab.com/elixxir/client/network/gateway"
	"gitlab.com/elixxir/client/network/message"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/ndf"
	"reflect"
	"testing"
	"time"
)

// Happy path
func TestUncheckedRoundScheduler(t *testing.T) {
	// General initializations
	testManager := newManager(t)
	roundId := id.Round(5)
	mockComms := &mockMessageRetrievalComms{testingSignature: t}
	quitChan := make(chan struct{})
	testNdf := getNDF()
	nodeId := id.NewIdFromString(ReturningGateway, id.Node, &testing.T{})
	gwId := nodeId.DeepCopy()
	gwId.SetType(id.Gateway)
	testNdf.Gateways = []ndf.Gateway{{ID: gwId.Marshal()}}
	p := gateway.DefaultPoolParams()
	p.MaxPoolSize = 1
	testManager.sender, _ = gateway.NewSender(p,
		fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG),
		testNdf, mockComms, testManager.Session, nil)

	// Create a local channel so reception is possible (testManager.messageBundles is
	// send only via newManager call above)
	messageBundleChan := make(chan message.Bundle)
	testManager.messageBundles = messageBundleChan

	testBackoffTable := newTestBackoffTable(t)
	checkInterval := 250 * time.Millisecond
	// Initialize the message retrieval
	go testManager.processMessageRetrieval(mockComms, quitChan)
	go testManager.processUncheckedRounds(checkInterval, testBackoffTable, quitChan)

	requestGateway := id.NewIdFromString(ReturningGateway, id.Gateway, t)

	// Construct expected values for checking
	expectedEphID := ephemeral.Id{1, 2, 3, 4, 5, 6, 7, 8}
	idList := [][]byte{requestGateway.Bytes()}
	roundInfo := &pb.RoundInfo{
		ID:       uint64(roundId),
		Topology: idList,
	}

	// Add round ot check
	err := testManager.Session.UncheckedRounds().AddRound(roundInfo, expectedEphID, requestGateway)
	if err != nil {
		t.Fatalf("Could not add round to session: %v", err)
	}

	var testBundle message.Bundle
	go func() {
		// Receive the bundle over the channel
		time.Sleep(1 * time.Second)
		testBundle = <-messageBundleChan

		// Close the process
		quitChan <- struct{}{}

	}()

	// Ensure bundle received and has expected values
	time.Sleep(2 * time.Second)
	if reflect.DeepEqual(testBundle, message.Bundle{}) {
		t.Fatalf("Did not receive a message bundle over the channel")
	}

	if testBundle.Identity.EphId.Int64() != expectedEphID.Int64() {
		t.Errorf("Unexpected ephemeral ID in bundle."+
			"\n\tExpected: %v"+
			"\n\tReceived: %v", expectedEphID, testBundle.Identity.EphId)
	}

	_, exists := testManager.Session.UncheckedRounds().GetRound(roundId)
	if exists {
		t.Fatalf("Expected round %d to be removed after being processed", roundId)
	}

}
