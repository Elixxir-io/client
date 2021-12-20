////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	ftCrypto "gitlab.com/elixxir/crypto/fileTransfer"
	"gitlab.com/xx_network/primitives/id"
)

// Error messages.
const (
	oldTransfersRoundResultsErr = "failed to recover round information for " +
		"%d rounds for old file transfers after %d attempts"
)

// roundResultsMaxAttempts is the maximum number of attempts to get round
// results via api.RoundEventCallback before stopping to try
const roundResultsMaxAttempts = 5

// oldTransferRecovery adds all unsent file parts back into the queue and
// updates the in-progress file parts by getting round updates.
func (m Manager) oldTransferRecovery(healthyChan chan bool) {

	// Exit if old transfers have already been recovered
	if m.oldTransfersRecovered {
		jww.DEBUG.Printf("Old file transfer recovery thread not starting: " +
			"none to recover (app was not closed)")
		return
	}

	// Get list of unsent parts and rounds that parts were sent on
	unsentParts, sentRounds := m.sent.GetUnsentPartsAndSentRounds()

	// Add all unsent parts to the queue
	for tid, partNums := range unsentParts {
		m.queueParts(tid, partNums)
	}

	// Update parts that were sent by looking up the status of the rounds they
	// were sent on
	go func() {
		err := m.updateSentRounds(healthyChan, sentRounds)
		if err != nil {
			jww.ERROR.Print(err)
		}
	}()
}

// updateSentRounds looks up the status of each round that parts were sent on
// but never arrived. It updates the status of each part depending on if the
// round failed or succeeded.
func (m Manager) updateSentRounds(healthyChan chan bool,
	sentRounds map[id.Round][]ftCrypto.TransferID) error {
	// Tracks the number of attempts to get round results
	var getRoundResultsAttempts int

	jww.DEBUG.Print("Starting old file transfer recovery thread.")

	// Wait for network to be healthy to attempt to get round states
	for getRoundResultsAttempts < roundResultsMaxAttempts {
		select {
		case healthy := <-healthyChan:
			// If the network is unhealthy, wait until it becomes healthy
			if !healthy {
				jww.DEBUG.Print("Suspending old file transfer recovery " +
					"thread: network is unhealthy.")
			}
			for !healthy {
				healthy = <-healthyChan
			}
			jww.DEBUG.Print("Old file transfer recovery thread: " +
				"network is healthy.")

			// Register callback to get Round results and retry on error
			roundList := roundIdMapToList(sentRounds)
			err := m.getRoundResults(roundList, roundResultsTimeout,
				m.makeRoundEventCallback(sentRounds))
			if err != nil {
				jww.WARN.Printf("Failed to get round results for old "+
					"transfers for rounds %d (attempt %d/%d): %+v",
					getRoundResultsAttempts, roundResultsMaxAttempts,
					roundList, err)
			} else {
				jww.INFO.Printf("Successfully recovered old file transfers.")
				return nil
			}
			getRoundResultsAttempts++
		}
	}

	return errors.Errorf(
		oldTransfersRoundResultsErr, len(sentRounds), getRoundResultsAttempts)
}

// roundIdMapToList returns a list of all round IDs in the map.
func roundIdMapToList(roundMap map[id.Round][]ftCrypto.TransferID) []id.Round {
	roundSlice := make([]id.Round, 0, len(roundMap))
	for rid := range roundMap {
		roundSlice = append(roundSlice, rid)
	}
	return roundSlice
}
