////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer2

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/fileTransfer2/store"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/xx_network/crypto/csprng"
	"go.uber.org/ratelimit"
	"time"
)

const (
	// Duration to wait before adding a partially filled part packet to the send
	// channel.
	unfilledPacketTimeout = 100 * time.Millisecond
)

// batchBuilderThread creates batches of file parts as they become available and
// buffer them to send. Also rate limits adding to the buffer.
func (m *manager) batchBuilderThread(stop *stoppable.Single) {
	// Calculate the average amount of data sent via SendManyCMIX
	avgNumMessages := (minPartsSendPerRound + maxPartsSendPerRound) / 2
	avgSendSize := avgNumMessages * 8192

	// Calculate the rate (sends per second) to achieve the desired bandwidth
	rate := 1
	if m.params.MaxThroughput > avgSendSize {
		rate = m.params.MaxThroughput / avgSendSize
	}

	// Calculate rate and make rate limiter if max throughput is set
	rl := ratelimit.NewUnlimited()
	if m.params.MaxThroughput > 0 {
		jww.INFO.Printf("[FT] Max throughput is %d. "+
			"File transfer will be rate limited to %d parts per second.",
			m.params.MaxThroughput, rate)
		rl = ratelimit.New(rate, ratelimit.WithoutSlack)
	} else {
		jww.WARN.Printf("[FT] Max throughput is %d. "+
			"File transfer will not be rate limited.", m.params.MaxThroughput)
	}

	for {
		numParts := generateRandomPacketSize(m.rng)
		packet := make([]store.Part, 0, numParts)
		delayedTimer := NewDelayedTimer(unfilledPacketTimeout)
	loop:
		for cap(packet) > len(packet) {
			select {
			case <-stop.Quit():
				delayedTimer.Stop()
				jww.DEBUG.Printf("[FT] Stopping file part packing thread " +
					"while packing: stoppable triggered.")
				stop.ToStopped()
				return
			case <-*delayedTimer.C:
				break loop
			case p := <-m.batchQueue:
				packet = append(packet, p)
				delayedTimer.Start()
			}
		}

		// Rate limiter
		rl.Take()
		m.sendQueue <- packet
	}
}

// generateRandomPacketSize returns a random number between minPartsSendPerRound
// and maxPartsSendPerRound, inclusive.
func generateRandomPacketSize(rngGen *fastRNG.StreamGenerator) int {
	rng := rngGen.GetStream()
	defer rng.Close()

	// Generate random bytes
	b, err := csprng.Generate(8, rng)
	if err != nil {
		jww.FATAL.Panicf(getRandomNumPartsRandPanic, err)
	}

	// Convert bytes to integer
	num := binary.LittleEndian.Uint64(b)

	// Return random number that is minPartsSendPerRound <= num <= max
	return int((num % (maxPartsSendPerRound)) + minPartsSendPerRound)
}