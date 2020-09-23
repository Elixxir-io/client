////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package health

import (
	//	"gitlab.com/elixxir/comms/network"
	"testing"
	"time"
)

func TestNewTracker(t *testing.T) {
	tracker := newTracker(1 * time.Second)
	//hbChan := tracker.heartbeat
	counter := 0

	// positiveHb := network.Heartbeat{
	// 	HasWaitingRound: true,
	// 	IsRoundComplete: true,
	// }
	// negativeHb := network.Heartbeat{
	// 	HasWaitingRound: false,
	// 	IsRoundComplete: false,
	// }

	listenChan := make(chan bool)
	listenFunc := func(isHealthy bool) {
		counter++
	}
	tracker.AddChannel(listenChan)
	tracker.AddFunc(listenFunc)
	go func() {
		for range listenChan {
			counter++
		}
	}()

	quit := make(chan struct{})
	go tracker.start(quit)
}
