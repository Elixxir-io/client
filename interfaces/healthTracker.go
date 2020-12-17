///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package interfaces

type HealthTracker interface {
	AddChannel(chan bool)
	AddFunc(f func(bool))
	IsHealthy() bool
}
