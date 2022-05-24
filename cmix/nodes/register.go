///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"gitlab.com/xx_network/crypto/csprng"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/cmix/gateway"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/ndf"
)

func registerNodes(r *registrar, s storage.Session, stop *stoppable.Single,
	inProgress, attempts *sync.Map) {

	interval := time.Duration(500) * time.Millisecond
	t := time.NewTicker(interval)
	for {
		select {
		case <-stop.Quit():
			t.Stop()
			stop.ToStopped()
			return

		case gw := <-r.c:
			rng := r.rng.GetStream()
			nidStr := hex.EncodeToString(gw.Node.ID)
			nid, err := gw.Node.GetNodeId()
			if err != nil {
				jww.WARN.Printf(
					"Could not process node ID for registration: %s", err)
				continue
			}

			if r.HasNode(nid) {
				jww.INFO.Printf(
					"Not registering node %s, already registered", nid)
			}

			if _, operating := inProgress.LoadOrStore(nidStr,
				struct{}{}); operating {
				continue
			}

			// Keep track of how many times this has been attempted
			numAttempts := uint(1)
			if nunAttemptsInterface, hasValue := attempts.LoadOrStore(
				nidStr, numAttempts); hasValue {
				numAttempts = nunAttemptsInterface.(uint)
				attempts.Store(nidStr, numAttempts+1)
			}

			// No need to register with stale nodes
			if isStale := gw.Node.Status == ndf.Stale; isStale {
				jww.DEBUG.Printf(
					"Skipping registration with stale nodes %s", nidStr)
				continue
			}
			err = registerWithNode(r.sender, r.comms, gw, s, r, rng, stop)
			inProgress.Delete(nidStr)
			if err != nil {
				jww.ERROR.Printf("Failed to register nodes: %+v", err)
				// If we have not reached the attempt limit for this gateway,
				// then send it back into the channel to retry
				if numAttempts < maxAttempts {
					go func() {
						// Delay the send for a backoff
						time.Sleep(delayTable[numAttempts-1])
						r.c <- gw
					}()
				}
			}
			rng.Close()
		case <-t.C:
		}
	}
}

// registerWithNode serves as a helper for registerNodes. It registers a user
// with a specific in the client's NDF.
func registerWithNode(sender gateway.Sender, comms RegisterNodeCommsInterface,
	ngw network.NodeGateway, s Session, r *registrar,
	rng csprng.Source, stop *stoppable.Single) error {

	nodeID, err := ngw.Node.GetNodeId()
	if err != nil {
		jww.ERROR.Printf("registerWithNode failed to decode node ID: %v", err)
		return err
	}

	if r.HasNode(nodeID) {
		return nil
	}

	jww.INFO.Printf("registerWithNode begin registration with node: %s",
		nodeID)

	var transmissionKey *cyclic.Int
	var validUntil uint64
	var keyId []byte
	// TODO: should move this to a pre-canned user initialization
	if s.IsPrecanned() {
		userNum := int(s.GetTransmissionID().Bytes()[7])
		h := sha256.New()
		h.Reset()
		h.Write([]byte(strconv.Itoa(4000 + userNum)))

		transmissionKey = r.session.GetCmixGroup().NewIntFromBytes(h.Sum(nil))
		jww.INFO.Printf("transmissionKey: %v", transmissionKey.Bytes())
	} else {
		// Request key from server
		transmissionKey, keyId, validUntil, err = requestKey(
			sender, comms, ngw, s, r, rng, stop)

		if err != nil {
			return errors.Errorf("Failed to request key: %+v", err)
		}

	}

	r.add(nodeID, transmissionKey, validUntil, keyId)

	jww.INFO.Printf("Completed registration with node %s", nodeID)

	return nil
}
