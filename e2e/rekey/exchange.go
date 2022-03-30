///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package rekey

import (
	"gitlab.com/elixxir/client/catalog"
	"gitlab.com/elixxir/client/e2e/ratchet"
	"gitlab.com/elixxir/client/e2e/receive"
	"gitlab.com/elixxir/client/network"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/e2e"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

const keyExchangeTriggerName = "KeyExchangeTrigger"
const keyExchangeConfirmName = "KeyExchangeConfirm"
const keyExchangeMulti = "KeyExchange"

type E2eSender func(mt catalog.MessageType, recipient *id.ID, payload []byte,
	cmixParams network.CMIXParams) (
	[]id.Round, e2e.MessageID, time.Time, error)

func Start(switchboard *receive.Switchboard, ratchet *ratchet.Ratchet,
	sender E2eSender, net network.Manager, grp *cyclic.Group, params Params) (stoppable.Stoppable, error) {

	// register the rekey trigger thread
	triggerCh := make(chan receive.Message, 100)
	triggerID := switchboard.RegisterChannel(keyExchangeTriggerName,
		&id.ID{}, catalog.KeyExchangeTrigger, triggerCh)

	// create the trigger stoppable
	triggerStop := stoppable.NewSingle(keyExchangeTriggerName)

	cleanupTrigger := func() {
		switchboard.Unregister(triggerID)
	}

	// start the trigger thread
	go startTrigger(ratchet, sender, net, grp, triggerCh, triggerStop, params,
		cleanupTrigger)

	//register the rekey confirm thread
	confirmCh := make(chan receive.Message, 100)
	confirmID := switchboard.RegisterChannel(keyExchangeConfirmName,
		&id.ID{}, catalog.KeyExchangeConfirm, confirmCh)

	// register the confirm stoppable
	confirmStop := stoppable.NewSingle(keyExchangeConfirmName)
	cleanupConfirm := func() {
		switchboard.Unregister(confirmID)
	}

	// start the confirm thread
	go startConfirm(ratchet, confirmCh, confirmStop, cleanupConfirm)

	//bundle the stoppables and return
	exchangeStop := stoppable.NewMulti(keyExchangeMulti)
	exchangeStop.Add(triggerStop)
	exchangeStop.Add(confirmStop)
	return exchangeStop, nil
}