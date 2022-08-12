////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

//go:build js
// +build js

package wasm

import (
	"gitlab.com/elixxir/client/bindings"
	"syscall/js"
)

// Cmix wraps the bindings.Cmix object so its methods can be wrapped to be
// Javascript compatible.
type Cmix struct {
	c *bindings.Cmix
}

// newCmixJS creates a new Javascript compatible object (map[string]interface{})
// that matches the Cmix structure.
func newCmixJS(net *bindings.Cmix) map[string]interface{} {
	c := Cmix{net}
	cmix := map[string]interface{}{
		"id":                          c.c.GetID(),
		"GetID":                       js.FuncOf(c.GetID),
		"MakeReceptionIdentity":       js.FuncOf(c.MakeReceptionIdentity),
		"MakeLegacyReceptionIdentity": js.FuncOf(c.MakeLegacyReceptionIdentity),
	}

	return cmix
}

// NewCmix creates user storage, generates keys, connects, and registers with
// the network. Note that this does not register a username/identity, but merely
// creates a new cryptographic identity for adding such information at a later
// date.
//
// Users of this function should delete the storage directory on error.
//
// Parameters:
//  - args[0] - NDF JSON (string)
//  - args[1] - storage directory path (string)
//  - args[2] - password used for storage (string)
//  - args[3] - registration code (string)
//
// Returns:
//  - error
func NewCmix(_ js.Value, args []js.Value) interface{} {
	return bindings.NewCmix(args[0].String(), args[1].String(),
		[]byte(args[2].String()), args[3].String())
}

// LoadCmix will load an existing user storage from the storageDir using the
// password. This will fail if the user storage does not exist or the password
// is incorrect.
//
// The password is passed as a byte array so that it can be cleared from memory
// and stored as securely as possible using the MemGuard library.
//
// LoadCmix does not block on network connection and instead loads and starts
// subprocesses to perform network operations.
//
// Parameters:
//  - args[0] - storage directory path (string)
//  - args[1] - password used for storage (string)
//  - args[2] - JSON of [xxdk.CMIXParams] (string)
//
// Returns:
//  - Javascript representation of the [bindings.Cmix] object or an error
func LoadCmix(_ js.Value, args []js.Value) interface{} {
	net, err := bindings.LoadCmix(args[0].String(),
		[]byte(args[1].String()), []byte(args[2].String()))
	if err != nil {
		return err
	}

	return newCmixJS(net)
}

// GetID returns the ID for this [bindings.Cmix] in the cmixTracker.
//
// Returns:
//  - int of the ID
func (c *Cmix) GetID(js.Value, []js.Value) interface{} {
	return c.c.GetID()
}