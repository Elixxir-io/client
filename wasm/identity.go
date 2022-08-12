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

////////////////////////////////////////////////////////////////////////////////
// ReceptionIdentity                                                          //
////////////////////////////////////////////////////////////////////////////////

// StoreReceptionIdentity stores the given identity in Cmix storage with the
// given key. This is the ideal way to securely store identities, as the caller
// of this function is only required to store the given key separately rather
// than the keying material.
//
// Parameters:
//  - args[0] - storage key (string)
//  - args[1] - JSON of the [xxdk.ReceptionIdentity] object (string)
//  - args[2] - ID of Cmix object in tracker (int)
//
// Returns:
//  - error
func StoreReceptionIdentity(_ js.Value, args []js.Value) interface{} {
	return bindings.StoreReceptionIdentity(
		args[0].String(), []byte(args[1].String()), args[2].Int())
}

// LoadReceptionIdentity loads the given identity in Cmix storage with the given
// key.
//
// Parameters:
//  - args[0] - storage key (string)
//  - args[1] - ID of Cmix object in tracker (int)
//
// Returns:
//  - JSON of the stored [xxdk.ReceptionIdentity] object (string) or an error
func LoadReceptionIdentity(_ js.Value, args []js.Value) interface{} {
	ri, err := bindings.LoadReceptionIdentity(args[0].String(), args[1].Int())
	if err != nil {
		return err
	}

	return ri
}

// MakeReceptionIdentity generates a new cryptographic identity for receiving
// messages.
//
// Returns:
//  - JSON of the [xxdk.ReceptionIdentity] object (string) or an error
func (c *Cmix) MakeReceptionIdentity(js.Value, []js.Value) interface{} {
	ri, err := c.c.MakeReceptionIdentity()
	if err != nil {
		return err
	}

	return ri
}

// MakeLegacyReceptionIdentity generates the legacy identity for receiving
// messages.
//
// Returns:
//  - JSON of the [xxdk.ReceptionIdentity] object (string) or an error
func (c *Cmix) MakeLegacyReceptionIdentity(js.Value, []js.Value) interface{} {
	ri, err := c.c.MakeLegacyReceptionIdentity()
	if err != nil {
		return err
	}

	return ri
}

// GetReceptionRegistrationValidationSignature returns the signature provided by
// the xx network.
//
// Returns:
//  - signature (string)
func (c *Cmix) GetReceptionRegistrationValidationSignature(js.Value, []js.Value) interface{} {
	return c.c.GetReceptionRegistrationValidationSignature()
}

////////////////////////////////////////////////////////////////////////////////
// Contact Functions                                                          //
////////////////////////////////////////////////////////////////////////////////

// GetIDFromContact returns the ID in the [contact.Contact] object.
//
// Parameters:
//  - args[0] - JSON marshalled bytes of [contact.Contact] (string)
//
// Returns:
//  - bytes of the [id.ID] object or error
func GetIDFromContact(_ js.Value, args []js.Value) interface{} {
	cID, err := bindings.GetIDFromContact([]byte(args[0].String()))
	if err != nil {
		return err
	}

	return cID
}

// GetPubkeyFromContact returns the DH public key in the [contact.Contact]
// object.
//
// Parameters:
//  - args[0] - JSON of [contact.Contact] (string)
//
// Returns:
//  - bytes of the [cyclic.Int] object or error
func GetPubkeyFromContact(_ js.Value, args []js.Value) interface{} {
	key, err := bindings.GetPubkeyFromContact([]byte(args[0].String()))
	if err != nil {
		return err
	}

	return key
}

////////////////////////////////////////////////////////////////////////////////
// Fact Functions                                                             //
////////////////////////////////////////////////////////////////////////////////

// SetFactsOnContact replaces the facts on the contact with the passed in facts
// pass in empty facts in order to clear the facts.
//
// Parameters:
//  - args[0] - JSON of [contact.Contact] (string)
//  - args[1] - JSON of [fact.FactList] (string)
//
// Returns:
//  - marshalled bytes of the modified [contact.Contact] (string) or error
func SetFactsOnContact(_ js.Value, args []js.Value) interface{} {
	c, err := bindings.SetFactsOnContact(
		[]byte(args[0].String()), []byte(args[1].String()))
	if err != nil {
		return err
	}

	return c
}

// GetFactsFromContact returns the fact list in the [contact.Contact] object.
//
// Parameters:
//  - args[0] - JSON of [contact.Contact] (string)
//
// Returns:
//  - JSON of [fact.FactList] (string) or error
func GetFactsFromContact(_ js.Value, args []js.Value) interface{} {
	fl, err := bindings.GetFactsFromContact([]byte(args[0].String()))
	if err != nil {
		return err
	}

	return fl
}
