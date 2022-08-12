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

// E2e wraps the bindings.E2e object so its methods can be wrapped to be
// Javascript compatible.
type E2e struct {
	e *bindings.E2e
}

// newE2eJS creates a new Javascript compatible object (map[string]interface{})
// that matches the E2e structure.
func newE2eJS(newE2E *bindings.E2e) map[string]interface{} {
	e := E2e{newE2E}
	e2e := map[string]interface{}{
		"id":                  e.e.GetID(),
		"GetID":               js.FuncOf(e.GetID),
		"GetContact":          js.FuncOf(e.GetContact),
		"GetUdAddressFromNdf": js.FuncOf(e.GetUdAddressFromNdf),
		"GetUdCertFromNdf":    js.FuncOf(e.GetUdCertFromNdf),
		"GetUdContactFromNdf": js.FuncOf(e.GetUdContactFromNdf),
	}

	return e2e
}

// GetID returns the ID for this [bindings.E2e] in the e2eTracker.
//
// Returns:
//  - int of the ID
func (e *E2e) GetID(js.Value, []js.Value) interface{} {
	return e.e.GetID()
}

// Login creates and returns a new E2e object and adds it to the
// e2eTrackerSingleton. Identity should be created via
// Cmix.MakeReceptionIdentity and passed in here. If callbacks is left nil, a
// default auth.Callbacks will be used.
//
// Parameters:
//  - args[0] - ID of Cmix object in tracker (int)
//  - args[1] - Javascript object matching [bindings.AuthCallbacks]
//  - args[2] - JSON of the [xxdk.ReceptionIdentity] object (string)
//  - args[3] - JSON of [xxdk.E2EParams] (string)
//
// Returns:
//  - Javascript representation of the [bindings.E2e] object or an error
func Login(_ js.Value, args []js.Value) interface{} {
	a := newAuthCallbacks(args[1])

	newE2E, err := bindings.Login(
		args[0].Int(), a, []byte(args[2].String()), []byte(args[3].String()))
	if err != nil {
		return err
	}

	return newE2eJS(newE2E)
}

// LoginEphemeral creates and returns a new ephemeral E2e object and adds it to
// the e2eTrackerSingleton. Identity should be created via
// Cmix.MakeReceptionIdentity or Cmix.MakeLegacyReceptionIdentity and passed in
// here. If callbacks is left nil, a default auth.Callbacks will be used.
//
// Parameters:
//  - args[0] - ID of Cmix object in tracker (int)
//  - args[1] - Javascript object matching [bindings.AuthCallbacks]
//  - args[2] - JSON of the [xxdk.ReceptionIdentity] object (string)
//  - args[3] - JSON of [xxdk.E2EParams] (string)
//
// Returns:
//  - Javascript representation of the [bindings.E2e] object or an error
func LoginEphemeral(_ js.Value, args []js.Value) interface{} {
	a := newAuthCallbacks(args[1])

	newE2E, err := bindings.LoginEphemeral(
		args[0].Int(), a, []byte(args[2].String()), []byte(args[3].String()))
	if err != nil {
		return err
	}

	return newE2eJS(newE2E)
}

// GetContact returns a [contact.Contact] object for the E2e ReceptionIdentity.
//
// Returns:
//  - JSON of [contact.Contact] ([]byte)
func (e *E2e) GetContact(js.Value, []js.Value) interface{} {
	return e.e.GetContact()
}

// GetUdAddressFromNdf retrieve the User Discovery's network address fom the
// NDF.
//
// Returns:
//  - User Discovery's address (string)
func (e *E2e) GetUdAddressFromNdf(js.Value, []js.Value) interface{} {
	return e.e.GetUdAddressFromNdf()
}

// GetUdCertFromNdf retrieves the User Discovery's TLS certificate from the NDF.
//
// Returns:
//  - public certificate in PEM format ([]byte)
func (e *E2e) GetUdCertFromNdf(js.Value, []js.Value) interface{} {
	return e.e.GetUdCertFromNdf()
}

// GetUdContactFromNdf assembles the User Discovery's contact file from the data
// within the NDF.
//
// Returns
//  - JSON of [contact.Contact] ([]byte)
func (e *E2e) GetUdContactFromNdf(js.Value, []js.Value) interface{} {
	b, err := e.e.GetUdContactFromNdf()
	if err != nil {
		return err
	}
	return b
}

////////////////////////////////////////////////////////////////////////////////
// Auth Callbacks                                                             //
////////////////////////////////////////////////////////////////////////////////

// authCallbacks wraps Javascript callbacks to adhere to the
// [bindings.AuthCallbacks] interface.
type authCallbacks struct {
	request func(args ...interface{}) js.Value
	confirm func(args ...interface{}) js.Value
	reset   func(args ...interface{}) js.Value
}

// newAuthCallbacks adds all the callbacks from the Javascript object. If a
// callback is not defined, it is skipped.
func newAuthCallbacks(value js.Value) *authCallbacks {
	a := &authCallbacks{}

	request := value.Get("Request")
	if !request.IsUndefined() {
		a.request = request.Invoke
	}

	confirm := value.Get("Confirm")
	if !confirm.IsUndefined() {
		a.confirm = confirm.Invoke
	}

	reset := value.Get("Reset")
	if !reset.IsUndefined() {
		a.confirm = reset.Invoke
	}

	return a
}

func (a *authCallbacks) Request(contact, receptionId []byte, ephemeralId, roundId int64) {
	if a.request != nil {
		a.request(contact, receptionId, ephemeralId, roundId)
	}
}

func (a *authCallbacks) Confirm(contact, receptionId []byte, ephemeralId, roundId int64) {
	if a.confirm != nil {
		a.confirm(contact, receptionId, ephemeralId, roundId)
	}

}
func (a *authCallbacks) Reset(contact, receptionId []byte, ephemeralId, roundId int64) {
	if a.reset != nil {
		a.reset(contact, receptionId, ephemeralId, roundId)
	}
}
