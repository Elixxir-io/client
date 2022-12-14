////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"bytes"
	"encoding/json"
	"gitlab.com/elixxir/client/cmix"
	"reflect"
	"testing"
)

// Tests that no data is lost when marshaling and unmarshalling the Params
// object.
func TestParams_MarshalUnmarshal(t *testing.T) {
	// Construct a set of params
	p := DefaultParams()

	// Marshal the params
	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Unmarshal the params object
	received := Params{}
	err = json.Unmarshal(data, &received)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	// Re-marshal this params object
	data2, err := json.Marshal(received)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Check that they match (it is done this way to avoid false failures with
	// the reflect.DeepEqual function and pointers)
	if !bytes.Equal(data, data2) {
		t.Fatalf("Data was lost in marshal/unmarshal.")
	}

}

// Tests that DefaultParams returns a Params object with the expected defaults.
func TestDefaultParams(t *testing.T) {
	expected := Params{
		MaxThroughput: defaultMaxThroughput,
		SendTimeout:   defaultSendTimeout,
		Cmix:          cmix.GetDefaultCMIXParams(),
	}
	received := DefaultParams()
	received.Cmix.Stop = expected.Cmix.Stop

	if !reflect.DeepEqual(expected, received) {
		t.Errorf("Received Params does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, received)
	}
}
