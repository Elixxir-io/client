////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package switchboard

import (
	"gitlab.com/elixxir/client/context/message"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"testing"
	"time"
)

//verify func listener adheres to the listener interface
var _ Listener = &funcListener{}

//verify chan listener adheres to the listener interface
var _ Listener = &chanListener{}

//test listenerID returns the userID
func TestListenerID_GetUserID(t *testing.T) {
	lid := ListenerID{
		userID:      id.NewIdFromUInt(42, id.User, t),
		messageType: 42,
		listener:    nil,
	}

	if !lid.GetUserID().Cmp(lid.userID) {
		t.Errorf("Returned userID does not match")
	}
}

//test listenerID returns the messageType
func TestListenerID_GetMessageType(t *testing.T) {
	lid := ListenerID{
		userID:      id.NewIdFromUInt(42, id.User, t),
		messageType: 42,
		listener:    nil,
	}

	if lid.GetMessageType() != lid.messageType {
		t.Errorf("Returned message type does not match")
	}
}

//test listenerID returns the name
func TestListenerID_GetName(t *testing.T) {
	name := "test"

	lid := ListenerID{
		userID:      id.NewIdFromUInt(42, id.User, t),
		messageType: 42,
		listener:    newFuncListener(nil, name),
	}

	if lid.GetName() != name {
		t.Errorf("Returned name type does not match")
	}
}

//tests new function listener creates the funcListener properly
func TestNewFuncListener(t *testing.T) {
	f := func(item message.Receive) {}
	name := "test"
	listener := newFuncListener(f, name)

	if listener.listener == nil {
		t.Errorf("function is wrong")
	}

	if listener.name != name {
		t.Errorf("name is wrong")
	}
}

//tests FuncListener Hear works
func TestFuncListener_Hear(t *testing.T) {
	m := message.Receive{
		Payload:     []byte{0, 1, 2, 3},
		Sender:      id.NewIdFromUInt(42, id.User, t),
		MessageType: 69,
	}

	heard := make(chan message.Receive, 1)

	f := func(item message.Receive) {
		heard <- item
	}

	listener := newFuncListener(f, "test")

	listener.Hear(m)

	select {
	case item := <-heard:
		if !reflect.DeepEqual(item, m) {
			t.Errorf("Heard message did not match")
		}
	case <-time.After(5 * time.Millisecond):
		t.Errorf("Did not hear")
	}
}

// Test FuncListener returns the correct name
func TestFuncListener_Name(t *testing.T) {
	name := "test"
	listener := newFuncListener(nil, name)

	if listener.Name() != name {
		t.Errorf("Name did not match")
	}
}

//tests new chan listener creates the chanListener properly
func TestNewChanListener(t *testing.T) {
	c := make(chan message.Receive)
	name := "test"
	listener := newChanListener(c, name)

	if listener.listener == nil {
		t.Errorf("function is wrong")
	}

	if listener.name != name {
		t.Errorf("name is wrong")
	}
}

//tests ChanListener Hear works
func TestChanListener_Hear(t *testing.T) {
	m := message.Receive{
		Payload:     []byte{0, 1, 2, 3},
		Sender:      id.NewIdFromUInt(42, id.User, t),
		MessageType: 69,
	}

	heard := make(chan message.Receive, 1)

	listener := newChanListener(heard, "test")

	listener.Hear(m)

	select {
	case item := <-heard:
		if !reflect.DeepEqual(item, m) {
			t.Errorf("Heard message did not match")
		}
	case <-time.After(5 * time.Millisecond):
		t.Errorf("Did not hear")
	}
}

// Test FuncListener returns the correct name
func TestChanListener_Name(t *testing.T) {
	name := "test"
	listener := newChanListener(nil, name)

	if listener.Name() != name {
		t.Errorf("Name did not match")
	}
}
