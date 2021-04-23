///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gitlab.com/xx_network/primitives/id"
	"reflect"
	"testing"
	"time"
)

// Unit test of newInternalMsg.
func Test_newInternalMsg(t *testing.T) {
	externalPayloadSize := 2 * internalMinSize
	im, err := newInternalMsg(externalPayloadSize)
	if err != nil {
		t.Errorf("newInternalMsg() returned an error: %+v", err)
	}

	if len(im.data) != externalPayloadSize {
		t.Errorf("newInternalMsg() set data to the wrong length."+
			"\nexpected: %d\nreceived: %d", externalPayloadSize, len(im.data))
	}
}

// Error path: the externalPayloadSize is smaller than the minimum size.
func Test_newInternalMsg_PayloadSizeError(t *testing.T) {
	externalPayloadSize := internalMinSize - 1
	expectedErr := fmt.Sprintf(newInternalSizeErr, externalPayloadSize, internalMinSize)

	_, err := newInternalMsg(externalPayloadSize)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("newInternalMsg() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Unit test of mapInternalMsg.
func Test_mapInternalMsg(t *testing.T) {
	// Create all the expected data
	timestamp := make([]byte, timestampSize)
	binary.LittleEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	senderID := id.NewIdFromString("test sender ID", id.User, t).Marshal()
	payload := []byte("Sample payload contents.")
	size := make([]byte, payloadSizeSize)
	binary.LittleEndian.PutUint16(size, uint16(len(payload)))

	// Construct data into single slice
	data := bytes.NewBuffer(nil)
	data.Write(timestamp)
	data.Write(senderID)
	data.Write(size)
	data.Write(payload)

	// Map data
	im := mapInternalMsg(data.Bytes())

	// Check that the mapped values match the expected values
	if !bytes.Equal(timestamp, im.timestamp) {
		t.Errorf("mapInternalMsg() did not correctly map timestamp."+
			"\nexpected: %+v\nreceived: %+v", timestamp, im.timestamp)
	}

	if !bytes.Equal(senderID, im.senderID) {
		t.Errorf("mapInternalMsg() did not correctly map senderID."+
			"\nexpected: %+v\nreceived: %+v", senderID, im.senderID)
	}

	if !bytes.Equal(size, im.size) {
		t.Errorf("mapInternalMsg() did not correctly map size."+
			"\nexpected: %+v\nreceived: %+v", size, im.size)
	}

	if !bytes.Equal(payload, im.payload) {
		t.Errorf("mapInternalMsg() did not correctly map payload."+
			"\nexpected: %+v\nreceived: %+v", payload, im.payload)
	}
}

// Tests that a marshaled and unmarshalled internalMsg matches the original.
func TestInternalMsg_Marshal_unmarshalInternalMsg(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)
	im.SetTimestamp(time.Now())
	im.SetSenderID(id.NewIdFromString("test sender ID", id.User, t))
	_ = im.SetPayload([]byte("Sample payload message."))

	data := im.Marshal()

	newIm, err := unmarshalInternalMsg(data)
	if err != nil {
		t.Errorf("unmarshalInternalMsg() returned an error: %+v", err)
	}

	if !reflect.DeepEqual(im, newIm) {
		t.Errorf("unmarshalInternalMsg() did not return the expected internalMsg."+
			"\nexpected: %s\nreceived: %s", im, newIm)
	}
}

// Error path: error is returned when the data is too short.
func Test_unmarshalInternalMsg_DataLengthError(t *testing.T) {
	expectedErr := fmt.Sprintf(unmarshalInternalSizeErr, 0, internalMinSize)

	_, err := unmarshalInternalMsg(nil)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("unmarshalInternalMsg() failed to return the expected error"+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func TestInternalMsg_SetTimestamp_GetTimestamp(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)
	timestamp := time.Now()
	im.SetTimestamp(timestamp)
	testTimestamp := im.GetTimestamp()

	if !timestamp.Equal(testTimestamp) {
		t.Errorf("Failed to get original timestamp."+
			"\nexpected: %s\nreceived: %s", timestamp, testTimestamp)
	}
}

// Happy path.
func TestInternalMsg_SetSenderID_GetSenderID(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)
	sid := id.NewIdFromString("testSenderID", id.User, t)
	im.SetSenderID(sid)
	testID, err := im.GetSenderID()
	if err != nil {
		t.Errorf("GetSenderID() returned an error: %+v", err)
	}

	if !sid.Cmp(testID) {
		t.Errorf("Failed to get original sender ID."+
			"\nexpected: %s\nreceived: %s", sid, testID)
	}
}

// Tests that the original payload matches the saved one.
func TestInternalMsg_SetPayload_GetPayload(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)
	payload := []byte("Test payload message.")
	err := im.SetPayload(payload)
	if err != nil {
		t.Errorf("SetPayload() returned an error: %+v", err)
	}
	testPayload := im.GetPayload()

	if !bytes.Equal(payload, testPayload) {
		t.Errorf("Failed to get original sender payload."+
			"\nexpected: %s\nreceived: %s", payload, testPayload)
	}
}

// Error path: error is returned if the data is larger than the payload in the
// message.
func TestInternalMsg_SetPayload_PayloadDataTooLarge(t *testing.T) {
	expectedErr := fmt.Sprintf(setInternalPayloadLenErr, len(payload), len(im.payload))
}

// Happy path.
func TestInternalMsg_GetPayloadSize(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)
	payload := []byte("Test payload message.")
	err := im.SetPayload(payload)
	if err != nil {
		t.Errorf("SetPayload() returned an error: %+v", err)
	}

	if len(payload) != im.GetPayloadSize() {
		t.Errorf("GetPayloadSize() failed to return the correct size."+
			"\nexpected: %d\nreceived: %d", len(payload), im.GetPayloadSize())
	}
}

// Happy path.
func TestInternalMsg_GetPayloadMaxSize(t *testing.T) {
	im, _ := newInternalMsg(internalMinSize * 2)

	if internalMinSize != im.GetPayloadMaxSize() {
		t.Errorf("GetPayloadMaxSize() failed to return the correct size."+
			"\nexpected: %d\nreceived: %d", internalMinSize, im.GetPayloadMaxSize())
	}
}
