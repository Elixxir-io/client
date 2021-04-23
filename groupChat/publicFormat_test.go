package groupChat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"testing"
)

// Unit test of newPublicMsg.
func Test_newPublicMsg(t *testing.T) {
	maxDataSize := 2 * publicMinLen
	im, err := newPublicMsg(maxDataSize)
	if err != nil {
		t.Errorf("newPublicMsg() returned an error: %+v", err)
	}

	if len(im.data) != maxDataSize {
		t.Errorf("newPublicMsg() set data to the wrong length."+
			"\nexpected: %d\nreceived: %d", maxDataSize, len(im.data))
	}
}

// Error path: the maxDataSize is smaller than the minimum size.
func Test_newPublicMsg_PayloadSizeError(t *testing.T) {
	maxDataSize := publicMinLen - 1
	expectedErr := fmt.Sprintf(newPublicSizeErr, maxDataSize, publicMinLen)

	_, err := newPublicMsg(maxDataSize)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("newPublicMsg() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Unit test of mapPublicMsg.
func Test_mapPublicMsg(t *testing.T) {
	// Create all the expected data
	salt := make([]byte, saltLen)
	rand.New(rand.NewSource(42)).Read(salt)
	payload := []byte("Sample payload contents.")
	size := make([]byte, publicPayloadSizeLen)
	binary.LittleEndian.PutUint16(size, uint16(len(payload)))

	// Construct data into single slice
	data := bytes.NewBuffer(nil)
	data.Write(salt)
	data.Write(size)
	data.Write(payload)

	// Map data
	im := mapPublicMsg(data.Bytes())

	// Check that the mapped values match the expected values
	if !bytes.Equal(salt, im.salt) {
		t.Errorf("mapPublicMsg() did not correctly map salt."+
			"\nexpected: %+v\nreceived: %+v", salt, im.salt)
	}

	if !bytes.Equal(size, im.size) {
		t.Errorf("mapPublicMsg() did not correctly map size."+
			"\nexpected: %+v\nreceived: %+v", size, im.size)
	}

	if !bytes.Equal(payload, im.payload) {
		t.Errorf("mapPublicMsg() did not correctly map payload."+
			"\nexpected: %+v\nreceived: %+v", payload, im.payload)
	}
}

// Tests that a marshaled and unmarshalled publicMsg matches the original.
func Test_publicMsg_Marshal_unmarshalPublicMsg(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)
	salt := make([]byte, saltLen)
	rand.New(rand.NewSource(42)).Read(salt)
	pm.SetSalt(salt)
	_ = pm.SetPayload([]byte("Sample payload message."))

	data := pm.Marshal()

	newPm, err := unmarshalPublicMsg(data)
	if err != nil {
		t.Errorf("unmarshalPublicMsg() returned an error: %+v", err)
	}

	if !reflect.DeepEqual(pm, newPm) {
		t.Errorf("unmarshalPublicMsg() did not return the expected publicMsg."+
			"\nexpected: %s\nreceived: %s", pm, newPm)
	}
}

// Error path: error is returned when the data is too short.
func Test_unmarshalPublicMsg(t *testing.T) {
	expectedErr := fmt.Sprintf(unmarshalPublicSizeErr, 0, publicMinLen)

	_, err := unmarshalPublicMsg(nil)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("unmarshalPublicMsg() failed to return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func Test_publicMsg_SetSalt_GetSalt(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)
	salt := make([]byte, saltLen)
	rand.New(rand.NewSource(42)).Read(salt)
	pm.SetSalt(salt)

	testSalt := pm.GetSalt()
	if !bytes.Equal(salt, testSalt) {
		t.Errorf("Failed to get original salt."+
			"\nexpected: %+v\nreceived: %+v", salt, testSalt)
	}
}

// Tests that the original payload matches the saved one.
func Test_publicMsg_SetPayload_GetPayload(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)
	payload := []byte("Test payload message.")
	err := pm.SetPayload(payload)
	if err != nil {
		t.Errorf("SetPayload() returned an error: %+v", err)
	}
	testPayload := pm.GetPayload()

	if !bytes.Equal(payload, testPayload) {
		t.Errorf("Failed to get original sender payload."+
			"\nexpected: %s\nreceived: %s", payload, testPayload)
	}
}

// Error path: error is returned if the data is larger than the payload in the
// message.
func Test_publicMsg_SetPayload_PayloadDataTooLarge(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen + 1)

	payload := make([]byte, publicMinLen*2)
	expectedErr := fmt.Sprintf(setPublicPayloadLenErr, len(payload), len(pm.payload))

	err := pm.SetPayload(payload)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("SetPayload() did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Error path: error is returned if the length of the data does not fit in a
// uint16.
func Test_publicMsg_SetPayload_PayloadDataLengthTooLarge(t *testing.T) {
	pm, _ := newPublicMsg(math.MaxUint16 * 2)

	payload := make([]byte, math.MaxUint16+1)
	expectedErr := fmt.Sprintf(setPublicPayloadSizeErr, len(payload), math.MaxUint16)

	err := pm.SetPayload(payload)
	if err == nil || err.Error() != expectedErr {
		t.Errorf("SetPayload() did not return the expected error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Happy path.
func Test_publicMsg_GetPayloadSize(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)
	payload := []byte("Test encrypted payload.")
	err := pm.SetPayload(payload)
	if err != nil {
		t.Errorf("Failed to set the payload: %+v", err)
	}

	if len(payload) != pm.GetPayloadSize() {
		t.Errorf("GetPayloadSize() failed to return the correct size."+
			"\nexpected: %d\nreceived: %d", len(payload), pm.GetPayloadSize())
	}
}

// Happy path.
func Test_publicMsg_GetPayloadMaxSize(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)

	if publicMinLen != pm.GetPayloadMaxSize() {
		t.Errorf("GetPayloadMaxSize() failed to return the correct size."+
			"\nexpected: %d\nreceived: %d", publicMinLen, pm.GetPayloadMaxSize())
	}
}

// Happy path.
func Test_publicMsg_String(t *testing.T) {
	pm, _ := newPublicMsg(publicMinLen * 2)
	salt := make([]byte, saltLen)
	rand.New(rand.NewSource(42)).Read(salt)
	pm.SetSalt(salt)
	payload := []byte("Sample payload message.")
	payload = append(payload, 0, 1, 2)
	_ = pm.SetPayload(payload)

	expected := `{salt:U4x/lrFkvxuXu59LtHLon1sUhPJSCcnZND6SugndnVI=, size:26, payload:"Sample payload message.\x00\x01\x02"}`

	if pm.String() != expected {
		t.Errorf("String() failed to return the expected value."+
			"\nexpected: %s\nreceived: %s", expected, pm.String())
	}
}

// Happy path: tests that String returns the expected string for a nil publicMsg.
func Test_publicMsg_String_NilInternalMessage(t *testing.T) {
	pm := publicMsg{}

	expected := "{salt:<nil>, size:<nil>, payload:<nil>}"

	if pm.String() != expected {
		t.Errorf("String() failed to return the expected value."+
			"\nexpected: %s\nreceived: %s", expected, pm.String())
	}
}
