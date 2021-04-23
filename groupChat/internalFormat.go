///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
	"math"
	"strconv"
	"time"
)

// Sizes of marshaled data, in bytes.
const (
	timestampSize   = 8
	payloadSizeSize = 2
	internalMinSize = timestampSize + id.ArrIDLen + payloadSizeSize
)

// Error messages
const (
	newInternalSizeErr        = "New Internal Group Message: external payload size %d < %d minimum required"
	unmarshalInternalSizeErr  = "Unmarshal Internal Group Message: size of data %d < %d minimum required"
	setInternalPayloadLenErr  = "Internal Group Message: can not set payload with length %d > %d maximum"
	setInternalPayloadSizeErr = "Internal Group Message: payload with length %d too large"
)

// internalMsg is the internal, unencrypted data in a group message.
type internalMsg struct {
	data      []byte // Serial of all the parts of the message
	timestamp []byte // 64-bit Unix time timestamp stored in nanoseconds
	senderID  []byte // 264-bit sender ID
	size      []byte // Size of the payload
	payload   []byte // Message contents
}

// newInternalMsg creates a new internalMsg of size externalPayloadSize. An
// error is returned if the externalPayloadSize is smaller than the minimum
// internalMsg size.
func newInternalMsg(externalPayloadSize int) (internalMsg, error) {
	if externalPayloadSize < internalMinSize {
		return internalMsg{}, errors.Errorf(newInternalSizeErr,
			externalPayloadSize, internalMinSize)
	}

	return mapInternalMsg(make([]byte, externalPayloadSize)), nil
}

// mapInternalMsg maps all the parts of the internalMsg to the passed in data.
func mapInternalMsg(data []byte) internalMsg {
	return internalMsg{
		data:      data,
		timestamp: data[:timestampSize],
		senderID:  data[timestampSize : timestampSize+id.ArrIDLen],
		size:      data[timestampSize+id.ArrIDLen : timestampSize+id.ArrIDLen+payloadSizeSize],
		payload:   data[timestampSize+id.ArrIDLen+payloadSizeSize:],
	}
}

// unmarshalInternalMsg unmarshal the data into an internalMsg.
func unmarshalInternalMsg(data []byte) (internalMsg, error) {
	if len(data) < internalMinSize {
		return internalMsg{}, errors.Errorf(unmarshalInternalSizeErr,
			len(data), internalMinSize)
	}

	return mapInternalMsg(data), nil
}

// Marshal returns the serial of the internalMsg.
func (im internalMsg) Marshal() []byte {
	return im.data
}

// GetTimestamp returns the timestamp as a time.Time.
func (im internalMsg) GetTimestamp() time.Time {
	return time.Unix(0, int64(binary.LittleEndian.Uint64(im.timestamp)))
}

// SetTimestamp converts the time.Time to Unix nano and save as bytes.
func (im internalMsg) SetTimestamp(t time.Time) {
	binary.LittleEndian.PutUint64(im.timestamp, uint64(t.UnixNano()))
}

// GetSenderID returns the sender ID bytes as a id.ID.
func (im internalMsg) GetSenderID() (*id.ID, error) {
	return id.Unmarshal(im.senderID)
}

// SetSenderID sets the sender ID.
func (im internalMsg) SetSenderID(sid *id.ID) {
	copy(im.senderID, sid.Marshal())
}

// GetPayload returns the payload truncated to the correct size.
func (im internalMsg) GetPayload() []byte {
	return im.payload[:im.GetPayloadSize()]
}

func (im internalMsg) SetPayload(payload []byte) error {
	if len(payload) > len(im.payload) {
		return errors.Errorf(setInternalPayloadLenErr, len(payload), len(im.payload))
	} else if len(payload) > math.MaxUint16 {
		return errors.Errorf(setInternalPayloadSizeErr, len(payload))
	}

	// Save size of payload
	binary.LittleEndian.PutUint16(im.size, uint16(len(payload)))

	// Save payload
	copy(im.payload, payload)

	return nil
}

// GetPayloadSize returns the length of the content in the payload.
func (im internalMsg) GetPayloadSize() int {
	return int(binary.LittleEndian.Uint16(im.size))
}

// GetPayloadMaxSize returns the maximum size of the payload.
func (im internalMsg) GetPayloadMaxSize() int {
	return len(im.payload)
}

// String prints a string representation of internalMsg. This functions
// satisfies the fmt.Stringer interface.
func (im internalMsg) String() string {
	timestamp := im.GetTimestamp().String()

	senderID, _ := im.GetSenderID()
	senderIDStr := "<nil>"
	if senderID != nil {
		senderIDStr = senderID.String()
	}

	size := strconv.Itoa(im.GetPayloadSize())
	payload := string(im.GetPayload())

	return "{timestamp:" + timestamp + ", senderID:" + senderIDStr +
		", size:" + size + ", payload:" + payload + "}"
}
