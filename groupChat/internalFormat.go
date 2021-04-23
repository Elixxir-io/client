///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"bytes"
	"github.com/pkg/errors"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

// Sizes of marshaled data, in bytes.
const (
	marshalTimeStampSize = 15
)

// Error messages
const (
	marshalTimestampErr      = "Group Internal Message Marshal: failed to marshal timestamp: %+v"
	marshalTimestampLenErr   = "Group Internal Message Marshal: length of marshalled timestamp %d > %d expected"
	unmarshalTimestampLenErr = "Group Internal Message Unmarshal: failed to unmarshal timestamp: %+v"
	unmarshalIdLenErr        = "Group Internal Message Unmarshal: failed to unmarshal sender ID: %+v"
)

// internalMsg is the internal, unencrypted data in a group message.
type internalMsg struct {
	data      []byte // Serial of all the parts of the message
	timestamp []byte // 120-bit Unix time timestamp stored in nanoseconds
	senderID  []byte // 264-bit sender ID
	payload   []byte // Message contents
}

// MarshalBinary serializes the internalMsg into a byte slice. It implements the
// encoding.BinaryMarshaler interface.
func (im internalMsg) MarshalBinary() ([]byte, error) {
	buff := bytes.NewBuffer(nil)
	buff.Grow(marshalTimeStampSize + id.ArrIDLen + len(im.payload))

	time.Now().UnixNano()

	// Marshal the timestamp and make sure it is the correct size
	timestamp, err := im.timestamp.MarshalBinary()
	if err != nil {
		return nil, errors.Errorf(marshalTimestampErr, err)
	} else if len(timestamp) > marshalTimeStampSize {
		return nil, errors.Errorf(marshalTimestampLenErr, len(timestamp), marshalTimeStampSize)
	}

	// Write 120-bit timestamp to buffer
	timestampSized := make([]byte, marshalTimeStampSize)
	copy(timestampSized, timestamp)
	buff.Write(timestampSized)

	// Write sender ID and payload to buffer
	buff.Write(im.senderID.Bytes())
	buff.Write(im.payload)

	return buff.Bytes(), nil
}

// UnmarshalBinary deserializes the internalMsg. It implements the
// encoding.BinaryUnmarshaler interface.
func (im *internalMsg) UnmarshalBinary(data []byte) error {
	buff := bytes.NewBuffer(data)

	err := im.timestamp.UnmarshalBinary(buff.Next(marshalTimeStampSize))
	if err != nil {
		return errors.Errorf(unmarshalTimestampLenErr, err)
	}

	im.senderID, err = id.Unmarshal(buff.Next(id.ArrIDLen))
	if err != nil {
		return errors.Errorf(unmarshalIdLenErr, err)
	}

	im.payload = buff.Bytes()

	return nil
}
