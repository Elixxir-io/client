///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/group"
	"math"
	"strconv"
)

// Sizes of marshaled data, in bytes.
const (
	saltLen              = group.SaltLen
	publicPayloadSizeLen = 2
	publicMinLen         = saltLen + publicPayloadSizeLen
)

// Error messages
const (
	newPublicSizeErr        = "New Public Group Message: max message size %d < %d minimum required"
	unmarshalPublicSizeErr  = "Unmarshal Public Group Message: size of data %d < %d minimum required"
	setPublicPayloadLenErr  = "Public Group Message: can not set encrypted payload with length %d > %d maximum"
	setPublicPayloadSizeErr = "Public Group Message: cannot save encrypted payload length %d > %d maximum"
)

// publicMsg is contains the salt and encrypted data in a group message.
//
// +-------------------------------+
// |             data              |
// +----------+---------+----------+
// |   salt   |  size   | payload  |
// | 32 bytes | 2 bytes | variable |
// +----------+---------+----------+
type publicMsg struct {
	data    []byte // Serial of all the parts of the message
	salt    []byte // 256-bit sender salt
	size    []byte // Size of the payload
	payload []byte // Encrypted internalMsg
}

// newPublicMsg creates a new publicMsg of size maxDataSize. An error is
// returned if the maxDataSize is smaller than the minimum newPublicMsg size.
func newPublicMsg(maxDataSize int) (publicMsg, error) {
	if maxDataSize < publicMinLen {
		return publicMsg{},
			errors.Errorf(newPublicSizeErr, maxDataSize, publicMinLen)
	}

	return mapPublicMsg(make([]byte, maxDataSize)), nil
}

// mapPublicMsg maps all the parts of the publicMsg to the passed in data.
func mapPublicMsg(data []byte) publicMsg {
	return publicMsg{
		data:    data,
		salt:    data[:saltLen],
		size:    data[saltLen : saltLen+publicPayloadSizeLen],
		payload: data[saltLen+publicPayloadSizeLen:],
	}
}

// unmarshalPublicMsg unmarshal the data into an publicMsg.  An error is
// returned if the data length is smaller than the minimum allowed size.
func unmarshalPublicMsg(data []byte) (publicMsg, error) {
	if len(data) < publicMinLen {
		return publicMsg{},
			errors.Errorf(unmarshalPublicSizeErr, len(data), publicMinLen)
	}

	return mapPublicMsg(data), nil
}

// Marshal returns the serial of the publicMsg.
func (pm publicMsg) Marshal() []byte {
	return pm.data
}

// GetSalt returns the 256-bit salt.
func (pm publicMsg) GetSalt() []byte {
	return pm.salt
}

// SetSalt sets the 256-bit salt.
func (pm publicMsg) SetSalt(salt []byte) {
	copy(pm.salt, salt)
}

// GetPayload returns the payload truncated to the correct size.
func (pm publicMsg) GetPayload() []byte {
	return pm.payload[:pm.GetPayloadSize()]
}

// SetPayload sets the payload and saves it size. An error is returned if the
// payload is larger the the max payload size of the the length is larger than
// can be stored in the size field.
func (pm publicMsg) SetPayload(payload []byte) error {
	if len(payload) > len(pm.payload) {
		return errors.Errorf(setPublicPayloadLenErr, len(payload), len(pm.payload))
	} else if len(payload) > math.MaxUint16 {
		return errors.Errorf(setPublicPayloadSizeErr, len(payload), math.MaxUint16)
	}

	// Save size of payload
	binary.LittleEndian.PutUint16(pm.size, uint16(len(payload)))

	// Save payload
	copy(pm.payload, payload)

	return nil
}

// GetPayloadSize returns the length of the content in the payload.
func (pm publicMsg) GetPayloadSize() int {
	return int(binary.LittleEndian.Uint16(pm.size))
}

// GetPayloadMaxSize returns the maximum size of the payload.
func (pm publicMsg) GetPayloadMaxSize() int {
	return len(pm.payload)
}

// String prints a string representation of publicMsg. This functions satisfies
// the fmt.Stringer interface.
func (pm publicMsg) String() string {
	salt := "<nil>"
	if len(pm.salt) > 0 {
		salt = base64.StdEncoding.EncodeToString(pm.salt)
	}

	size := "<nil>"
	if len(pm.size) > 0 {
		size = strconv.Itoa(pm.GetPayloadSize())
	}

	payload := "<nil>"
	if len(pm.size) > 0 {
		payload = fmt.Sprintf("%q", pm.GetPayload())
	}

	return "{salt:" + salt + ", size:" + size + ", payload:" + payload + "}"
}
