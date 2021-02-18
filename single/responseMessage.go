///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package single

import (
	"encoding/binary"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
)

const (
	partNumLen      = 1
	maxPartsLen     = 1
	responseMinSize = partNumLen + maxPartsLen + sizeSize
)

/*
+-----------------------------------------+
|          CMIX Message Contents          |
+---------+----------+---------+----------+
| partNum | maxParts |  size   | contents |
| 1 bytes |  1 byte  | 2 bytes | variable |
+------------+----------+---------+-------+
*/

type responseMessagePart struct {
	data     []byte // Serial of all contents
	partNum  []byte // Index of message in a series of messages
	maxParts []byte // The number of parts in this message.
	size     []byte // Size of the contents
	contents []byte // The encrypted contents
}

// newResponseMessagePart generates a new response message part of the specified
// size.
func newResponseMessagePart(externalPayloadSize int) responseMessagePart {
	if externalPayloadSize < responseMinSize {
		jww.FATAL.Panicf("Failed to create new single-use response message "+
			"part: size of external payload (%d) is too small to contain the "+
			"message part number and max parts (%d)",
			externalPayloadSize, responseMinSize)
	}

	return mapResponseMessagePart(make([]byte, externalPayloadSize))
}

// mapResponseMessagePart builds a message part mapped to the passed in data.
// It is mapped by reference; a copy is not made.
func mapResponseMessagePart(data []byte) responseMessagePart {
	return responseMessagePart{
		data:     data,
		partNum:  data[:partNumLen],
		maxParts: data[partNumLen : maxPartsLen+partNumLen],
		size:     data[maxPartsLen+partNumLen : responseMinSize],
		contents: data[responseMinSize:],
	}
}

// unmarshalResponseMessage converts a byte buffer into a response message part.
func unmarshalResponseMessage(b []byte) (responseMessagePart, error) {
	if len(b) < responseMinSize {
		return responseMessagePart{}, errors.Errorf("Size of passed in bytes "+
			"(%d) is too small to contain the message part number and max "+
			"parts (%d).", len(b), responseMinSize)
	}
	return mapResponseMessagePart(b), nil
}

// Marshal returns the bytes of the message part.
func (m responseMessagePart) Marshal() []byte {
	return m.data
}

// GetPartNum returns the index of this part in the message.
func (m responseMessagePart) GetPartNum() uint8 {
	return m.partNum[0]
}

// SetPartNum sets the part number of the message.
func (m responseMessagePart) SetPartNum(num uint8) {
	copy(m.partNum, []byte{num})
}

// GetMaxParts returns the number of parts in the message.
func (m responseMessagePart) GetMaxParts() uint8 {
	return m.maxParts[0]
}

// SetMaxParts sets the number of parts in the message.
func (m responseMessagePart) SetMaxParts(max uint8) {
	copy(m.maxParts, []byte{max})
}

// GetContents returns the contents of the message part.
func (m responseMessagePart) GetContents() []byte {
	return m.contents[:binary.BigEndian.Uint16(m.size)]
}

// GetContentsSize returns the length of the contents.
func (m responseMessagePart) GetContentsSize() int {
	return int(binary.BigEndian.Uint16(m.size))
}

// GetMaxContentsSize returns the max capacity of the contents.
func (m responseMessagePart) GetMaxContentsSize() int {
	return len(m.contents)
}

// SetContents sets the contents of the message part. Does not zero out previous
// contents.
func (m responseMessagePart) SetContents(contents []byte) {
	if len(contents) > len(m.contents) {
		jww.FATAL.Panicf("Failed to set contents of single-use response "+
			"message part: max size of message contents (%d) is smaller than "+
			"the size of the supplied contents (%d).",
			len(m.contents), len(contents))
	}

	binary.BigEndian.PutUint16(m.size, uint16(len(contents)))

	copy(m.contents, contents)
}
