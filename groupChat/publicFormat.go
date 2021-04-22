///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/group"
)

// Error messages
const (
	newPublicMsgSaltLenErr = "New Group Public Message: insufficient salt length %d < %d expected"
	unmarshalSaltLenErr    = "Group Public Message Unmarshal: insufficient data length %d < %d expected"
)

type PublicMsg struct {
	salt       [group.SaltLen]byte
	encPayload []byte
}

// NewPublicMsg creates a new PublicMsg. An error is returned if the salt is
// not 256 bits.
func NewPublicMsg(salt, encPayload []byte) (PublicMsg, error) {
	pm := PublicMsg{
		salt:       [group.SaltLen]byte{},
		encPayload: encPayload,
	}

	if len(salt) < group.SaltLen {
		return PublicMsg{}, errors.Errorf(newPublicMsgSaltLenErr, len(salt), group.SaltLen)
	}

	return pm, nil
}

// MarshalBinary serializes the PublicMsg into a byte slice. It implements the
// encoding.BinaryMarshaler interface.
func (pm PublicMsg) MarshalBinary() ([]byte, error) {
	return append(pm.salt[:], pm.encPayload...), nil
}

// UnmarshalBinary deserializes the PublicMsg. It implements the
// encoding.BinaryUnmarshaler interface.
func (pm *PublicMsg) UnmarshalBinary(data []byte) error {
	if len(data) < group.SaltLen {
		return errors.Errorf(unmarshalSaltLenErr, len(data), group.SaltLen)
	}

	copy(pm.salt[:], data[:group.SaltLen])
	copy(pm.encPayload, data[group.SaltLen:])

	return nil
}
