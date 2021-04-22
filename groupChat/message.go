///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"github.com/pkg/errors"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/crypto/group"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"io"
	"time"
)

type Group struct {
	members group.Membership
	id      *id.ID
	key     []byte
	rng     io.Reader
}

type internalFormat struct {
	timestamp time.Time
	senderID  *id.ID
	payload   []byte
}

func (g Group) NewMessage(msg []byte, fastRng *fastRNG.StreamGenerator) ([]format.Message, error) {
	stream := fastRng.GetStream()

	for i, member := range g.members {
		salt := make([]byte, 32)
		n, err := stream.Read(salt)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to generate salt, this should never happen")
		} else if n != 32 {
			return nil, errors.WithMessagef(err, "Failed to generate salt of length %d, received bytes of length %d", 32, n)
		}

		keyFp, err := group.NewKeyFingerprint(g.key, salt, member.ID)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to generate key fingerprint")
		}

		key, err := group.NewKdfKey(g.key, salt)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to generate key")
		}

		internal := internalFormat{
			timestamp: time.Time{},
			senderID:  nil,
			payload:   nil,
		}

	}

	stream.Close()
}
