///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/storage"
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
	store   *storage.Session
}

func (g Group) NewMessage(msg []byte, fastRng *fastRNG.StreamGenerator) ([]format.Message, error) {
	stream := fastRng.GetStream()
	msgs := make([]format.Message, len(g.members))

	for i, member := range g.members {
		salt := make([]byte, group.SaltLen)
		n, err := stream.Read(salt)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to generate salt, this should never happen")
		} else if n != 32 {
			return nil, errors.WithMessagef(err, "Failed to generate salt of length %d, received bytes of length %d", group.SaltLen, n)
		}

		keyFp, err := group.NewKeyFingerprint(g.key, salt, member.ID)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to generate key fingerprint")
		}

		key, err := group.NewKdfKey(g.key, salt)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to generate key")
		}

		internal := InternalMsg{
			timestamp: time.Now(),
			senderID:  member.ID,
			payload:   msg,
		}

		payload, err := internal.MarshalBinary()
		if err != nil {
			return nil, errors.WithMessage(err, "failed to binary marshal the internal message")
		}

		encryptedPayload := group.Encrypt(key, keyFp, payload)
		mac := group.NewMAC(key, encryptedPayload, member.DhKey)

		publicMsg, err := NewPublicMsg(salt, encryptedPayload)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create new public message for group")
		}

		msgs[i] = format.NewMessage(g.store.Cmix().GetGroup().GetP().ByteLen())
		contents, err := publicMsg.MarshalBinary()
		if err != nil {
			return nil, errors.WithMessage(err, "failed to binary marshal the public message")
		}
		msgs[i].SetContents(contents)
		msgs[i].SetKeyFP(format.NewFingerprint(keyFp))
		msgs[i].SetMac(mac)
	}

	stream.Close()
	return nil, nil
}
