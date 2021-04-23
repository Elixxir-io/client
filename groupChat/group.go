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

func (g Group) NewMessage(msg []byte, sender *id.ID, fastRng *fastRNG.StreamGenerator) ([]format.Message, error) {
	stream := fastRng.GetStream()
	timeNow := time.Now()

	// Create list of group cMix messages
	msgs := make([]format.Message, 0, len(g.members)-1)
	errChan := make(chan error, cap(msgs))
	msgChan := make(chan format.Message, cap(msgs))
	for i, member := range g.members {
		// Do not send to the sender
		if sender.Cmp(member.ID) {
			continue
		}

		go func(member group.Member, i int) {
			// Add cMix message to list
			cMixMsg, err := g.newCmixMsg(msg, &member, sender, timeNow, stream)
			if err != nil {
				errChan <- err
			}
			msgChan <- cMixMsg
		}(member, i)
	}

	select {
	case err := <-errChan:
		return nil, err
	case msg := <-msgChan:
		msgs = append(msgs, msg)
	}

	stream.Close()
	return nil, nil
}

// newCmixMsg generates a new cMix message to be sent to a group member.
func (g Group) newCmixMsg(msg []byte, m *group.Member, sender *id.ID,
	timeNow time.Time, rng io.Reader) (format.Message, error) {
	cmixMsg := format.NewMessage(g.store.Cmix().GetGroup().GetP().ByteLen())
	publicMsg, err := newPublicMsg(cmixMsg.ContentsSize())
	if err != nil {
		return cmixMsg,
			errors.Errorf("failed to create new group cMix message: %+v", err)
	}
	internalMsg, err := newInternalMsg(publicMsg.GetPayloadMaxSize())
	if err != nil {
		return cmixMsg,
			errors.Errorf("failed to create new group cMix message: %+v", err)
	}

	// Generate 256-bit salt
	salt := make([]byte, group.SaltLen)
	n, err := rng.Read(salt)
	if err != nil {
		return cmixMsg,
			errors.WithMessage(err, "failed to generate salt for group message")
	} else if n != 32 {
		return cmixMsg, errors.WithMessagef(err, "length of generated salt "+
			"%d != %d required", group.SaltLen, n)
	}

	// Generate key fingerprint
	keyFp, err := group.NewKeyFingerprint(g.key, salt, m.ID)
	if err != nil {
		return cmixMsg, errors.WithMessage(err, "failed to generate key fingerprint")
	}

	// Generate key
	key, err := group.NewKdfKey(g.key, salt)
	if err != nil {
		return cmixMsg, errors.WithMessage(err, "failed to generate key")
	}

	// Generate internal message
	internalMsg.SetTimestamp(timeNow)
	internalMsg.SetSenderID(sender)
	err = internalMsg.SetPayload(msg)
	if err != nil {
		return cmixMsg, errors.Errorf("message does not fit in internal "+
			"message payload: %+v", err)
	}
	payload := internalMsg.Marshal()

	// Encrypt internal message
	encryptedPayload := group.Encrypt(key, keyFp[:], payload)

	// Generate MAC
	mac := group.NewMAC(key, encryptedPayload, m.DhKey)

	// Generate public message
	publicMsg.SetSalt(salt)
	err = publicMsg.SetPayload(encryptedPayload)
	if err != nil {
		return cmixMsg, errors.Errorf("encrypted payload does not fit in "+
			"public message payload: %+v", err)
	}

	// Construct cMix message
	cmixMsg.SetContents(publicMsg.Marshal())
	cmixMsg.SetKeyFP(keyFp)
	cmixMsg.SetMac(mac)

	return cmixMsg, nil
}
