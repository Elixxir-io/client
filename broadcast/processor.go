////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	crypto "gitlab.com/elixxir/crypto/broadcast"
	"gitlab.com/elixxir/primitives/format"
)

// Error messages.
const (
	errDecrypt = "[BCAST] Failed to decrypt payload for broadcast %s (%q): %+v"
)

// processor struct for message handling. This structure adheres to the
// message.Processor interface.
type processor struct {
	c      *crypto.Channel
	cb     ListenerFunc
	method Method
}

// Process decrypts the broadcast message and sends the results on the callback.
func (p *processor) Process(msg format.Message,
	receptionID receptionID.EphemeralIdentity, round rounds.Round) {

	var payload []byte
	var err error
	switch p.method {
	case RSAToPublic:
		decodedMessage, decryptErr := p.c.DecryptRSAToPublic(
			msg.GetContents(), msg.GetMac(), msg.GetKeyFP())
		if decryptErr != nil {
			jww.ERROR.Printf(errDecrypt, p.c.ReceptionID, p.c.Name, decryptErr)
			return
		}
		size := binary.BigEndian.Uint16(
			decodedMessage[:internalPayloadSizeLength])
		payload = decodedMessage[internalPayloadSizeLength : size+internalPayloadSizeLength]

	case Symmetric:
		payload, err = p.c.DecryptSymmetric(
			msg.GetContents(), msg.GetMac(), msg.GetKeyFP())
		if err != nil {
			jww.ERROR.Printf(errDecrypt, p.c.ReceptionID, p.c.Name, err)
			return
		}
	default:
		jww.FATAL.Panicf("Unrecognized broadcast method %d", p.method)
	}

	p.cb(payload, receptionID, round)
}

// String returns a string identifying the symmetricProcessor for debugging
// purposes.
func (p *processor) String() string {
	return "broadcastChannel-" + p.c.Name
}
