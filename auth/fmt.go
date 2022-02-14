///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package auth

import (
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	sidhinterface "gitlab.com/elixxir/client/interfaces/sidh"
	util "gitlab.com/elixxir/client/storage/utility"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/id"
)

const requestFmtVersion = 1

//Basic Format//////////////////////////////////////////////////////////////////
type baseFormat struct {
	data       []byte
	pubkey     []byte
	ecrPayload []byte
	version    []byte
}

func newBaseFormat(payloadSize, pubkeySize int) baseFormat {
	total := pubkeySize
	// Size of sidh pubkey
	total += sidhinterface.PubKeyByteSize + 1
	// Size of version
	total += 1
	if payloadSize < total {
		jww.FATAL.Panicf("Size of baseFormat is too small (%d), must be big "+
			"enough to contain public key (%d) and sidh key (%d)"+
			"and version which totals to %d", payloadSize,
			pubkeySize, sidhinterface.PubKeyByteSize+1, total)
	}

	jww.INFO.Printf("Empty Space RequestAuth: %d", payloadSize-total)

	f := buildBaseFormat(make([]byte, payloadSize), pubkeySize)
	f.version[0] = requestFmtVersion
	return f
}

func buildBaseFormat(data []byte, pubkeySize int) baseFormat {
	f := baseFormat{
		data: data,
	}

	start := 0
	end := pubkeySize
	f.pubkey = f.data[start:end]

	start = end
	end = len(f.data) - 1
	f.ecrPayload = f.data[start:end]

	f.version = f.data[end:]

	return f
}

func unmarshalBaseFormat(b []byte, pubkeySize int) (baseFormat, error) {
	if len(b) < pubkeySize {
		return baseFormat{}, errors.New("Received baseFormat too small")
	}
	bfmt := buildBaseFormat(b, pubkeySize)
	version := bfmt.GetVersion()
	if version != requestFmtVersion {
		return baseFormat{}, errors.Errorf(
			"Unknown baseFormat version: %d", version)
	}

	return bfmt, nil
}

func (f baseFormat) Marshal() []byte {
	return f.data
}

func (f baseFormat) GetVersion() byte {
	return f.version[0]
}

func (f baseFormat) GetPubKey(grp *cyclic.Group) *cyclic.Int {
	return grp.NewIntFromBytes(f.pubkey)
}

func (f baseFormat) SetPubKey(pubKey *cyclic.Int) {
	pubKeyBytes := pubKey.LeftpadBytes(uint64(len(f.pubkey)))
	copy(f.pubkey, pubKeyBytes)
}

// GetEcrPayload is the data that is encrypted
func (f baseFormat) GetEcrPayload() []byte {
	return f.ecrPayload
}

func (f baseFormat) GetEcrPayloadLen() int {
	return len(f.ecrPayload)
}

func (f baseFormat) SetEcrPayload(ecr []byte) {
	if len(ecr) != len(f.ecrPayload) {
		jww.FATAL.Panicf("Passed ecr payload incorrect lengh. Expected:"+
			" %v, Recieved: %v", len(f.ecrPayload), len(ecr))
	}

	copy(f.ecrPayload, ecr)
}

//Encrypted Format//////////////////////////////////////////////////////////////
const ownershipSize = 32

type ecrFormat struct {
	data       []byte
	ownership  []byte
	sidHpubkey []byte
	payload    []byte
}

func newEcrFormat(size int) ecrFormat {
	if size < (ownershipSize + sidhinterface.PubKeyByteSize + 1) {
		jww.FATAL.Panicf("Size too small to hold")
	}

	f := buildEcrFormat(make([]byte, size))

	return f

}

func buildEcrFormat(data []byte) ecrFormat {
	f := ecrFormat{
		data: data,
	}

	start := 0
	end := ownershipSize
	f.ownership = f.data[start:end]

	start = end
	end = start + sidhinterface.PubKeyByteSize + 1
	f.sidHpubkey = f.data[start:end]

	start = end
	f.payload = f.data[start:]
	return f
}

func unmarshalEcrFormat(b []byte) (ecrFormat, error) {
	if len(b) < ownershipSize {
		return ecrFormat{}, errors.New("Received ecr baseFormat too small")
	}

	return buildEcrFormat(b), nil
}

func (f ecrFormat) Marshal() []byte {
	return f.data
}

func (f ecrFormat) GetOwnership() []byte {
	return f.ownership
}

func (f ecrFormat) SetOwnership(ownership []byte) {
	if len(ownership) != ownershipSize {
		jww.FATAL.Panicf("ownership proof is the wrong size")
	}

	copy(f.ownership, ownership)
}

func (f ecrFormat) SetSidHPubKey(pubKey *sidh.PublicKey) {
	f.sidHpubkey[0] = byte(pubKey.Variant())
	pubKey.Export(f.sidHpubkey[1:])
}

func (f ecrFormat) GetSidhPubKey() (*sidh.PublicKey, error) {
	variant := sidh.KeyVariant(f.sidHpubkey[0])
	pubKey := util.NewSIDHPublicKey(variant)
	err := pubKey.Import(f.sidHpubkey[1:])
	return pubKey, err
}

func (f ecrFormat) GetPayload() []byte {
	return f.payload
}

func (f ecrFormat) PayloadLen() int {
	return len(f.payload)
}

func (f ecrFormat) SetPayload(p []byte) {
	if len(p) != len(f.payload) {
		jww.FATAL.Panicf("Payload is the wrong length")
	}

	copy(f.payload, p)
}

//Request Format////////////////////////////////////////////////////////////////
type requestFormat struct {
	ecrFormat
	id         []byte
	msgPayload []byte
}

func newRequestFormat(ecrFmt ecrFormat) (requestFormat, error) {
	if len(ecrFmt.payload) < id.ArrIDLen {
		return requestFormat{}, errors.New("Payload is not long enough")
	}

	rf := requestFormat{
		ecrFormat: ecrFmt,
	}

	rf.id = rf.payload[:id.ArrIDLen]
	rf.msgPayload = rf.payload[id.ArrIDLen:]

	return rf, nil
}

func (rf requestFormat) GetID() (*id.ID, error) {
	return id.Unmarshal(rf.id)
}

func (rf requestFormat) SetID(myId *id.ID) {
	copy(rf.id, myId.Marshal())
}

func (rf requestFormat) SetMsgPayload(b []byte) {
	if len(b) > len(rf.msgPayload) {
		jww.FATAL.Panicf("Message Payload is too long")
	}

	copy(rf.msgPayload, b)
}

func (rf requestFormat) MsgPayloadLen() int {
	return len(rf.msgPayload)
}

func (rf requestFormat) GetMsgPayload() []byte {
	return rf.msgPayload
}
