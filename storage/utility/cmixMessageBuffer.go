///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package utility

import (
	"crypto/md5"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

const currentCmixMessageVersion = 0

type cmixMessageHandler struct{}

type storedMessage struct {
	Msg       []byte
	Recipient []byte
}

func (sm storedMessage) Marshal() []byte {

	data, err := json.Marshal(&sm)
	if err != nil {
		jww.FATAL.Panicf("Failed to marshal stored message: %s", err)
	}

	return data
}

// SaveMessage saves the message as a versioned object at the specified key
// in the key value store.
func (cmh *cmixMessageHandler) SaveMessage(kv *versioned.KV, m interface{}, key string) error {
	sm := m.(storedMessage)

	// Create versioned object
	obj := versioned.Object{
		Version:   currentCmixMessageVersion,
		Timestamp: time.Now(),
		Data:      sm.Marshal(),
	}

	// Save versioned object
	return kv.Set(key, &obj)
}

// LoadMessage returns the message with the specified key from the key value
// store. An empty message and error are returned if the message could not be
// retrieved.
func (cmh *cmixMessageHandler) LoadMessage(kv *versioned.KV, key string) (interface{}, error) {
	// Load the versioned object
	vo, err := kv.Get(key)
	if err != nil {
		return format.Message{}, err
	}

	sm := storedMessage{}
	if err = json.Unmarshal(vo.Data, &sm); err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal stored message")
	}

	// Create message from data
	return sm, nil
}

// DeleteMessage deletes the message with the specified key from the key value
// store.
func (cmh *cmixMessageHandler) DeleteMessage(kv *versioned.KV, key string) error {
	return kv.Delete(key)
}

// HashMessage generates a hash of the message.
func (cmh *cmixMessageHandler) HashMessage(m interface{}) MessageHash {
	sm := m.(storedMessage)
	return md5.Sum(sm.Marshal())
}

// CmixMessageBuffer wraps the message buffer to store and load raw cmix
// messages.
type CmixMessageBuffer struct {
	mb *MessageBuffer
}

func NewCmixMessageBuffer(kv *versioned.KV, key string) (*CmixMessageBuffer, error) {
	mb, err := NewMessageBuffer(kv, &cmixMessageHandler{}, key)
	if err != nil {
		return nil, err
	}

	return &CmixMessageBuffer{mb: mb}, nil
}

func LoadCmixMessageBuffer(kv *versioned.KV, key string) (*CmixMessageBuffer, error) {
	mb, err := LoadMessageBuffer(kv, &cmixMessageHandler{}, key)
	if err != nil {
		return nil, err
	}

	return &CmixMessageBuffer{mb: mb}, nil
}

func (cmb *CmixMessageBuffer) Add(msg format.Message, recipent *id.ID) {
	sm := storedMessage{
		Msg:       msg.Marshal(),
		Recipient: recipent.Marshal(),
	}
	cmb.mb.Add(sm)
}

func (cmb *CmixMessageBuffer) AddProcessing(msg format.Message, recipent *id.ID) {
	sm := storedMessage{
		Msg:       msg.Marshal(),
		Recipient: recipent.Marshal(),
	}
	cmb.mb.AddProcessing(sm)
}

func (cmb *CmixMessageBuffer) Next() (format.Message, *id.ID, bool) {
	m, ok := cmb.mb.Next()
	if !ok {
		return format.Message{}, nil, false
	}

	sm := m.(storedMessage)
	msg := format.Unmarshal(sm.Msg)
	recpient, err := id.Unmarshal(sm.Recipient)
	if err != nil {
		jww.FATAL.Panicf("Could nto get an id for stored cmix "+
			"message buffer: %+v", err)
	}
	return msg, recpient, true
}

func (cmb *CmixMessageBuffer) Succeeded(msg format.Message, recipent *id.ID) {
	sm := storedMessage{
		Msg:       msg.Marshal(),
		Recipient: recipent.Marshal(),
	}
	cmb.mb.Succeeded(sm)
}

func (cmb *CmixMessageBuffer) Failed(msg format.Message, recipent *id.ID) {
	sm := storedMessage{
		Msg:       msg.Marshal(),
		Recipient: recipent.Marshal(),
	}
	cmb.mb.Failed(sm)
}
