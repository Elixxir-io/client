///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package utility

import (
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/netTime"
	"golang.org/x/crypto/blake2b"
	"time"
)

const currentMeteredCmixMessageVersion = 0

type meteredCmixMessageHandler struct{}

type meteredCmixMessage struct {
	M         []byte
	Count     uint
	Timestamp time.Time
}

// SaveMessage saves the message as a versioned object at the specified key in
// the key value store.
func (*meteredCmixMessageHandler) SaveMessage(kv *versioned.KV, m interface{}, key string) error {
	msg := m.(meteredCmixMessage)

	marshaled, err := json.Marshal(&msg)
	if err != nil {
		return errors.WithMessage(err, "Failed to marshal metered cmix message")
	}

	// Create versioned object
	obj := versioned.Object{
		Version:   currentMeteredCmixMessageVersion,
		Timestamp: netTime.Now(),
		Data:      marshaled,
	}

	// Save versioned object
	return kv.Set(key, currentMessageBufferVersion, &obj)
}

// LoadMessage returns the message with the specified key from the key value
// store. An empty message and error are returned if the message could not be
// retrieved.
func (*meteredCmixMessageHandler) LoadMessage(kv *versioned.KV, key string) (interface{}, error) {
	// Load the versioned object
	vo, err := kv.Get(key, currentMeteredCmixMessageVersion)
	if err != nil {
		return nil, err
	}

	msg := meteredCmixMessage{}
	err = json.Unmarshal(vo.Data, &msg)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to unmarshal metered cmix message")
	}

	// Create message from data
	return msg, nil
}

// DeleteMessage deletes the message with the specified key from the key value
// store.
func (*meteredCmixMessageHandler) DeleteMessage(kv *versioned.KV, key string) error {
	return kv.Delete(key, currentMeteredCmixMessageVersion)
}

// HashMessage generates a hash of the message.
func (*meteredCmixMessageHandler) HashMessage(m interface{}) MessageHash {
	h, _ := blake2b.New256(nil)

	h.Write(m.(meteredCmixMessage).M)

	var messageHash MessageHash
	copy(messageHash[:], h.Sum(nil))

	return messageHash
}

// CmixMessageBuffer wraps the message buffer to store and load raw cmix
// messages.
type MeteredCmixMessageBuffer struct {
	mb  *MessageBuffer
	kv  *versioned.KV
	key string
}

func NewMeteredCmixMessageBuffer(kv *versioned.KV, key string) (*MeteredCmixMessageBuffer, error) {
	mb, err := NewMessageBuffer(kv, &meteredCmixMessageHandler{}, key)
	if err != nil {
		return nil, err
	}

	return &MeteredCmixMessageBuffer{mb: mb, kv: kv, key: key}, nil
}

func LoadMeteredCmixMessageBuffer(kv *versioned.KV, key string) (*MeteredCmixMessageBuffer, error) {
	mb, err := LoadMessageBuffer(kv, &meteredCmixMessageHandler{}, key)
	if err != nil {
		return nil, err
	}

	return &MeteredCmixMessageBuffer{mb: mb, kv: kv, key: key}, nil
}

func (mcmb *MeteredCmixMessageBuffer) Add(m format.Message) {
	msg := meteredCmixMessage{
		M:         m.Marshal(),
		Count:     0,
		Timestamp: netTime.Now(),
	}
	mcmb.mb.Add(msg)
}

func (mcmb *MeteredCmixMessageBuffer) AddProcessing(m format.Message) {
	msg := meteredCmixMessage{
		M:         m.Marshal(),
		Count:     0,
		Timestamp: netTime.Now(),
	}
	mcmb.mb.AddProcessing(msg)
}

func (mcmb *MeteredCmixMessageBuffer) Next() (format.Message, uint, time.Time, bool) {
	m, ok := mcmb.mb.Next()
	if !ok {
		return format.Message{}, 0, time.Time{}, false
	}

	msg := m.(meteredCmixMessage)
	rtnCnt := msg.Count

	// increment the count and save
	msg.Count++
	mcmh := &meteredCmixMessageHandler{}
	err := mcmh.SaveMessage(mcmb.kv, msg, makeStoredMessageKey(mcmb.key, mcmh.HashMessage(msg)))
	if err != nil {
		jww.FATAL.Panicf("Failed to save metered message after count "+
			"update: %s", err)
	}

	msfFormat := format.Unmarshal(msg.M)
	return msfFormat, rtnCnt, msg.Timestamp, true
}

func (mcmb *MeteredCmixMessageBuffer) Remove(m format.Message) {
	mcmb.mb.Succeeded(meteredCmixMessage{M: m.Marshal()})
}

func (mcmb *MeteredCmixMessageBuffer) Failed(m format.Message) {
	mcmb.mb.Failed(meteredCmixMessage{M: m.Marshal()})
}
