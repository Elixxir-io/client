///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package conversation

import (
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"math"
	"strings"
	"sync"
)

const (
	currentConversationVersion = 0
	maxTruncatedID             = math.MaxUint32
	bottomRegion               = maxTruncatedID / 4
	topRegion                  = bottomRegion * 3
)

type Conversation struct {
	// Public and stored data
	lastReceivedID         uint32
	numReceivedRevolutions uint32
	nextSentID             uint64

	// Private and non-stored data
	partner *id.ID
	kv      versioned.KV
	mux     sync.Mutex
}

// conversationDisk stores the public data of Conversation for saving to disk.
type conversationDisk struct {
	// Public and stored data
	LastReceivedID         uint32
	NumReceivedRevolutions uint32
	NextSendID             uint64
}

// LoadOrMakeConversation returns the Conversation with the given ID, if it can
// be found in KV. Otherwise, a new conversation with the given ID is generated,
// saved to KV, and returned.
func LoadOrMakeConversation(kv versioned.KV, partner *id.ID) *Conversation {
	c, err := loadConversation(kv, partner)
	if err != nil && !strings.Contains(err.Error(), "Failed to Load conversation") {
		jww.FATAL.Panicf("Failed to loadOrMakeConversation: %s", err)
	}

	// Create new conversation and save to KV if one does not exist
	if c == nil {
		c = &Conversation{
			lastReceivedID:         0,
			numReceivedRevolutions: 0,
			nextSentID:             0,
			partner:                partner,
			kv:                     kv,
		}

		if err = c.save(); err != nil {
			jww.FATAL.Panicf("Failed to save new conversation: %s", err)
		}
	}

	return c
}

// ProcessReceivedMessageID finds the full 64-bit message ID and updates the
// internal last message ID if the new ID is newer.
func (c *Conversation) ProcessReceivedMessageID(mid uint32) uint64 {
	c.mux.Lock()
	defer c.mux.Unlock()

	var high uint32
	switch cmp(c.lastReceivedID, mid) {
	case 1:
		c.numReceivedRevolutions++
		c.lastReceivedID = mid
		if err := c.save(); err != nil {
			jww.FATAL.Panicf("Failed to save after updating Last "+
				"Received ID in a conversation: %s", err)
		}
		high = c.numReceivedRevolutions

	case 0:
		if mid > c.lastReceivedID {
			c.lastReceivedID = mid
			if err := c.save(); err != nil {
				jww.FATAL.Panicf("Failed to save after updating Last "+
					"Received ID in a conversation: %s", err)
			}
		}
		high = c.numReceivedRevolutions

	case -1:
		high = c.numReceivedRevolutions - 1
	}

	return (uint64(high) << 32) | uint64(mid)
}

func cmp(a, b uint32) int {
	if a > topRegion && b < bottomRegion {
		return 1
	} else if a < bottomRegion && b > topRegion {
		return -1
	}
	return 0
}

// GetNextSendID returns the next sendID in both full and truncated formats.
func (c *Conversation) GetNextSendID() (uint64, uint32) {
	c.mux.Lock()
	old := c.nextSentID
	c.nextSentID++
	if err := c.save(); err != nil {
		jww.FATAL.Panicf("Failed to save after incrementing the sendID: %s",
			err)
	}
	c.mux.Unlock()
	return old, uint32(old & 0x00000000FFFFFFFF)
}

// loadConversation returns the Conversation with the given ID from KV storage.
func loadConversation(kv versioned.KV, partner *id.ID) (*Conversation, error) {
	key := makeConversationKey(partner)

	obj, err := kv.Get(key, currentConversationVersion)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to Load conversation")
	}

	c := &Conversation{
		partner: partner,
		kv:      kv,
	}

	if err = c.unmarshal(obj.Data); err != nil {
		return nil, errors.WithMessage(err, "Failed to Load conversation")
	}

	return c, nil
}

// save saves the Conversation to KV storage.
func (c *Conversation) save() error {
	data, err := c.marshal()
	if err != nil {
		return err
	}

	obj := versioned.Object{
		Version:   currentConversationVersion,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	key := makeConversationKey(c.partner)
	return c.kv.Set(key, currentConversationVersion, &obj)
}

// delete removes the Conversation from KV storage.
func (c *Conversation) delete() error {
	key := makeConversationKey(c.partner)
	return c.kv.Delete(key, currentConversationVersion)
}

func (c *Conversation) unmarshal(b []byte) error {
	cd := conversationDisk{}

	if err := json.Unmarshal(b, &cd); err != nil {
		return errors.Wrap(err, "Failed to Unmarshal Conversation")
	}

	c.lastReceivedID = cd.LastReceivedID
	c.numReceivedRevolutions = cd.NumReceivedRevolutions
	c.nextSentID = cd.NextSendID

	return nil
}

func (c *Conversation) marshal() ([]byte, error) {
	cd := conversationDisk{}
	cd.LastReceivedID = c.lastReceivedID
	cd.NumReceivedRevolutions = c.numReceivedRevolutions
	cd.NextSendID = c.nextSentID

	b, err := json.Marshal(&cd)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal conversation")
	}
	return b, nil
}

func makeConversationKey(partner *id.ID) string {
	return versioned.MakePartnerPrefix(partner)
}
