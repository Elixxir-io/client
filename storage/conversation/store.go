package conversation

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/xx_network/primitives/id"
	"sync"
)

const conversationKeyPrefix = "conversation"

type Store struct {
	loadedConversations map[id.ID]*Conversation
	kv                  *versioned.KV
	mux                 sync.RWMutex
}

// NewStore returns a new conversation store made off of the KV.
func NewStore(kv *versioned.KV) *Store {
	kv = kv.Prefix(conversationKeyPrefix)
	return &Store{
		loadedConversations: make(map[id.ID]*Conversation),
		kv:                  kv,
	}
}

// Get gets the conversation with the given partner ID from RAM, if it is there.
// Otherwise, it loads it from disk.
func (s *Store) Get(partner *id.ID) *Conversation {
	s.mux.RLock()
	c, ok := s.loadedConversations[*partner]
	s.mux.RUnlock()

	if !ok {
		s.mux.Lock()
		c, ok = s.loadedConversations[*partner]
		if !ok {
			c = LoadOrMakeConversation(s.kv, partner)
			s.loadedConversations[*partner] = c
		}
		s.mux.Unlock()
	}
	return c
}

// Delete deletes the conversation with the given partner ID from memory and
// storage. Panics if the object cannot be deleted from storage.
func (s *Store) Delete(partner *id.ID) {
	s.mux.Lock()
	defer s.mux.Unlock()

	// Get contact from memory
	c, exists := s.loadedConversations[*partner]
	if !exists {
		return
	}

	// Delete contact from storage
	err := c.delete()
	if err != nil {
		jww.FATAL.Panicf("Failed to remover conversation with ID %s from "+
			"storage: %+v", partner, err)
	}

	// Delete contact from memory
	delete(s.loadedConversations, *partner)
}
