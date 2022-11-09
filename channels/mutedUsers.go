////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/xx_network/primitives/netTime"
	"sync"
)

// Storage constants.
const (
	mutedUserListStoreVer = 0
	mutedUserListStoreKey = "mutedUserList"
)

// mutedUserKey identifies a user in the muted user list. It is derives from a
// user's Ed25519 public key.
type mutedUserKey string

type mutedUserManager struct {
	// List of muted users. This map keys on mutedUserKey (which is a string)
	// because json.Marshal requires the key be a string.
	userList map[mutedUserKey]struct{}

	mux sync.RWMutex
	kv  *versioned.KV
}

// newOrLoadMutedUserManager loads an existing mutedUserManager from storage, if
// it exists. Otherwise, it initialises a new empty mutedUserManager.
func newOrLoadMutedUserManager(kv *versioned.KV) (*mutedUserManager, error) {
	mum := newMutedUserManager(kv)

	err := mum.load()
	if err != nil && kv.Exists(err) {
		return nil, err
	}

	return mum, nil
}

// newMutedUserManager initializes a new and empty mutedUserManager.
func newMutedUserManager(kv *versioned.KV) *mutedUserManager {
	return &mutedUserManager{
		userList: make(map[mutedUserKey]struct{}),
		kv:       kv,
	}
}

// muteUser adds the user to the muted list.
func (mum *mutedUserManager) muteUser(userPubKey ed25519.PublicKey) {
	mum.mux.Lock()
	defer mum.mux.Unlock()

	mum.userList[makeMutedUserKey(userPubKey)] = struct{}{}
	if err := mum.save(); err != nil {
		jww.FATAL.Panicf("Failed to save list of muted users: %+v", err)
	}
}

// unmuteUser removes the user from the muted list.
func (mum *mutedUserManager) unmuteUser(userPubKey ed25519.PublicKey) {
	mum.mux.Lock()
	defer mum.mux.Unlock()

	delete(mum.userList, makeMutedUserKey(userPubKey))
	if err := mum.save(); err != nil {
		jww.FATAL.Panicf("Failed to save list of muted users: %+v", err)
	}
}

// isMuted returns true if the user is muted.
func (mum *mutedUserManager) isMuted(userPubKey ed25519.PublicKey) bool {
	mum.mux.RLock()
	_, exists := mum.userList[makeMutedUserKey(userPubKey)]
	mum.mux.RUnlock()
	return exists
}

// len returns the number of muted users.
func (mum *mutedUserManager) len() int {
	mum.mux.RLock()
	defer mum.mux.RUnlock()
	return len(mum.userList)
}

// save stores the muted user list to storage.
func (mum *mutedUserManager) save() error {
	data, err := json.Marshal(mum.userList)
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   mutedUserListStoreVer,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	return mum.kv.Set(mutedUserListStoreKey, obj)
}

// load retrieves the muted user list from storage.
func (mum *mutedUserManager) load() error {
	obj, err := mum.kv.Get(mutedUserListStoreKey, mutedUserListStoreVer)
	if err != nil {
		return err
	}

	return json.Unmarshal(obj.Data, &mum.userList)
}

// makeMutedUserKey generates a mutedUserKey from a user's Ed25519 public key,
func makeMutedUserKey(pubKey ed25519.PublicKey) mutedUserKey {
	return mutedUserKey(hex.EncodeToString(pubKey[:]))
}
