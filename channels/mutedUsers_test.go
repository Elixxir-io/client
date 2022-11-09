////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package channels

import (
	"crypto/ed25519"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/ekv"
	"io"
	"math/rand"
	"os"
	"reflect"
	"testing"
)

// Tests that newOrLoadMutedUserManager initialises a new empty mutedUserManager
// when called for the first time and that it loads the mutedUserManager from
// storage after the original has been saved.
func Test_newOrLoadMutedUserManager(t *testing.T) {
	prng := rand.New(rand.NewSource(32))
	kv := versioned.NewKV(ekv.MakeMemstore())
	expected := newMutedUserManager(kv)

	mum, err := newOrLoadMutedUserManager(kv)
	if err != nil {
		t.Errorf("Failed to create new mutedUserManager: %+v", err)
	}

	if !reflect.DeepEqual(expected, mum) {
		t.Errorf("New mutedUserManager does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, mum)
	}

	mum.muteUser(makeEd25519PubKey(prng, t))

	loadedMum, err := newOrLoadMutedUserManager(kv)
	if err != nil {
		t.Errorf("Failed to load mutedUserManager: %+v", err)
	}

	if !reflect.DeepEqual(mum, loadedMum) {
		t.Errorf("Loaded mutedUserManager does not match expected."+
			"\nexpected: %+v\nreceived: %+v", mum, loadedMum)
	}
}

// Tests that newMutedUserManager returns the new expected mutedUserManager.
func Test_newMutedUserManager(t *testing.T) {
	kv := versioned.NewKV(ekv.MakeMemstore())
	expected := &mutedUserManager{
		userList: make(map[mutedUserKey]struct{}),
		kv:       kv,
	}

	mum := newMutedUserManager(kv)

	if !reflect.DeepEqual(expected, mum) {
		t.Errorf("New mutedUserManager does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, mum)
	}
}

// Tests that mutedUserManager.muteUser adds all the users to the list and that
// all the users are saved to storage.
func Test_mutedUserManager_muteUser(t *testing.T) {
	prng := rand.New(rand.NewSource(189))
	kv := versioned.NewKV(ekv.MakeMemstore())
	mum := newMutedUserManager(kv)

	expected := make(map[mutedUserKey]struct{})

	for i := 0; i < 10; i++ {
		pubKey := makeEd25519PubKey(prng, t)
		expected[makeMutedUserKey(pubKey)] = struct{}{}
		mum.muteUser(pubKey)
	}

	if !reflect.DeepEqual(expected, mum.userList) {
		t.Errorf("User list does not match expected."+
			"\nexpected: %s\nreceived: %s", expected, mum.userList)
	}

	newMum := newMutedUserManager(mum.kv)
	if err := newMum.load(); err != nil {
		t.Fatalf("Failed to load user list: %+v", err)
	}

	if !reflect.DeepEqual(expected, newMum.userList) {
		t.Errorf("Loaded mutedUserManager does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expected, newMum.userList)
	}
}

// Tests that mutedUserManager.unmuteUser removes all muted users from the list
// and that all the users are removed from storage.
func Test_mutedUserManager_unmuteUser(t *testing.T) {
	prng := rand.New(rand.NewSource(189))
	kv := versioned.NewKV(ekv.MakeMemstore())
	mum := newMutedUserManager(kv)

	expected := make(map[mutedUserKey]ed25519.PublicKey)

	for i := 0; i < 10; i++ {
		pubKey := makeEd25519PubKey(prng, t)
		expected[makeMutedUserKey(pubKey)] = pubKey
		mum.muteUser(pubKey)
	}
	for key, pubKey := range expected {
		mum.unmuteUser(pubKey)

		if _, exists := mum.userList[key]; exists {
			t.Errorf("User %s not removed from list.", key)
		}
	}

	if len(mum.userList) != 0 {
		t.Errorf(
			"%d not removed from list: %v", len(mum.userList), mum.userList)
	}

	newMum := newMutedUserManager(mum.kv)
	if err := newMum.load(); err != nil {
		t.Fatalf("Failed to load user list: %+v", err)
	}

	if len(newMum.userList) != 0 {
		t.Errorf("%d not removed from loaded list: %v",
			len(newMum.userList), newMum.userList)
	}
}

// Tests that mutedUserManager.isMuted only returns true for users in the list.
func Test_mutedUserManager_isMuted(t *testing.T) {
	prng := rand.New(rand.NewSource(189))
	kv := versioned.NewKV(ekv.MakeMemstore())
	mum := newMutedUserManager(kv)

	expected := make([]ed25519.PublicKey, 20)

	for i := range expected {
		pubKey := makeEd25519PubKey(prng, t)
		expected[i] = pubKey
		if i%2 == 0 {
			mum.muteUser(pubKey)
		}
	}

	for i, pubKey := range expected {
		if i%2 == 0 && !mum.isMuted(pubKey) {
			t.Errorf("User %x is not muted when they should be.", pubKey)
		} else if i%2 != 0 && mum.isMuted(pubKey) {
			t.Errorf("User %x is muted when they should not be.", pubKey)
		}
	}
}

// Tests that mutedUserManager.len returns the correct length for an empty user
// list and a user list with users added.
func TestIsNicknameValid_mutedUserManager_len(t *testing.T) {
	prng := rand.New(rand.NewSource(189))
	kv := versioned.NewKV(ekv.MakeMemstore())
	mum := newMutedUserManager(kv)

	if mum.len() != 0 {
		t.Errorf("New mutedUserManager has incorrect length."+
			"\nexpected: %d\nreceived: %d", 0, mum.len())
	}

	mum.muteUser(makeEd25519PubKey(prng, t))
	mum.muteUser(makeEd25519PubKey(prng, t))
	mum.muteUser(makeEd25519PubKey(prng, t))

	if mum.len() != 3 {
		t.Errorf("mutedUserManager has incorrect length."+
			"\nexpected: %d\nreceived: %d", 3, mum.len())
	}
}

// Tests that the mutedUserManager can be saved and loaded from storage using
// mutedUserManager.save and mutedUserManager.load.
func Test_mutedUserManager_save_load(t *testing.T) {
	prng := rand.New(rand.NewSource(189))
	mum := &mutedUserManager{
		userList: map[mutedUserKey]struct{}{
			makeMutedUserKey(makeEd25519PubKey(prng, t)): {},
			makeMutedUserKey(makeEd25519PubKey(prng, t)): {},
			makeMutedUserKey(makeEd25519PubKey(prng, t)): {},
			makeMutedUserKey(makeEd25519PubKey(prng, t)): {},
			makeMutedUserKey(makeEd25519PubKey(prng, t)): {},
		},
		kv: versioned.NewKV(ekv.MakeMemstore()),
	}

	err := mum.save()
	if err != nil {
		t.Fatalf("Failed to save user list: %+v", err)
	}

	newMum := newMutedUserManager(mum.kv)
	err = newMum.load()
	if err != nil {
		t.Fatalf("Failed to load user list: %+v", err)
	}

	if !reflect.DeepEqual(mum, newMum) {
		t.Errorf("Loaded mutedUserManager does not match expected."+
			"\nexpected: %+v\nreceived: %+v", mum, newMum)
	}
}

// Error path: Tests that mutedUserManager.load returns an error when there is
// nothing to load from storage.
func Test_mutedUserManager_load_StorageLoadError(t *testing.T) {
	mum := newMutedUserManager(versioned.NewKV(ekv.MakeMemstore()))
	err := mum.load()
	if err == nil || mum.kv.Exists(err) {
		t.Errorf("Did not get expected error when loading a user list that "+
			"does not exist.\nexpected: %s\nreceived: %+v", os.ErrNotExist, err)
	}
}

// Consistency test of makeMutedUserKey.
func Test_makeMutedUserKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(953))

	expectedKeys := []mutedUserKey{
		"c5c110ded852439379bb28e01f8d8d0355c5795c27a4d8900a4e56334fe9f501",
		"a86958de4e9e8c1f4f1dc9c236ad8b799899823a8f9da8ba0c5e190e96c7221c",
		"7da41b27cbd8c5008d7fa40077bcbbffb34805f8be45556506da0f00d9621e01",
		"a2e7062f6d50ca8a2bce840ac0b654ad9ba3dfdf2094a5e5255f3cdfaeb4a1f4",
		"605f307875c0889bb0495c5c4f743f5cd41cf9384a60cea2336443bc28f2c084",
		"ec0e906d3617294907694e7b7c121bafe7b802d6c6103f4481a408d8a5c2c81c",
		"e1b4cd55c9c3e9bee635e89151f93ea6cad9fc4c340460d426773a043a98fb31",
		"91fb296f961cddb189e13cd60e4fc83910944d10e3adc07e8615611feaf2ce64",
		"b967cb95a305c991910006139c27c8d455ee8dfdb4d3b1bf4b2ae1a4866020c7",
		"d7849701f641d0265df39f7716c209b8aa0cf24308cc89a14d4afd0012581996",
	}

	for i, expected := range expectedKeys {
		pubKey := makeEd25519PubKey(prng, t)
		key := makeMutedUserKey(pubKey)

		if key != expected {
			t.Errorf("mutedUserKey does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, key)
		}
	}
}

// makeEd25519PubKey generates an ed25519.PublicKey for testing.
func makeEd25519PubKey(rng io.Reader, t *testing.T) ed25519.PublicKey {
	pubKey, _, err := ed25519.GenerateKey(rng)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 keys: %+v", err)
	}
	return pubKey
}
