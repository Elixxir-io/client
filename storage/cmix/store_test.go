///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"testing"
)

// Happy path
func TestNewStore(t *testing.T) {
	kv := make(ekv.Memstore)
	vkv := versioned.NewKV(kv)

	grp := cyclic.NewGroup(large.NewInt(173), large.NewInt(2))
	priv := grp.NewInt(2)
	pub := diffieHellman.GeneratePublicKey(priv, grp)

	store, err := NewStore(grp, vkv, priv)
	if err != nil {
		t.Fatal(err.Error())
	}

	if store.nodes == nil {
		t.Errorf("Failed to initialize nodes")
	}
	if store.GetDHPrivateKey() == nil || store.GetDHPrivateKey().Cmp(priv) != 0 {
		t.Errorf("Failed to set store.dhPrivateKey correctly")
	}
	if store.GetDHPublicKey() == nil || store.GetDHPublicKey().Cmp(pub) != 0 {
		t.Errorf("Failed to set store.dhPublicKey correctly")
	}
	if store.grp == nil {
		t.Errorf("Failed to set store.grp")
	}
	if store.kv == nil {
		t.Errorf("Failed to set store.kv")
	}
}

// Happy path Add/Done test
func TestStore_AddRemove(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, _ := makeTestStore()

	nodeId := id.NewIdFromString("test", id.Node, t)
	key := testStore.grp.NewInt(5)

	testStore.Add(nodeId, key)
	if _, exists := testStore.nodes[*nodeId]; !exists {
		t.Fatal("Failed to add node key")
	}

	testStore.Remove(nodeId)
	if _, exists := testStore.nodes[*nodeId]; exists {
		t.Fatal("Failed to remove node key")
	}
}


// Happy path Add/Has test
func TestStore_AddHas(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, _ := makeTestStore()

	nodeId := id.NewIdFromString("test", id.Node, t)
	key := testStore.grp.NewInt(5)

	testStore.Add(nodeId, key)
	if _, exists := testStore.nodes[*nodeId]; !exists {
		t.Fatal("Failed to add node key")
	}

	if !testStore.Has(nodeId) {
		t.Fatal("cannot find the node id that that was added")
	}
}

// Tests that has returns false when it doesnt have
func TestStore_DoesntHave(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, _ := makeTestStore()

	nodeId := id.NewIdFromString("test", id.Node, t)

	if testStore.Has(nodeId) {
		t.Fatal("found the node when it shouldnt have been found")
	}
}

// Happy path
func TestLoadStore(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, kv := makeTestStore()

	// Add a test node key
	nodeId := id.NewIdFromString("test", id.Node, t)
	key := testStore.grp.NewInt(5)

	testStore.Add(nodeId, key)

	// Load the store and check its attributes
	store, err := LoadStore(kv)
	if err != nil {
		t.Fatalf("Unable to load store: %+v", err)
	}
	if store.GetDHPublicKey().Cmp(testStore.GetDHPublicKey()) != 0 {
		t.Errorf("LoadStore failed to load public key")
	}
	if store.GetDHPrivateKey().Cmp(testStore.GetDHPrivateKey()) != 0 {
		t.Errorf("LoadStore failed to load public key")
	}
	if len(store.nodes) != len(testStore.nodes) {
		t.Errorf("LoadStore failed to load node keys")
	}
}

// Happy path
func TestStore_GetRoundKeys(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, _ := makeTestStore()
	// Set up the circuit
	numIds := 10
	nodeIds := make([]*id.ID, numIds)
	for i := 0; i < numIds; i++ {
		nodeIds[i] = id.NewIdFromUInt(uint64(i)+1, id.Node, t)
		key := testStore.grp.NewInt(int64(i) + 1)
		testStore.Add(nodeIds[i], key)

		// This is wack but it cleans up after the test
		defer testStore.Remove(nodeIds[i])
	}

	circuit := connect.NewCircuit(nodeIds)
	result, missing := testStore.GetRoundKeys(circuit)
	if len(missing) != 0 {
		t.Errorf("Expected to have no missing keys, got %d", len(missing))
	}
	if result == nil || len(result.keys) != numIds {
		t.Errorf("Expected to have %d node keys", numIds)
	}
}

// Missing keys path
func TestStore_GetRoundKeys_Missing(t *testing.T) {
	// Uncomment to print keys that Set and Get are called on
	// jww.SetStdoutThreshold(jww.LevelTrace)

	testStore, _ := makeTestStore()
	// Set up the circuit
	numIds := 10
	nodeIds := make([]*id.ID, numIds)
	for i := 0; i < numIds; i++ {
		nodeIds[i] = id.NewIdFromUInt(uint64(i)+1, id.Node, t)
		key := testStore.grp.NewInt(int64(i) + 1)

		// Only add every other node so there are missing nodes
		if i%2 == 0 {
			testStore.Add(nodeIds[i], key)
			testStore.Add(nodeIds[i], key)

			// This is wack but it cleans up after the test
			defer testStore.Remove(nodeIds[i])
		}
	}

	circuit := connect.NewCircuit(nodeIds)
	result, missing := testStore.GetRoundKeys(circuit)
	if len(missing) != numIds/2 {
		t.Errorf("Expected to have %d missing keys, got %d", numIds/2, len(missing))
	}
	if result != nil {
		t.Errorf("Expected nil value for result due to missing keys!")
	}
}

// Happy path.
func TestStore_Count(t *testing.T) {
	vkv := versioned.NewKV(make(ekv.Memstore))
	grp := cyclic.NewGroup(large.NewInt(173), large.NewInt(2))

	store, err := NewStore(grp, vkv, grp.NewInt(2))
	if err != nil {
		t.Fatalf("Failed to generate new Store: %+v", err)
	}

	if store.Count() != 0 {
		t.Errorf("Count() did not return the expected value for a new Store."+
			"\nexpected: %d\nreceived: %d", 0, store.Count())
	}

	count := 50
	for i := 0; i < count; i++ {
		store.Add(id.NewIdFromUInt(uint64(i), id.Node, t), grp.NewInt(int64(42+i)))
	}

	if store.Count() != count {
		t.Errorf("Count() did not return the expected value."+
			"\nexpected: %d\nreceived: %d", count, store.Count())
	}
}

// Main testing function.
func makeTestStore() (*Store, *versioned.KV) {

	kv := make(ekv.Memstore)
	vkv := versioned.NewKV(kv)

	grp := cyclic.NewGroup(large.NewInt(173), large.NewInt(2))
	priv := grp.NewInt(2)

	testStore, _ := NewStore(grp, vkv, priv)

	return testStore, vkv
}
