///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package versioned

import (
	"bytes"
	"errors"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/primitives/netTime"
	"testing"
)

// UnbufferedKV.Get should call the Upgrade function when it is available.
func TestUnbufferedKV_Get_Error(t *testing.T) {
	vkv := NewUnbufferedKV(make(ekv.Memstore))
	key := vkv.GetFullKey("test", 0)
	result, err := vkv.Get(key, 0)
	if err == nil {
		t.Error("Getting a key that didn't exist should have returned an error")
	}
	if result != nil {
		t.Error("Getting a key that didn't exist shouldn't have returned data")
	}
}

// Test UnbufferedKV.GetAndUpgrade happy path.
func TestUnbufferedKV_GetAndUpgrade(t *testing.T) {
	// Set up a dummy UnbufferedKV with the required data
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	key := vkv.GetFullKey("test", 0)
	original := Object{
		Version:   0,
		Timestamp: netTime.Now(),
		Data:      []byte("not upgraded"),
	}
	originalSerialized := original.Marshal()
	kv[key] = originalSerialized

	upgrade := []Upgrade{func(oldObject *Object) (*Object, error) {
		return &Object{
			Version:   1,
			Timestamp: netTime.Now(),
			Data:      []byte("this object was upgraded from v0 to v1"),
		}, nil
	}}

	result, err := vkv.GetAndUpgrade("test", UpgradeTable{1, upgrade})
	if err != nil {
		t.Fatalf("Error getting something that should have been in: %v", err)
	}
	if !bytes.Equal(result.Data,
		[]byte("this object was upgraded from v0 to v1")) {
		t.Errorf("Upgrade should have overwritten data. result data: %q",
			result.Data)
	}
}

// Test UnbufferedKV.GetAndUpgrade key not found path.
func TestUnbufferedKV_GetAndUpgrade_KeyNotFound(t *testing.T) {
	// Set up a dummy UnbufferedKV with the required data
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	key := "test"

	upgrade := []Upgrade{func(oldObject *Object) (*Object, error) {
		return &Object{
			Version:   1,
			Timestamp: netTime.Now(),
			Data:      []byte("this object was upgraded from v0 to v1"),
		}, nil
	}}

	_, err := vkv.GetAndUpgrade(key, UpgradeTable{1, upgrade})
	if err == nil {
		t.Fatalf("Error getting something that shouldn't be there!")
	}
}

// Test UnbufferedKV.GetAndUpgrade returns error path.
func TestUnbufferedKV_GetAndUpgrade_UpgradeReturnsError(t *testing.T) {
	// Set up a dummy UnbufferedKV with the required data
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	key := vkv.GetFullKey("test", 0)
	original := Object{
		Version:   0,
		Timestamp: netTime.Now(),
		Data:      []byte("not upgraded"),
	}
	originalSerialized := original.Marshal()
	kv[key] = originalSerialized

	upgrade := []Upgrade{func(oldObject *Object) (*Object, error) {
		return &Object{}, errors.New("test error")
	}}

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	_, _ = vkv.GetAndUpgrade("test", UpgradeTable{1, upgrade})
}

// Test UnbufferedKV.Delete key happy path.
func TestUnbufferedKV_Delete(t *testing.T) {
	// Set up a dummy UnbufferedKV with the required data
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	key := vkv.GetFullKey("test", 0)
	original := Object{
		Version:   0,
		Timestamp: netTime.Now(),
		Data:      []byte("not upgraded"),
	}
	originalSerialized := original.Marshal()
	kv[key] = originalSerialized

	err := vkv.Delete("test", 0)
	if err != nil {
		t.Fatalf("Error getting something that should have been in: %v", err)
	}

	if _, ok := kv[key]; ok {
		t.Fatal("Key still exists in kv map")
	}
}

// Test UnbufferedKV.Get without Upgrade path.
func TestUnbufferedKV_Get(t *testing.T) {
	// Set up a dummy UnbufferedKV with the required data
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	originalVersion := uint64(0)
	key := vkv.GetFullKey("test", originalVersion)
	original := Object{
		Version:   originalVersion,
		Timestamp: netTime.Now(),
		Data:      []byte("not upgraded"),
	}
	originalSerialized := original.Marshal()
	kv[key] = originalSerialized

	result, err := vkv.Get("test", originalVersion)
	if err != nil {
		t.Fatalf("Error getting something that should have been in: %v", err)
	}
	if !bytes.Equal(result.Data, []byte("not upgraded")) {
		t.Errorf("Upgrade should not have overwritten data. result data: %q",
			result.Data)
	}
}

// Test that UnbufferedKV.Set puts data in the store.
func TestUnbufferedKV_Set(t *testing.T) {
	kv := make(ekv.Memstore)
	vkv := NewUnbufferedKV(kv)
	originalVersion := uint64(1)
	key := vkv.GetFullKey("test", originalVersion)
	original := Object{
		Version:   originalVersion,
		Timestamp: netTime.Now(),
		Data:      []byte("not upgraded"),
	}
	err := vkv.Set("test", originalVersion, &original)
	if err != nil {
		t.Fatal(err)
	}

	// Store should now have data in it at that key
	_, ok := kv[key]
	if !ok {
		t.Error("data store didn't have anything in the key")
	}
}
