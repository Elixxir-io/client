///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package ud

import (
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/elixxir/primitives/fact"
	"reflect"
	"sort"
	"testing"
)

func TestNewStore(t *testing.T) {

	kv := versioned.NewKV(make(ekv.Memstore))

	_, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

}

//
//func TestStore_StoreFact(t *testing.T) {
//	kv := versioned.NewKV(make(ekv.Memstore))
//
//	expectedStore, err := NewStore(kv)
//	if err != nil {
//		t.Errorf("NewStore() produced an error: %v", err)
//	}
//
//	expected := fact.Fact{
//		Fact: "josh",
//		T:    fact.Username,
//	}
//
//	err = expectedStore.ConfirmFact(expected)
//	if err != nil {
//		t.Fatalf("ConfirmFact() produced an error: %v", err)
//	}
//
//	_, exists := expectedStore.confirmedFacts[expected]
//	if !exists {
//		t.Fatalf("Fact %s does not exist in map", expected)
//	}
//
//}

func TestStore_DeleteFact(t *testing.T) {
	kv := versioned.NewKV(make(ekv.Memstore))

	expectedStore, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

	expected := fact.Fact{
		Fact: "josh",
		T:    fact.Username,
	}

	expectedStore.confirmedFacts[expected] = struct{}{}

	_, exists := expectedStore.confirmedFacts[expected]
	if !exists {
		t.Fatalf("Fact %s does not exist in map", expected)
	}

	err = expectedStore.DeleteFact(expected)
	if err != nil {
		t.Fatalf("DeleteFact() produced an error: %v", err)
	}

	err = expectedStore.DeleteFact(expected)
	if err == nil {
		t.Fatalf("DeleteFact should produce an error when deleting a fact not in store")
	}

}

func TestStore_BackUpMissingFacts(t *testing.T) {
	kv := versioned.NewKV(make(ekv.Memstore))

	expectedStore, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

	email := fact.Fact{
		Fact: "josh@elixxir.io",
		T:    fact.Email,
	}

	phone := fact.Fact{
		Fact: "6175555678",
		T:    fact.Phone,
	}

	err = expectedStore.BackUpMissingFacts(email, phone)
	if err != nil {
		t.Fatalf("BackUpMissingFacts() produced an error: %v", err)
	}

	_, exists := expectedStore.confirmedFacts[email]
	if !exists {
		t.Fatalf("Fact %v not found in store.", email)
	}

	_, exists = expectedStore.confirmedFacts[phone]
	if !exists {
		t.Fatalf("Fact %v not found in store.", phone)
	}

}

func TestStore_BackUpMissingFacts_DuplicateFactType(t *testing.T) {
	kv := versioned.NewKV(make(ekv.Memstore))

	expectedStore, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

	email := fact.Fact{
		Fact: "josh@elixxir.io",
		T:    fact.Email,
	}

	phone := fact.Fact{
		Fact: "6175555678",
		T:    fact.Phone,
	}

	err = expectedStore.BackUpMissingFacts(email, phone)
	if err != nil {
		t.Fatalf("BackUpMissingFacts() produced an error: %v", err)
	}

	err = expectedStore.BackUpMissingFacts(email, fact.Fact{})
	if err == nil {
		t.Fatalf("BackUpMissingFacts() should not allow backing up an "+
			"email when an email has already been backed up: %v", err)
	}

	err = expectedStore.BackUpMissingFacts(fact.Fact{}, phone)
	if err == nil {
		t.Fatalf("BackUpMissingFacts() should not allow backing up a "+
			"phone number when a phone number has already been backed up: %v", err)
	}

}

func TestStore_GetFacts(t *testing.T) {
	kv := versioned.NewKV(make(ekv.Memstore))

	testStore, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

	emailFact := fact.Fact{
		Fact: "josh@elixxir.io",
		T:    fact.Email,
	}

	emptyFact := fact.Fact{}

	err = testStore.BackUpMissingFacts(emailFact, emptyFact)
	if err != nil {
		t.Fatalf("Faild to add fact %v: %v", emailFact, err)
	}

	phoneFact := fact.Fact{
		Fact: "6175555212",
		T:    fact.Phone,
	}

	err = testStore.BackUpMissingFacts(emptyFact, phoneFact)
	if err != nil {
		t.Fatalf("Faild to add fact %v: %v", phoneFact, err)
	}

	expectedFacts := []fact.Fact{emailFact, phoneFact}

	receivedFacts := testStore.GetFacts()

	sort.SliceStable(receivedFacts, func(i, j int) bool {
		return receivedFacts[i].Fact > receivedFacts[j].Fact
	})

	sort.SliceStable(expectedFacts, func(i, j int) bool {
		return expectedFacts[i].Fact > expectedFacts[j].Fact
	})

	if !reflect.DeepEqual(expectedFacts, receivedFacts) {
		t.Fatalf("GetFacts() did not return expected fact list."+
			"\nExpected: %v"+
			"\nReceived: %v", expectedFacts, receivedFacts)
	}
}

func TestStore_GetFactStrings(t *testing.T) {
	kv := versioned.NewKV(make(ekv.Memstore))

	testStore, err := NewStore(kv)
	if err != nil {
		t.Errorf("NewStore() produced an error: %v", err)
	}

	emailFact := fact.Fact{
		Fact: "josh@elixxir.io",
		T:    fact.Email,
	}

	emptyFact := fact.Fact{}

	err = testStore.BackUpMissingFacts(emailFact, emptyFact)
	if err != nil {
		t.Fatalf("Faild to add fact %v: %v", emailFact, err)
	}

	phoneFact := fact.Fact{
		Fact: "6175555212",
		T:    fact.Phone,
	}

	err = testStore.BackUpMissingFacts(emptyFact, phoneFact)
	if err != nil {
		t.Fatalf("Faild to add fact %v: %v", phoneFact, err)
	}

	expectedFacts := []string{emailFact.Stringify(), phoneFact.Stringify()}

	receivedFacts := testStore.GetStringifiedFacts()
	sort.SliceStable(receivedFacts, func(i, j int) bool {
		return receivedFacts[i] > receivedFacts[j]
	})

	sort.SliceStable(expectedFacts, func(i, j int) bool {
		return expectedFacts[i] > expectedFacts[j]
	})

	if !reflect.DeepEqual(expectedFacts, receivedFacts) {
		t.Fatalf("GetStringifiedFacts() did not return expected fact list."+
			"\nExpected: %v"+
			"\nReceived: %v", expectedFacts, receivedFacts)
	}

}
