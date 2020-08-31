package e2e

import (
	"errors"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/csprng"
	dh "gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/ekv"
	"testing"
)

func TestSession_generate_noPrivateKeyReceive(t *testing.T) {

	grp := getGroup()
	rng := csprng.NewSystemRNG()
	partnerPrivKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, grp, rng)
	partnerPubKey := dh.GeneratePublicKey(partnerPrivKey, grp)

	//create context objects for general use
	fps := newFingerprints()
	ctx := &context{
		fa:  &fps,
		grp: grp,
		kv:  versioned.NewKV(make(ekv.Memstore)),
	}

	//build the session
	s := &Session{
		partnerPubKey: partnerPubKey,
		params:        GetDefaultSessionParams(),
		manager: &Manager{
			ctx: ctx,
		},
		t: Receive,
	}

	//run the generate command
	s.generate()

	//check that it generated a private key
	if s.myPrivKey == nil {
		t.Errorf("Private key was not generated when missing")
	}

	//verify the basekey is correct
	expectedBaseKey := dh.GenerateSessionKey(s.myPrivKey, s.partnerPubKey, grp)

	if expectedBaseKey.Cmp(s.baseKey) != 0 {
		t.Errorf("generated base key does not match expected base key")
	}

	//verify the ttl was generated
	if s.ttl == 0 {
		t.Errorf("ttl not generated")
	}

	//verify keystates where created
	if s.keyState == nil {
		t.Errorf("keystates not generated")
	}

	//verify keys were registered in the fingerprintMap
	for keyNum := uint32(0); keyNum < s.keyState.numkeys; keyNum++ {
		key := newKey(s, keyNum)
		if _, ok := fps.toKey[key.Fingerprint()]; !ok {
			t.Errorf("key %v not in fingerprint map", keyNum)
		}
	}
}

func TestSession_generate_PrivateKeySend(t *testing.T) {

	grp := getGroup()
	rng := csprng.NewSystemRNG()
	partnerPrivKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, grp, rng)
	partnerPubKey := dh.GeneratePublicKey(partnerPrivKey, grp)

	myPrivKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, grp, rng)

	//create context objects for general use
	fps := newFingerprints()
	ctx := &context{
		fa:  &fps,
		grp: grp,
		kv:  versioned.NewKV(make(ekv.Memstore)),
	}

	//build the session
	s := &Session{
		myPrivKey:     myPrivKey,
		partnerPubKey: partnerPubKey,
		params:        GetDefaultSessionParams(),
		manager: &Manager{
			ctx: ctx,
		},
		t: Send,
	}

	//run the generate command
	s.generate()

	//check that it generated a private key
	if s.myPrivKey.Cmp(myPrivKey) != 0 {
		t.Errorf("Public key was generated when not missing")
	}

	//verify the basekey is correct
	expectedBaseKey := dh.GenerateSessionKey(s.myPrivKey, s.partnerPubKey, grp)

	if expectedBaseKey.Cmp(s.baseKey) != 0 {
		t.Errorf("generated base key does not match expected base key")
	}

	//verify the ttl was generated
	if s.ttl == 0 {
		t.Errorf("ttl not generated")
	}

	//verify keystates where created
	if s.keyState == nil {
		t.Errorf("keystates not generated")
	}

	//verify keys were not registered in the fingerprintMap
	for keyNum := uint32(0); keyNum < s.keyState.numkeys; keyNum++ {
		key := newKey(s, keyNum)
		if _, ok := fps.toKey[key.Fingerprint()]; ok {
			t.Errorf("key %v in fingerprint map", keyNum)
		}
	}
}

// Shows that newSession can result in all the fields being populated
func TestNewSession(t *testing.T) {
	// Make a test session to easily populate all the fields
	sessionA, _ := makeTestSession(t)
	// Make a new session with the variables we got from makeTestSession
	sessionB := newSession(sessionA.manager, sessionA.myPrivKey, sessionA.partnerPubKey, sessionA.params, sessionA.t)

	err := cmpSerializedFields(sessionA, sessionB)
	if err != nil {
		t.Error(err)
	}
	// For everything else, just make sure it's populated
	if sessionB.keyState == nil {
		t.Error("newSession should populate keyState")
	}
	if sessionB.manager == nil {
		t.Error("newSession should populate manager")
	}
	if sessionB.ttl == 0 {
		t.Error("newSession should populate ttl")
	}
}

// Shows that loadSession can result in all the fields being populated
func TestSession_Load(t *testing.T) {
	// Make a test session to easily populate all the fields
	sessionA, _ := makeTestSession(t)
	err := sessionA.save()
	if err != nil {
		t.Fatal(err)
	}
	// Load another, hopefully identical session from the storage
	sessionB, err := loadSession(sessionA.manager, makeSessionKey(sessionA.GetID()))
	if err != nil {
		t.Fatal(err)
	}
	err = cmpSerializedFields(sessionA, sessionB)
	if err != nil {
		t.Error(err)
	}
	// Key state should also be loaded and equivalent to the other session
	// during loadSession()
	err = cmpKeyState(sessionA.keyState, sessionB.keyState)
	if err != nil {
		t.Error(err)
	}
	// For everything else, just make sure it's populated
	if sessionB.manager == nil {
		t.Error("load should populate manager")
	}
	if sessionB.ttl == 0 {
		t.Error("load should populate ttl")
	}
}

func cmpKeyState(a *stateVector, b *stateVector) error {
	// ignore ctx, mux
	if a.key != b.key {
		return errors.New("keys differed")
	}
	if a.numAvailable != b.numAvailable {
		return errors.New("numAvailable differed")
	}
	if a.firstAvailable != b.firstAvailable {
		return errors.New("firstAvailable differed")
	}
	if a.numkeys != b.numkeys {
		return errors.New("numkeys differed")
	}
	if len(a.vect) != len(b.vect) {
		return errors.New("vect differed")
	}
	for i := range a.vect {
		if a.vect[i] != b.vect[i] {
			return errors.New("vect differed")
		}
	}
	return nil
}

// Create a new session. Marshal and unmarshal it
func TestSession_Serialization(t *testing.T) {
	s, ctx := makeTestSession(t)
	sSerialized, err := s.marshal()
	if err != nil {
		t.Fatal(err)
	}

	sDeserialized := &Session{
		manager: &Manager{ctx: ctx},
	}
	err = sDeserialized.unmarshal(sSerialized)
	if err != nil {
		t.Fatal(err)
	}

}

// compare fields also represented in SessionDisk
// fields not represented in SessionDisk shouldn't be expected to be populated by Unmarshal
func cmpSerializedFields(a *Session, b *Session) error {
	if a.negotiationStatus != b.negotiationStatus {
		return errors.New("confirmed differed")
	}
	if a.t != b.t {
		return errors.New("t differed")
	}
	if a.params.MaxKeys != b.params.MaxKeys {
		return errors.New("maxKeys differed")
	}
	if a.params.MinKeys != b.params.MinKeys {
		return errors.New("minKeys differed")
	}
	if a.params.NumRekeys != b.params.NumRekeys {
		return errors.New("numRekeys differed")
	}
	if a.params.MinNumKeys != b.params.MinNumKeys {
		return errors.New("minNumKeys differed")
	}
	if a.params.TTLScalar != b.params.TTLScalar {
		return errors.New("ttlScalar differed")
	}
	if a.baseKey.Cmp(b.baseKey) != 0 {
		return errors.New("baseKey differed")
	}
	if a.myPrivKey.Cmp(b.myPrivKey) != 0 {
		return errors.New("myPrivKey differed")
	}
	if a.partnerPubKey.Cmp(b.partnerPubKey) != 0 {
		return errors.New("partnerPubKey differed")
	}
	return nil
}

// PopKey should return a new key from this session
func TestSession_PopKey(t *testing.T) {
	s, _ := makeTestSession(t)
	key, err := s.PopKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Error("PopKey should have returned non-nil key")
	}
	if key.session != s {
		t.Error("Key should record it belongs to this session")
	}
	// PopKey should return the first available key
	if key.keyNum != 0 {
		t.Error("First key popped should have keynum 0")
	}
}

// Delete should remove unused keys from this session
func TestSession_Delete(t *testing.T) {
	s, _ := makeTestSession(t)
	err := s.save()
	if err != nil {
		t.Fatal(err)
	}
	s.Delete()

	// Getting the keys that should have been stored should now result in an error
	_, err = s.manager.ctx.kv.Get(makeStateVectorKey(keyEKVPrefix, s.GetID()))
	if err == nil {
		t.Error("State vector was gettable")
	}
	_, err = s.manager.ctx.kv.Get(makeSessionKey(s.GetID()))
	if err == nil {
		t.Error("Session was gettable")
	}
}

// PopKey should return an error if it's time for this session to rekey
// or if the key state vector is out of keys
// Unfortunately, the key state vector being out of keys is something
// that will also get caught by the other error first. So it's only practical
// to test the one error.
func TestSession_PopKey_Error(t *testing.T) {
	s, ctx := makeTestSession(t)
	// Construct a specific state vector that will quickly run out of keys
	var err error
	s.keyState, err = newStateVector(ctx, makeStateVectorKey(keyEKVPrefix, s.GetID()), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PopKey()
	if err == nil {
		t.Fatal("PopKey should have returned an error")
	}
	t.Log(err)
}

// PopRekey should return the next key
// There's no boundary, except for the number of keynums in the state vector
func TestSession_PopReKey(t *testing.T) {
	s, _ := makeTestSession(t)
	key, err := s.PopReKey()
	if err != nil {
		t.Fatal("PopKey should have returned an error")
	}
	if key == nil {
		t.Error("Key should be non-nil")
	}
	if key.session != s {
		t.Error("Key should record it belongs to this session")
	}
	// PopReKey should return the first available key
	if key.keyNum != 0 {
		t.Error("First key popped should have keynum 0")
	}
}

// PopRekey should not return the next key if there are no more keys available
// in the state vector
func TestSession_PopReKey_Err(t *testing.T) {
	s, ctx := makeTestSession(t)
	// Construct a specific state vector that will quickly run out of keys
	var err error
	s.keyState, err = newStateVector(ctx, makeStateVectorKey(keyEKVPrefix, s.GetID()), 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PopReKey()
	if err == nil {
		t.Fatal("PopReKey should have returned an error")
	}
}

// Simple test that shows the base key can get got
func TestSession_GetBaseKey(t *testing.T) {
	s, _ := makeTestSession(t)
	baseKey := s.GetBaseKey()
	if baseKey.Cmp(s.baseKey) != 0 {
		t.Errorf("expected %v, got %v", baseKey.Text(16), s.baseKey.Text(16))
	}
}

// Smoke test for GetID
func TestSession_GetID(t *testing.T) {
	s, _ := makeTestSession(t)
	id := s.GetID()
	if len(id.Bytes()) == 0 {
		t.Error("Zero length for session ID!")
	}
}

// Smoke test for GetPartnerPubKey
func TestSession_GetPartnerPubKey(t *testing.T) {
	s, _ := makeTestSession(t)
	partnerPubKey := s.GetPartnerPubKey()
	if partnerPubKey.Cmp(s.partnerPubKey) != 0 {
		t.Errorf("expected %v, got %v", partnerPubKey.Text(16), s.partnerPubKey.Text(16))
	}
}

// Smoke test for GetMyPrivKey
func TestSession_GetMyPrivKey(t *testing.T) {
	s, _ := makeTestSession(t)
	myPrivKey := s.GetMyPrivKey()
	if myPrivKey.Cmp(s.myPrivKey) != 0 {
		t.Errorf("expected %v, got %v", myPrivKey.Text(16), s.myPrivKey.Text(16))
	}
}

// Shows that IsConfirmed returns whether the session is confirmed
func TestSession_IsConfirmed(t *testing.T) {
	s, _ := makeTestSession(t)
	s.negotiationStatus = Unconfirmed
	if s.IsConfirmed() {
		t.Error("s was confirmed when it shouldn't have been")
	}
	s.negotiationStatus = Confirmed
	if !s.IsConfirmed() {
		t.Error("s wasn't confirmed when it should have been")
	}
}

// IsReKeyNeeded only returns true once, when the number of keys available is
// equal to the TTL. If it returned true after the TTL, it could result in
// additional, unnecessary rekeys.
func TestSession_IsReKeyNeeded(t *testing.T) {
	s, _ := makeTestSession(t)
	s.keyState.numAvailable = s.ttl
	if !s.IsReKeyNeeded() {
		t.Error("Rekey should be needed if the number available is the TTL")
	}
	s.keyState.numAvailable = s.ttl + 1
	if s.IsReKeyNeeded() {
		t.Error("Rekey shouldn't be needed in this case")
	}
	s.keyState.numAvailable = s.ttl - 1
	if s.IsReKeyNeeded() {
		t.Error("Rekey shouldn't be needed in this case")
	}
}

// Shows that Status can result in all possible statuses
func TestSession_Status(t *testing.T) {
	s, ctx := makeTestSession(t)
	var err error
	s.keyState, err = newStateVector(ctx, makeStateVectorKey(keyEKVPrefix, s.GetID()), 500)
	if err != nil {
		t.Fatal(err)
	}
	s.keyState.numAvailable = 0
	if s.Status() != RekeyEmpty {
		t.Error("status should have been rekey empty with no keys left")
	}
	s.keyState.numAvailable = 1
	if s.Status() != Empty {
		t.Error("Status should have been empty")
	}
	// Passing the ttl should result in a rekey being needed
	s.keyState.numAvailable = s.keyState.numkeys - s.ttl
	if s.Status() != RekeyNeeded {
		t.Error("Just past the ttl, rekey should be needed")
	}
	s.keyState.numAvailable = s.keyState.numkeys
	if s.Status() != Active {
		t.Error("If all keys available, session should be active")
	}
}

// After a Confirm call, confirmed should be true
func TestConfirm(t *testing.T) {
	s, _ := makeTestSession(t)
	s.confirmed = false
	err := s.confirm()
	if err != nil {
		t.Fatal(err)
	}
	if !s.confirmed {
		t.Error("Should be confirmed after confirming")
	}
}

// Make a default test session with some things populated
func makeTestSession(t *testing.T) (*Session, *context) {
	grp := getGroup()
	rng := csprng.NewSystemRNG()
	partnerPrivKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, grp, rng)
	partnerPubKey := dh.GeneratePublicKey(partnerPrivKey, grp)
	myPrivKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, grp, rng)
	baseKey := dh.GenerateSessionKey(myPrivKey, partnerPubKey, grp)

	//create context objects for general use
	fps := newFingerprints()
	ctx := &context{
		fa:  &fps,
		grp: grp,
		kv:  versioned.NewKV(make(ekv.Memstore)),
	}

	s := &Session{
		baseKey:       baseKey,
		myPrivKey:     myPrivKey,
		partnerPubKey: partnerPubKey,
		params:        GetDefaultSessionParams(),
		manager: &Manager{
			ctx: ctx,
		},
		t:                 Receive,
		negotiationStatus: Confirmed,
		ttl:               5,
	}
	var err error
	s.keyState, err = newStateVector(ctx, makeStateVectorKey(keyEKVPrefix, s.GetID()), 1024)
	if err != nil {
		panic(err)
	}
	return s, ctx
}
