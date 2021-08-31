package reception

import (
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/primitives/netTime"
	"math/rand"
	// "strings"
	"testing"
	"time"
)

// func TestNewRegistration_Failed(t *testing.T) {
// 	// Generate an identity for use
// 	rng := rand.New(rand.NewSource(42))
// 	timestamp := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
// 	idu, _ := generateFakeIdentity(rng, 15, timestamp)
// 	id := idu.Identity
// 	kv := versioned.NewKV(make(ekv.Memstore))

// 	id.End = time.Time{}
// 	id.ExtraChecks = 0

// 	_, err := newRegistration(id, kv)
// 	if err == nil || !strings.Contains(err.Error(), "Cannot create a registration for an identity which has expired") {
// 		t.Error("Registration creation succeeded with expired identity.")
// 	}
// }

func TestNewRegistration_Ephemeral(t *testing.T) {
	// Generate an identity for use
	rng := rand.New(rand.NewSource(42))
	timestamp := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	idu, _ := generateFakeIdentity(rng, 15, timestamp)
	id := idu.Identity
	kv := versioned.NewKV(make(ekv.Memstore))

	id.End = netTime.Now().Add(1 * time.Hour)
	id.ExtraChecks = 2
	id.Ephemeral = true

	reg, err := newRegistration(id, kv)
	if err != nil {
		t.Fatalf("Registration creation failed when it should have "+
			"succeeded: %+v", err)
	}

	if _, err = reg.kv.Get(identityStorageKey, 0); err == nil {
		t.Error("Ephemeral identity stored the identity when it should not have.")
	}
}

func TestNewRegistration_Persistent(t *testing.T) {
	// Generate an identity for use
	rng := rand.New(rand.NewSource(42))
	timestamp := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	idu, _ := generateFakeIdentity(rng, 15, timestamp)
	id := idu.Identity
	kv := versioned.NewKV(make(ekv.Memstore))

	id.End = netTime.Now().Add(1 * time.Hour)
	id.ExtraChecks = 2
	id.Ephemeral = false

	reg, err := newRegistration(id, kv)
	if err != nil {
		t.Fatalf("Registration creation failed when it should have "+
			"succeeded: %+v", err)
	}

	if _, err = reg.kv.Get(identityStorageKey, 0); err != nil {
		t.Errorf("Persistent identity did not store the identity when "+
			"it should: %+v.", err)
	}
}

func TestLoadRegistration(t *testing.T) {
	// Generate an identity for use
	rng := rand.New(rand.NewSource(42))
	timestamp := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	idu, _ := generateFakeIdentity(rng, 15, timestamp)
	id := idu.Identity
	kv := versioned.NewKV(make(ekv.Memstore))

	id.End = netTime.Now().Add(1 * time.Hour)
	id.ExtraChecks = 2
	id.Ephemeral = false

	_, err := newRegistration(id, kv)
	if err != nil {
		t.Fatalf("Registration creation failed when it should have "+
			"succeeded: %+v", err)
	}

	_, err = loadRegistration(idu.EphId, idu.Source, idu.StartValid, kv)
	if err != nil {
		t.Fatalf("Registration loading failed: %+v", err)
	}

}

// TODO: finish
func Test_registration_Delete(t *testing.T) {
	// Generate an identity for use
	rng := rand.New(rand.NewSource(42))
	timestamp := time.Date(2009, 11, 17, 20, 34, 58, 651387237, time.UTC)
	idu, _ := generateFakeIdentity(rng, 15, timestamp)
	id := idu.Identity
	kv := versioned.NewKV(make(ekv.Memstore))

	id.End = netTime.Now().Add(1 * time.Hour)
	id.ExtraChecks = 2
	id.Ephemeral = false

	r, err := newRegistration(id, kv)
	if err != nil {
		t.Fatalf("Registration creation failed when it should have "+
			"succeeded: %+v", err)
	}

	err = r.Delete()
	if err != nil {
		t.Errorf("delete() returned an error: %+v", err)
	}
}
