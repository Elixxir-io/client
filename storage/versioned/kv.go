////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package versioned

type KV interface {
	// Prefix returns a new UnbufferedKV with the new prefix.
	Prefix(prefix string) *UnbufferedKV

	// Set upserts new data into the unbuffered key/value store. When calling
	// this, you are responsible for prefixing the key with the correct type
	// optionally unique ID! Call Prefix to do so.
	Set(key string, version uint64, object *Object) error

	// Get gets and upgrades data stored in the unbuffered key/value store. Make
	// sure to inspect the version returned inside the versioned object.
	Get(key string, version uint64) (*Object, error)

	// GetAndUpgrade gets and upgrades data stored in the unbuffered key/value
	// store. Make sure to inspect the version returned inside the versioned
	// object.
	GetAndUpgrade(key string, ut UpgradeTable) (*Object, error)

	// Delete removes a given key from the unbuffered key/value store.
	Delete(key string, version uint64) error

	// GetFullKey returns the key with all prefixes appended.
	GetFullKey(key string, version uint64) string
}

// Upgrade functions must be of this type.
type Upgrade func(oldObject *Object) (*Object, error)

type UpgradeTable struct {
	CurrentVersion uint64
	Table          []Upgrade
}
