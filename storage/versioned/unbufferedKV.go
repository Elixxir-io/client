///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package versioned

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/xx_network/primitives/id"
	"strconv"
)

const PrefixSeparator = "/"

// MakePartnerPrefix creates a string prefix to denote who a conversation or
// relationship is with.
func MakePartnerPrefix(id *id.ID) string {
	return "Partner:" + id.String()
}

// UnbufferedKV stores versioned data and Upgrade functions.
type UnbufferedKV struct {
	r      *root
	prefix string
}

type root struct {
	data ekv.KeyValue
}

// NewUnbufferedKV creates a versioned key/value store backed by something
// implementing ekv.KeyValue.
func NewUnbufferedKV(data ekv.KeyValue) *UnbufferedKV {
	return &UnbufferedKV{
		r: &root{data},
	}
}

// Get gets and upgrades data stored in the unbuffered key/value store. Make
// sure to inspect the version returned inside the versioned object.
func (ukv *UnbufferedKV) Get(key string, version uint64) (*Object, error) {
	key = ukv.makeKey(key, version)
	jww.TRACE.Printf("Get %p with key %v", ukv.r.data, key)

	// Get raw data
	result := Object{}
	err := ukv.r.data.Get(key, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetAndUpgrade gets and upgrades data stored in the unbuffered key/value
// store. Make sure to inspect the version returned inside the versioned object.
func (ukv *UnbufferedKV) GetAndUpgrade(key string, ut UpgradeTable) (*Object, error) {
	version := ut.CurrentVersion
	baseKey := key
	key = ukv.makeKey(baseKey, version)

	if uint64(len(ut.Table)) != version {
		jww.FATAL.Panicf("Cannot get upgrade for %s: table length (%d) does "+
			"not match current version (%d)", key, len(ut.Table), version)
	}

	// NOTE: Upgrades do not happen on the current version, so we check to see
	// if version-1, version-2, and so on exist to find out if an earlier
	// version of this object exists.
	version++
	var result *Object
	for version != 0 {
		version--
		key = ukv.makeKey(baseKey, version)
		jww.TRACE.Printf("Get %p with key %v", ukv.r.data, key)

		// Get raw data
		result = &Object{}
		err := ukv.r.data.Get(key, result)
		if err == nil {
			// Break when we find the *newest* version of the object in the data
			// store
			break
		}
	}

	if result == nil || len(result.Data) == 0 {
		return nil, errors.Errorf(
			"Failed to get key and upgrade it for %s",
			ukv.makeKey(baseKey, ut.CurrentVersion))
	}

	var err error
	initialVersion := result.Version
	for result.Version < uint64(len(ut.Table)) {
		oldVersion := result.Version
		result, err = ut.Table[oldVersion](result)
		if err != nil || oldVersion == result.Version {
			jww.FATAL.Panicf("failed to upgrade key %s from "+
				"version %v, initial version %v", key,
				oldVersion, initialVersion)
		}
	}

	return result, nil
}

// Delete removes a given key from the unbuffered key/value store.
func (ukv *UnbufferedKV) Delete(key string, version uint64) error {
	key = ukv.makeKey(key, version)
	jww.TRACE.Printf("delete %p with key %v", ukv.r.data, key)
	return ukv.r.data.Delete(key)
}

// Set upserts new data into the unbuffered key/value store. When calling this,
// you are responsible for prefixing the key with the correct type optionally
// unique ID! Call Prefix to do so.
func (ukv *UnbufferedKV) Set(key string, version uint64, object *Object) error {
	key = ukv.makeKey(key, version)
	jww.TRACE.Printf("Set %p with key %v", ukv.r.data, key)
	return ukv.r.data.Set(key, object)
}

// Prefix returns a new UnbufferedKV with the new prefix.
func (ukv *UnbufferedKV) Prefix(prefix string) *UnbufferedKV {
	kvPrefix := UnbufferedKV{
		r:      ukv.r,
		prefix: ukv.prefix + prefix + PrefixSeparator,
	}
	return &kvPrefix
}

// GetFullKey returns the key with all prefixes appended.
func (ukv *UnbufferedKV) GetFullKey(key string, version uint64) string {
	return ukv.makeKey(key, version)
}

func (ukv *UnbufferedKV) makeKey(key string, version uint64) string {
	return ukv.prefix + key + "_" + strconv.FormatUint(version, 10)
}
