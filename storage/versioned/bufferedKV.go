////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package versioned

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/stoppable"
	"sync"
	"sync/atomic"
	"time"
)

type BufferedKV struct {
	kv *UnbufferedKV
	*bufferedKV
}

type bufferedKV struct {
	buffer        atomic.Value
	bufferEnabled *uint32
	rate          time.Duration
}

type storedValue struct {
	object   *Object
	version  uint64
	deletion bool
}

const bkvStoppableName = "BufferedKV"

func (bkv *BufferedKV) StoreProcesses() stoppable.Stoppable {
	stop := stoppable.NewSingle(bkvStoppableName)

	go func() {
		var done bool
		ticker := time.NewTicker(bkv.rate)
		for !done {

			select {
			case <-stop.Quit():
				done = true
				atomic.StoreUint32(bkv.bufferEnabled, 0)
			case <-ticker.C:

			}

			timer := time.NewTimer(bkv.rate)
			timerChan := make(chan struct{}, 1)

			go func() {
				select {
				case <-timer.C:
					jww.FATAL.Panicf("Failed to execute writes on BufferedKV "+
						"StoreProcesses after %s", bkv.rate)
				case <-timerChan:

				}
			}()

			var newSM *sync.Map
			sm := bkv.buffer.Swap(newSM).(*sync.Map)
			var errors []error
			var i int
			sm.Range(func(keyInterface, valueInterface interface{}) bool {
				i++
				key := keyInterface.(string)
				value := valueInterface.(*storedValue)
				if value.deletion {
					err := bkv.kv.Delete(key, value.version)
					if err != nil {
						errors = append(errors, err)
					}
				} else {
					err := bkv.kv.Set(key, value.version, value.object)
					if err != nil {
						errors = append(errors, err)
					}
				}
				return true
			})

			timerChan <- struct{}{}

			if len(errors) > 0 {
				jww.FATAL.Panicf("%d errors occurred when writing %d queued "+
					"writes to disk: %+v", len(errors), i, errors)
			}

			break
		}
	}()

	return stop
}

// Get gets and upgrades data stored in the key/value store. Make sure to
// inspect the version returned inside the versioned object.
func (bkv *BufferedKV) Get(key string, version uint64) (*Object, error) {
	sm := bkv.buffer.Load().(*sync.Map)

	newKey := bkv.kv.makeKey(key, version)
	val, ok := sm.Load(newKey)
	if ok {
		jww.TRACE.Printf("Get queued %p with key %v", bkv.kv.r.data, newKey)
		return val.(*Object), nil
	}

	return bkv.kv.Get(key, version)
}

// Delete removes a given key from the data store.
func (bkv *BufferedKV) Delete(key string, version uint64) error {
	if atomic.LoadUint32(bkv.bufferEnabled) == 0 {
		return bkv.kv.Delete(key, version)
	}

	sm := bkv.buffer.Load().(*sync.Map)

	newKey := bkv.kv.makeKey(key, version)
	sm.Store(newKey, &storedValue{
		object:   nil,
		version:  version,
		deletion: true,
	})

	jww.TRACE.Printf("Delete buffer %p with key %v", bkv.kv.r.data, key)

	return nil
}

// Set upserts new data into the storage. When calling this, you are responsible
// for prefixing the key with the correct type optionally unique ID! Call
// MakeKeyWithPrefix() to do so.
func (bkv *BufferedKV) Set(key string, version uint64, object *Object) error {
	if atomic.LoadUint32(bkv.bufferEnabled) == 0 {
		return bkv.kv.Set(key, version, object)
	}

	sm := bkv.buffer.Load().(*sync.Map)

	newKey := bkv.kv.makeKey(key, version)
	sm.Store(newKey, &storedValue{
		object:   object,
		version:  version,
		deletion: false,
	})

	jww.TRACE.Printf("Set queued %p with key %v", bkv.kv.r.data, key)

	return nil
}

// GetAndUpgrade gets and upgrades data stored in the key/value store. Make sure
// to inspect the version returned inside the versioned object.
// TODO: implement this
func (bkv *BufferedKV) GetAndUpgrade(_ string, _ UpgradeTable) (*Object, error) {
	jww.FATAL.Panicf("Implement me!")
	return nil, nil
}

// Prefix returns a new UnbufferedKV with the new prefix.
func (bkv *BufferedKV) Prefix(prefix string) *BufferedKV {
	kvPrefix := BufferedKV{
		kv:         bkv.kv.Prefix(prefix),
		bufferedKV: bkv.bufferedKV,
	}
	return &kvPrefix
}

// GetFullKey returns the key with all prefixes appended.
func (bkv *BufferedKV) GetFullKey(key string, version uint64) string {
	return bkv.kv.makeKey(key, version)
}
