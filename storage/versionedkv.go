package storage

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Make key with a data type and a version
// TODO We might need a separator string here, or a fixed number of digits available to the version string
//  Otherwise version 10 could be mistaken for version 1! Bad news
//  For now, let's hope a semicolon won't be part of the rest of the key
//  It's not in base64, so maybe it will be fine
func MakeKeyPrefix(dataType string, version uint64) string {
	return dataType + strconv.FormatUint(version, 10) + ";"
}

type Marshaller interface {
	Marshal() ([]byte, error)
}

type Unmarshaller interface {
	Unmarshal([]byte) error
}

type KeyValue interface {
	Set(key string, objectToStore Marshaller) error
	Get(key string, loadIntoThisObject Unmarshaller) error
	// Are these useful?
	SetInterface(key string, objectToStore interface{}) error
	GetInterface(key string) (interface{}, error)
}

type VersionedObject struct {
	// Used to determine version upgrade, if any
	Version uint64

	// Marshal to/from time.Time using Time.MarshalText and Time.UnmarshalText
	Timestamp []byte

	// Serialized version of original object
	Data []byte
}

func (v *VersionedObject) Unmarshal(data []byte) error {
	return json.Unmarshal(data, v)
}

func (v *VersionedObject) Marshal() ([]byte, error) {
	return json.Marshal(v)
}

type upgrade func(key string, oldObject *VersionedObject) (*VersionedObject, error)

// VersionedKV
type VersionedKV struct {
	upgradeTable map[string]upgrade
	data         KeyValue
}

// Create a versioned key/value store backed by data
func NewVersionedKV(data KeyValue) *VersionedKV {
	newKV := new(VersionedKV)
	// Add new upgrade functions to this upgrade table
	newKV.upgradeTable = make(map[string]upgrade)
	// All upgrade functions should upgrade to the latest version. You can call older upgrade functions if you need to
	// Upgrade functions don't change the key or store the upgraded version of the data in the key/value store.
	// There's no mechanism built in for this -- users should always make the key prefix before calling Set,
	// and if they want the upgraded data persisted they should call Set with the upgraded data.
	newKV.upgradeTable[MakeKeyPrefix("test", 0)] = func(key string, oldObject *VersionedObject) (*VersionedObject, error) {
		return &VersionedObject{
			Version: 1,
			// Unsure if upgrade functions should always change timestamp to time.Now
			Timestamp: oldObject.Timestamp,
			Data:      []byte("this object was upgraded from v0 to v1"),
		}, nil
	}
	newKV.data = data
	return newKV
}

// Get gets and upgrades data stored in the key/value store
// Make sure to inspect the version returned in the versioned object
func (v *VersionedKV) Get(key string) (*VersionedObject, error) {
	// Get raw data
	result := VersionedObject{}
	err := v.data.Get(key, &result)
	if err != nil {
		return nil, err
	}
	// If the key starts with a version tag that we can find in the table,
	// we should call that function to upgrade it
	for version, upgrade := range v.upgradeTable {
		if strings.HasPrefix(key, version) {
			// We should run this upgrade function
			// The user of this function must update the key based on the version returned in this versioned object!
			return upgrade(key, &result)
		}
	}
	return &result, nil
}

// Set() upserts new data into the storage
// When calling this, you are responsible for prefixing the key with the correct type and version!
// Call MakeKeyPrefix() to do so.
func (v *VersionedKV) Set(key string, object *VersionedObject) error {
	return v.data.Set(key, object)
}
