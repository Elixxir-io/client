package collective

import (
	"encoding/json"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/ekv"
)

// StoreMapElement stores a versioned map element into the KV. This relies
// on the underlying remote [KV.StoreMapElement] function to lock and control
// updates, but it uses [versioned.Object] values.
// All Map storage functions update the remote.
func (r *internalKV) StoreMapElement(mapName, element string,
	value []byte) error {
	elementsMap := make(map[string][]byte)
	elementsMap[element] = value
	return r.txLog.WriteMap(mapName, elementsMap, nil)
}

// StoreMap saves each element of the map, then updates the map structure
// and deletes no longer used keys in the map.
// All Map storage functions update the remote.
func (r *internalKV) StoreMap(mapName string, value map[string][]byte) error {
	return r.txLog.WriteMap(mapName, value, nil)
}

// GetMapElement looks up the element for the given map
func (r *internalKV) GetMapElement(mapName, element string) ([]byte, error) {
	mapKey := versioned.MakeMapKey(mapName)
	elementKey := versioned.MakeElementKey(mapName, element)

	keys := []string{elementKey, mapKey}

	op := func(old map[string]ekv.Value) (updates map[string]ekv.Value, err error) {
		return nil, errors.New("dummy")
	}

	old, _, _ := r.local.MutualTransaction(keys, op)

	mapFile, err := getMapFile(old[mapKey], 100)
	if err != nil {
		return nil, errors.WithMessage(err, "map file could not be found")
	}
	if !mapFile.Has(elementKey) {
		return nil, errors.New("element not found in map")
	}
	elementValue := old[elementKey]
	if !elementValue.Exists {
		return nil, errors.New("failed to get element from disk")
	}

	return elementValue.Data, nil
}

// GetMap get an entire map from disk
func (r *internalKV) GetMap(mapName string) (map[string][]byte, error) {
	mapKey := versioned.MakeMapKey(mapName)

	mapFileBytes, err := r.local.GetBytes(mapKey)
	if err != nil {
		return nil, errors.WithMessage(err, "could not find map")
	}

	mapFile, err := getMapFile(ekv.Value{
		Data:   mapFileBytes,
		Exists: true,
	}, 100)
	if err != nil {
		return nil, errors.WithMessage(err, "map file could not be found")
	}

	keys := make([]string, 0, mapFile.Length())
	for key := range mapFile {
		keys = append(keys, key)
	}

	op := func(old map[string]ekv.Value) (updates map[string]ekv.Value, err error) {
		return nil, errors.New("dummy")
	}

	old, _, _ := r.MutualTransaction(keys, op)

	m := make(map[string][]byte)
	for key, value := range old {
		if value.Exists {
			m[key] = value.Data
		}
	}

	return m, nil
}

func getMapFile(mapFileValue ekv.Value, length int) (set, error) {
	mapFile := newSet(uint(length))
	if mapFileValue.Exists {
		err := mapFile.UnmarshalJSON(mapFileValue.Data)
		if err != nil {
			return nil, err
		}
	}
	return mapFile, nil
}

// set object to allow for easier implementation of map operations
type set map[string]struct{}

func newSet(size uint) set {
	if size == 0 {
		return make(set)
	} else {
		return make(set, size)
	}
}

func (ks set) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &set{})
}

func (ks set) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ks)
}

func (ks set) Has(element string) bool {
	_, ok := ks[element]
	return ok
}

func (ks set) Add(element string) {
	ks[element] = struct{}{}
}

func (ks set) Delete(element string) {
	delete(ks, element)
}

func (ks set) Length() int {
	return len(ks)
}