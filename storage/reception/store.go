package reception

import (
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/netTime"
	"golang.org/x/crypto/blake2b"
	"io"
	"sync"
	"time"
)

const receptionPrefix = "reception"
const receptionStoreStorageKey = "receptionStoreKey"
const receptionStoreStorageVersion = 0

type Store struct {
	// Identities which are being actively checked
	active  []*registration
	present map[idHash]struct{}

	kv *versioned.KV

	mux sync.Mutex
}

type storedReference struct {
	Eph        ephemeral.Id
	Source     *id.ID
	StartValid time.Time
}

type idHash [16]byte

func makeIdHash(ephID ephemeral.Id, source *id.ID) idHash {
	h, _ := blake2b.New256(nil)
	h.Write(ephID[:])
	h.Write(source.Bytes())
	idH := idHash{}
	copy(idH[:], h.Sum(nil))
	return idH
}

// NewStore creates a new reception store that starts empty.
func NewStore(kv *versioned.KV) *Store {
	s := &Store{
		active:  []*registration{},
		present: make(map[idHash]struct{}),
		kv:      kv.Prefix(receptionPrefix),
	}

	// Store the empty list
	if err := s.save(); err != nil {
		jww.FATAL.Panicf("Failed to save new reception store: %+v", err)
	}

	return s
}

func LoadStore(kv *versioned.KV) *Store {
	kv = kv.Prefix(receptionPrefix)

	// Load the versioned object for the reception list
	vo, err := kv.Get(receptionStoreStorageKey, receptionStoreStorageVersion)
	if err != nil {
		jww.FATAL.Panicf("Failed to get the reception storage list: %+v", err)
	}

	// JSON unmarshal identities list
	var identities []storedReference
	if err = json.Unmarshal(vo.Data, &identities); err != nil {
		jww.FATAL.Panicf("Failed to unmarshal the stored identity list: %+v", err)
	}

	s := &Store{
		active:  make([]*registration, len(identities)),
		present: make(map[idHash]struct{}, len(identities)),
		kv:      kv,
	}

	for i, sr := range identities {
		s.active[i], err = loadRegistration(sr.Eph, sr.Source, sr.StartValid, s.kv)
		if err != nil {
			jww.FATAL.Panicf("Failed to load registration for %s: %+v",
				regPrefix(sr.Eph, sr.Source, sr.StartValid), err)
		}
		s.present[makeIdHash(sr.Eph, sr.Source)] = struct{}{}
	}

	return s
}

func (s *Store) save() error {
	identities := s.makeStoredReferences()
	data, err := json.Marshal(&identities)
	if err != nil {
		return errors.WithMessage(err, "failed to store reception store")
	}

	// Create versioned object with data
	obj := &versioned.Object{
		Version:   receptionStoreStorageVersion,
		Timestamp: netTime.Now(),
		Data:      data,
	}

	err = s.kv.Set(receptionStoreStorageKey, receptionStoreStorageVersion, obj)
	if err != nil {
		return errors.WithMessage(err, "Failed to store reception store")
	}

	return nil
}

// makeStoredReferences generates a reference of any non-ephemeral identities
// for storage.
func (s *Store) makeStoredReferences() []storedReference {
	identities := make([]storedReference, len(s.active))

	i := 0
	for _, reg := range s.active {
		if !reg.Ephemeral {
			identities[i] = storedReference{
				Eph:        reg.EphId,
				Source:     reg.Source,
				StartValid: reg.StartValid.Round(0),
			}
			i++
		}
	}

	return identities[:i]
}

func (s *Store) GetIdentity(rng io.Reader, addressSize uint8) (IdentityUse, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	now := netTime.Now()

	// Remove any now expired identities
	s.prune(now)

	var identity IdentityUse
	var err error

	// If the list is empty, then we return a randomly generated identity to
	// poll with so we can continue tracking the network and to further
	// obfuscate network identities.
	if len(s.active) == 0 {
		identity, err = generateFakeIdentity(rng, addressSize, now)
		if err != nil {
			jww.FATAL.Panicf("Failed to generate a new ID when none "+
				"available: %+v", err)
		}
	} else {
		identity, err = s.selectIdentity(rng, now)
		if err != nil {
			jww.FATAL.Panicf("Failed to select an ID: %+v", err)
		}
	}

	return identity, nil
}

func (s *Store) AddIdentity(identity Identity) error {
	idH := makeIdHash(identity.EphId, identity.Source)
	s.mux.Lock()
	defer s.mux.Unlock()

	// Do not make duplicates of IDs
	if _, ok := s.present[idH]; ok {
		jww.DEBUG.Printf("Ignoring duplicate identity for %d (%s)",
			identity.EphId.Int64(), identity.Source)
		return nil
	}

	if identity.StartValid.After(identity.EndValid) {
		return errors.Errorf("Cannot add an identity which start valid "+
			"time (%s) is after its end valid time (%s)", identity.StartValid,
			identity.EndValid)
	}

	reg, err := newRegistration(identity, s.kv)
	if err != nil {
		return errors.WithMessage(err, "failed to add new identity to "+
			"reception store")
	}

	s.active = append(s.active, reg)
	s.present[idH] = struct{}{}
	if !identity.Ephemeral {
		if err := s.save(); err != nil {
			jww.FATAL.Panicf("Failed to save reception store after identity "+
				"addition: %+v", err)
		}
	}

	return nil
}

func (s *Store) RemoveIdentity(ephID ephemeral.Id) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for i, inQuestion := range s.active {
		if inQuestion.EphId == ephID {
			s.active = append(s.active[:i], s.active[i+1:]...)

			err := inQuestion.Delete()
			if err != nil {
				jww.FATAL.Panicf("Failed to delete identity: %+v", err)
			}

			if !inQuestion.Ephemeral {
				if err := s.save(); err != nil {
					jww.FATAL.Panicf("Failed to save reception store after "+
						"identity removal: %+v", err)
				}
			}

			return
		}
	}
}

func (s *Store) SetToExpire(addressSize uint8) {
	s.mux.Lock()
	defer s.mux.Unlock()

	expire := netTime.Now().Add(5 * time.Minute)

	for i, active := range s.active {
		if active.AddressSize < addressSize && active.EndValid.After(expire) {
			s.active[i].EndValid = expire
			err := s.active[i].store(s.kv)
			if err != nil {
				jww.ERROR.Printf("Failed to store identity %d: %+v", i, err)
			}
		}
	}
}

func (s *Store) prune(now time.Time) {
	lengthBefore := len(s.active)
	var pruned []int64

	// Prune the list
	for i := 0; i < len(s.active); i++ {
		inQuestion := s.active[i]
		if now.After(inQuestion.End) && inQuestion.ExtraChecks == 0 {
			if err := inQuestion.Delete(); err != nil {
				jww.ERROR.Printf("Failed to delete Identity for %s: %+v",
					inQuestion, err)
			}
			pruned = append(pruned, inQuestion.EphId.Int64())

			s.active = append(s.active[:i], s.active[i+1:]...)

			i--
		}
	}

	// Save the list if it changed
	if lengthBefore != len(s.active) {
		jww.INFO.Printf("Pruned %d identities [%+v]", lengthBefore-len(s.active), pruned)
		if err := s.save(); err != nil {
			jww.FATAL.Panicf("Failed to store reception storage: %+v", err)
		}
	}
}

func (s *Store) selectIdentity(rng io.Reader, now time.Time) (IdentityUse, error) {
	// Choose a member from the list
	var selected *registration

	if len(s.active) == 1 {
		selected = s.active[0]
	} else {
		seed := make([]byte, 32)
		if _, err := rng.Read(seed); err != nil {
			return IdentityUse{}, errors.WithMessage(err, "Failed to choose "+
				"ID due to RNG failure")
		}

		selectedNum := large.NewInt(1).Mod(
			large.NewIntFromBytes(seed),
			large.NewInt(int64(len(s.active))),
		)

		selected = s.active[selectedNum.Uint64()]
	}

	if now.After(selected.End) {
		selected.ExtraChecks--
	}

	jww.TRACE.Printf("Selected identity: EphId: %d  ID: %s  End: %s  "+
		"StartValid: %s  EndValid: %s",
		selected.EphId.Int64(), selected.Source,
		selected.End.Format("01/02/06 03:04:05 pm"),
		selected.StartValid.Format("01/02/06 03:04:05 pm"),
		selected.EndValid.Format("01/02/06 03:04:05 pm"))

	return IdentityUse{
		Identity: selected.Identity,
		Fake:     false,
		UR:       selected.UR,
		ER:       selected.ER,
		CR:       selected.CR,
	}, nil
}
