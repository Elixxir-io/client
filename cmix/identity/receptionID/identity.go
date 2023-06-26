////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package receptionID

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/collective/versioned"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/netTime"
)

const identityStorageKey = "IdentityStorage"
const identityStorageVersion = 0

type EphemeralIdentity struct {
	// Identity
	EphID  ephemeral.Id `json:"ephID"`
	Source *id.ID       `json:"source"`
}

type Identity struct {
	// Identity
	EphemeralIdentity
	AddressSize uint8 `json:"addressSize"`

	/* Usage variables */
	// End is the timestamp when active polling will stop.
	End time.Time `json:"end"`
	// ExtraChecks is the number of extra checks executed as active after the ID
	// exits active.
	ExtraChecks uint `json:"extraChecks"`

	/* Polling parameters */
	// StartValid is the timestamp when the ephemeral ID begins being valid
	StartValid time.Time `json:"startValid"`
	// EndValid is the timestamp when the ephemeral ID stops being valid
	EndValid time.Time `json:"endValid"`

	// Ephemeral makes the identity not stored on disk.
	Ephemeral bool `json:"ephemeral"`

	// When this identity expired, it will auto add ProcessNext to the identity
	// list to be processed. In practice, this is a reverse ordered list and is
	// added whenever many identities are added at once in order to pick up
	// sequentially.
	ProcessNext *Identity `json:"processNext"`
}

func loadIdentity(kv versioned.KV) (Identity, error) {
	obj, err := kv.Get(identityStorageKey, identityStorageVersion)
	if err != nil {
		return Identity{}, errors.WithMessage(err, "Failed to load Identity")
	}

	r := Identity{}
	err = json.Unmarshal(obj.Data, &r)
	if err != nil {
		return Identity{}, errors.WithMessage(err, "Failed to unmarshal Identity")
	}

	return r, nil
}

func (i Identity) store(kv versioned.KV) error {
	// Marshal the registration
	regStr, err := json.Marshal(&i)
	if err != nil {
		return errors.WithMessage(err, "Failed to marshal Identity")
	}

	// Create versioned object with data
	obj := &versioned.Object{
		Version:   identityStorageVersion,
		Timestamp: netTime.Now(),
		Data:      regStr,
	}

	// Store the data
	err = kv.Set(identityStorageKey, obj)
	if err != nil {
		return errors.WithMessage(err, "Failed to store Identity")
	}

	return nil
}

func (i Identity) delete(kv versioned.KV) error {
	return kv.Delete(identityStorageKey, identityStorageVersion)
}

// String returns a string representations of the ephemeral ID and source ID of
// the Identity. This function adheres to the fmt.Stringer interface.
func (i Identity) String() string {
	return strconv.FormatInt(i.EphID.Int64(), 16) + " " + i.Source.String()
}

// GoString returns a string representations of all the values in the Identity.
// This function adheres to the fmt.GoStringer interface.
func (i Identity) GoString() string {
	str := []string{
		"EphID:" + strconv.FormatInt(i.EphID.Int64(), 16),
		"Source:" + i.Source.String(),
		"AddressSize:" + strconv.FormatUint(uint64(i.AddressSize), 10),
		"End:" + i.End.String(),
		"ExtraChecks:" + strconv.FormatUint(uint64(i.ExtraChecks), 10),
		"StartValid:" + i.StartValid.String(),
		"EndValid:" + i.EndValid.String(),
		"Ephemeral:" + strconv.FormatBool(i.Ephemeral),
	}

	return "{" + strings.Join(str, ", ") + "}"
}

func (i Identity) Equal(b Identity) bool {
	return i.EphID == b.EphID &&
		i.Source.Cmp(b.Source) &&
		i.AddressSize == b.AddressSize &&
		i.End.Equal(b.End) &&
		i.ExtraChecks == b.ExtraChecks &&
		i.StartValid.Equal(b.StartValid) &&
		i.EndValid.Equal(b.EndValid) &&
		i.Ephemeral == b.Ephemeral
}

// BuildIdentityFromRound returns an EphemeralIdentity that the source would
// use to receive messages from the given round
func BuildIdentityFromRound(source *id.ID,
	round rounds.Round) EphemeralIdentity {
	ephID, _, _, _ := ephemeral.GetId(source, uint(round.AddressSpaceSize),
		round.Timestamps[states.QUEUED].UnixNano())
	jww.INFO.Printf("BuildIdentityFromRound for %s: %d %d %d",
		source, ephID.Int64(), round.AddressSpaceSize,
		round.Timestamps[states.QUEUED].UnixNano())
	return EphemeralIdentity{
		EphID:  ephID,
		Source: source,
	}
}
