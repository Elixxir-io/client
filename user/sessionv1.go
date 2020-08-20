package user

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/globals"
	"gitlab.com/elixxir/client/keyStore"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/switchboard"
	"gitlab.com/xx_network/primitives/id"
	"sync"
)

// Struct holding relevant session data
type SessionObjV1 struct {
	// Currently authenticated user
	CurrentUser *UserV1

	Keys             map[id.ID]NodeKeys
	RSAPrivateKey    *rsa.PrivateKey
	RSAPublicKey     *rsa.PublicKey
	CMIXDHPrivateKey *cyclic.Int
	CMIXDHPublicKey  *cyclic.Int
	E2EDHPrivateKey  *cyclic.Int
	E2EDHPublicKey   *cyclic.Int
	CmixGrp          *cyclic.Group
	E2EGrp           *cyclic.Group
	Salt             []byte

	// Last received message ID. Check messages after this on the gateway.
	LastMessageID string

	//Interface map for random data storage
	InterfaceMap map[string]interface{}

	// E2E KeyStore
	KeyMaps *keyStore.KeyStore

	// Rekey Manager
	RekeyManager *keyStore.RekeyManager

	// Non exported fields (not GOB encoded/decoded)
	// Local pointer to storage of this session
	store globals.Storage

	// Switchboard
	listeners *switchboard.Switchboard

	// Quit channel for message reception runner
	quitReceptionRunner chan struct{}

	lock sync.Mutex

	// The password used to encrypt this session when saved
	password string

	//The validation signature provided by permissioning
	regValidationSignature []byte

	// Buffer of messages that cannot be decrypted
	garbledMessages []*format.Message

	RegState *uint32

	storageLocation uint8

	ContactsByValue map[string]SearchedUserRecord
}

// Struct representing a User in the system
type UserV1 struct {
	User  *id.ID
	Nick  string
	Email string
}

// ConvertSessionV1toV2 converts the session object from version 1 to version 2.
// This conversion includes:
//  1. Changing the RegState values to the new integer values (1 to 2000, and 2
//     to 3000).
func ConvertSessionV1toV2(inputWrappedSession *SessionStorageWrapper) (*SessionStorageWrapper, error) {
	//extract teh session from the wrapper
	var sessionBytes bytes.Buffer

	//get the old session object
	sessionBytes.Write(inputWrappedSession.Session)
	dec := gob.NewDecoder(&sessionBytes)

	sessionV1 := SessionObjV1{}

	err := dec.Decode(&sessionV1)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to decode session")
	}

	sessionV2 := SessionObj{}

	// Convert RegState to new values
	if *sessionV1.RegState == 1 {
		*sessionV1.RegState = 2000
	} else if *sessionV1.RegState == 2 {
		*sessionV1.RegState = 3000
	}

	sessionV2.KeyMaps = sessionV1.KeyMaps
	sessionV2.RekeyManager = sessionV1.RekeyManager

	//re encode the session
	var sessionBuffer bytes.Buffer

	enc := gob.NewEncoder(&sessionBuffer)

	err = enc.Encode(sessionV2)

	if err != nil {
		err = errors.New(fmt.Sprintf("ConvertSessionV1toV2: Could not "+
			" store session v2: %s", err.Error()))
		return nil, err
	}

	//build the session wrapper
	ssw := SessionStorageWrapper{
		Version:   2,
		Timestamp: inputWrappedSession.Timestamp,
		Session:   sessionBuffer.Bytes(),
	}

	return &ssw, nil
}
