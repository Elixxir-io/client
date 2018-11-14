////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package user

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"gitlab.com/elixxir/client/globals"
	"gitlab.com/elixxir/crypto/cyclic"
	"math/rand"
	"time"
	"gitlab.com/elixxir/crypto/id"
)

// Errors
var ErrQuery = errors.New("element not in map")

// Globally instantiated Session
// FIXME remove this sick filth
var TheSession Session

// Interface for User Session operations
type Session interface {
	GetCurrentUser() (currentUser *User)
	GetGWAddress() string
	SetGWAddress(addr string)
	GetKeys() []NodeKeys
	GetPrivateKey() *cyclic.Int
	GetPublicKey() *cyclic.Int
	GetLastMessageID() string
	SetLastMessageID(id string)
	StoreSession() error
	Immolate() error
	UpsertMap(key string, element interface{}) error
	QueryMap(key string) (interface{}, error)
	DeleteMap(key string) error
	LockStorage()
	UnlockStorage()
}

type NodeKeys struct {
	PublicKey        *cyclic.Int
	TransmissionKeys RatchetKey
	ReceptionKeys    RatchetKey
	ReceiptKeys      RatchetKey
	ReturnKeys       RatchetKey
}

type RatchetKey struct {
	Base      *cyclic.Int
	Recursive *cyclic.Int
}

// Creates a new Session interface for registration
func NewSession(u *User, GatewayAddr string, nk []NodeKeys) Session {

	// With an underlying Session data structure
	return Session(&SessionObj{
		CurrentUser:  u,
		GWAddress:    GatewayAddr, // FIXME: don't store this here
		Keys:         nk,
		PrivateKey:   cyclic.NewMaxInt(),
		InterfaceMap: make(map[string]interface{}),
	})

}

func LoadSession(UID *id.UserID) (Session, error) {
	if globals.LocalStorage == nil {
		err := errors.New("StoreSession: Local Storage not avalible")
		return nil, err
	}

	rand.Seed(time.Now().UnixNano())

	sessionGob := globals.LocalStorage.Load()

	var sessionBytes bytes.Buffer

	sessionBytes.Write(sessionGob)

	dec := gob.NewDecoder(&sessionBytes)

	session := SessionObj{}

	err := dec.Decode(&session)

	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSession: unable to load session: %s", err.Error()))
		return nil, err
	}

	if *session.CurrentUser.UserID != *UID {
		err = errors.New(fmt.Sprintf(
			"LoadSession: loaded incorrect "+
				"user; Expected: %q; Received: %q",
			*session.CurrentUser.UserID, *UID))
		return nil, err
	}

	TheSession = &session

	return &session, nil
}

// Struct holding relevant session data
type SessionObj struct {
	// Currently authenticated user
	CurrentUser *User

	// Gateway address to the cMix network
	GWAddress string

	Keys       []NodeKeys
	PrivateKey *cyclic.Int

	// Last received message ID. Check messages after this on the gateway.
	LastMessageID string

	//Interface map for random data storage
	InterfaceMap map[string]interface{}
}

func (s *SessionObj) GetLastMessageID() string {
	return s.LastMessageID
}

func (s *SessionObj) SetLastMessageID(id string) {
	s.LastMessageID = id
}

func (s *SessionObj) GetKeys() []NodeKeys {
	return s.Keys
}

func (s *SessionObj) GetPrivateKey() *cyclic.Int {
	return s.PrivateKey
}

func (s *SessionObj) GetPublicKey() *cyclic.Int {
	return cyclic.NewMaxInt()
}

// Return a copy of the current user
func (s *SessionObj) GetCurrentUser() (currentUser *User) {
	if s.CurrentUser != nil {
		// Explicit deep copy
		currentUser = &User{
			UserID: s.CurrentUser.UserID,
			Nick:   s.CurrentUser.Nick,
		}
	}
	return
}

func (s *SessionObj) GetGWAddress() string {
	return s.GWAddress
}

func (s *SessionObj) SetGWAddress(addr string) {
	s.GWAddress = addr
}

func (s *SessionObj) storeSession() error {

	if globals.LocalStorage == nil {
		err := errors.New("StoreSession: Local Storage not available")
		return err
	}

	var session bytes.Buffer

	enc := gob.NewEncoder(&session)

	err := enc.Encode(s)

	if err != nil {
		err = errors.New(fmt.Sprintf("StoreSession: Could not encode user"+
			" session: %s", err.Error()))
		return err
	}

	err = globals.LocalStorage.Save(session.Bytes())

	if err != nil {

		err = errors.New(fmt.Sprintf("StoreSession: Could not save the encoded user"+
			" session: %s", err.Error()))
		return err
	}

	return nil

}

func (s *SessionObj) StoreSession() error {
	globals.LocalStorage.Lock()
	err := s.storeSession()
	globals.LocalStorage.Unlock()
	return err
}

// Immolate scrubs all cryptographic data from ram and logs out
// the ram overwriting can be improved
func (s *SessionObj) Immolate() error {
	if s == nil {
		err := errors.New("immolate: Cannot immolate that which has no life")
		return err
	}

	// clear data stored in session
	// Warning: be careful about immolating the memory backing the user ID
	// because that may alias a key in the user maps
	s.CurrentUser.Nick = burntString(len(s.CurrentUser.Nick))
	s.CurrentUser.Nick = burntString(len(s.CurrentUser.Nick))
	s.CurrentUser.Nick = ""

	s.GWAddress = burntString(len(s.GWAddress))
	s.GWAddress = burntString(len(s.GWAddress))
	s.GWAddress = ""

	clearCyclicInt(s.PrivateKey)

	for i := 0; i < len(s.Keys); i++ {
		clearCyclicInt(s.Keys[i].PublicKey)
		clearRatchetKeys(&s.Keys[i].TransmissionKeys)
		clearRatchetKeys(&s.Keys[i].ReceptionKeys)
	}

	TheSession = nil

	return nil
}

//Upserts an element into the interface map and saves the session object
func (s *SessionObj) UpsertMap(key string, element interface{}) error {
	globals.LocalStorage.Lock()
	s.InterfaceMap[key] = element
	err := s.storeSession()
	globals.LocalStorage.Unlock()
	return err
}

//Pulls an element from the interface in the map
func (s *SessionObj) QueryMap(key string) (interface{}, error) {
	var err error
	globals.LocalStorage.Lock()
	element, ok := s.InterfaceMap[key]
	if !ok {
		err = ErrQuery
		element = nil
	}
	globals.LocalStorage.Unlock()
	return element, err
}

func (s *SessionObj) DeleteMap(key string) error {
	globals.LocalStorage.Lock()
	delete(s.InterfaceMap, key)
	err := s.storeSession()
	globals.LocalStorage.Unlock()
	return err
}

func (s *SessionObj) LockStorage() {
	globals.LocalStorage.Lock()
}

func (s *SessionObj) UnlockStorage() {
	globals.LocalStorage.Unlock()
}

func clearCyclicInt(c *cyclic.Int) {
	c.Set(cyclic.NewMaxInt())
	c.SetInt64(0)
}

func clearRatchetKeys(r *RatchetKey) {
	clearCyclicInt(r.Base)
	clearCyclicInt(r.Recursive)
}

// FIXME Shouldn't we just be putting pseudorandom bytes in to obscure the mem?
func burntString(length int) string {

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}
