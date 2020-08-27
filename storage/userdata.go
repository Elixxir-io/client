////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package storage

import (
	"bytes"
	"encoding/gob"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/cyclic"
	//"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"time"
)

// Struct representing a User in the system
type User struct {
	User     *id.ID
	Username string
	Precan   bool
}

// DeepCopy performs a deep copy of a user and returns a pointer to the new copy
func (u *User) DeepCopy() *User {
	if u == nil {
		return nil
	}
	nu := new(User)
	nu.User = u.User
	nu.Username = u.Username
	nu.Precan = u.Precan
	return nu
}

// This whole struct is serialized/deserialized all together
type UserData struct {
	// Fields
	ThisUser *User
	//RSAPrivateKey    *rsa.PrivateKey
	//RSAPublicKey     *rsa.PublicKey
	CMIXDHPrivateKey *cyclic.Int
	CMIXDHPublicKey  *cyclic.Int
	E2EDHPrivateKey  *cyclic.Int
	E2EDHPublicKey   *cyclic.Int
	CmixGrp          *cyclic.Group
	E2EGrp           *cyclic.Group
	Salt             []byte
}

const currentUserDataVersion = 0

func makeUserDataKey() string {
	return "UserData"
}

func (s *Session) GetUserData() (*UserData, error) {
	if s.userData != nil {
		// We already got this and don't need to get it again
		return s.userData, nil
	}
	obj, err := s.Get(makeUserDataKey())
	if err != nil {
		return nil, err
	}

	var resultBuffer bytes.Buffer
	var result UserData
	resultBuffer.Write(obj.Data)
	dec := gob.NewDecoder(&resultBuffer)
	err = dec.Decode(&result)
	if err != nil {
		return nil, err
	}
	s.userData = &result
	return &result, nil
}

// Make changes to the user data after getting it, then
// commit those changes to the ekv store using this
// I haven't added a mutex to the user data because it's only
// created once. If you add modification to the user data structure,
// please
func (s *Session) CommitUserData(data *UserData) error {
	// Serialize the data
	var userDataBuffer bytes.Buffer
	enc := gob.NewEncoder(&userDataBuffer)
	err := enc.Encode(data)
	if err != nil {
		return err
	}

	obj := &versioned.Object{
		Version:   currentUserDataVersion,
		Timestamp: time.Now(),
		Data:      userDataBuffer.Bytes(),
	}
	return s.Set(makeUserDataKey(), obj)
}
