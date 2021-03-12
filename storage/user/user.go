///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package user

import (
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"sync"
)

type User struct {
	ci *CryptographicIdentity

	transmissionRegValidationSig []byte
	receptionRegValidationSig    []byte
	rvsMux                       sync.RWMutex

	username    string
	usernameMux sync.RWMutex

	kv *versioned.KV
}

// builds a new user.
func NewUser(kv *versioned.KV, transmissionID, receptionID *id.ID, transmissionSalt,
	receptionSalt []byte, transmissionRsa, receptionRsa *rsa.PrivateKey, isPrecanned bool) (*User, error) {

	ci := newCryptographicIdentity(transmissionID, receptionID, transmissionSalt, receptionSalt, transmissionRsa, receptionRsa, isPrecanned, kv)

	return &User{ci: ci, kv: kv}, nil
}

func LoadUser(kv *versioned.KV) (*User, error) {
	ci, err := loadCryptographicIdentity(kv)
	if err != nil {
		return nil, errors.WithMessage(err, "Failed to load user "+
			"due to failure to load cryptographic identity")
	}

	u := &User{ci: ci, kv: kv}
	u.loadTransmissionRegistrationValidationSignature()
	u.loadReceptionRegistrationValidationSignature()
	u.loadUsername()

	return u, nil
}

func (u *User) GetCryptographicIdentity() *CryptographicIdentity {
	return u.ci
}
