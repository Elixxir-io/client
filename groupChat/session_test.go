////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package groupChat

import (
	"gitlab.com/elixxir/client/v4/storage"
	"gitlab.com/elixxir/client/v4/storage/user"
	"gitlab.com/elixxir/client/v4/storage/utility"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	accountSync "gitlab.com/elixxir/client/v4/sync"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/elixxir/primitives/version"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/ndf"
	"io"
	"time"
)

// mockSession is a storage.Session implementation for testing.
type mockSession struct {
	kv *utility.KV
}

func (m mockSession) GetKV() *utility.KV {
	if m.kv != nil {
		return m.kv
	}

	return &utility.KV{Local: versioned.NewKV(ekv.MakeMemstore())}

}

func newMockSesion(kv *utility.KV) storage.Session {
	return mockSession{kv: kv}
}

func (m mockSession) GetE2EGroup() *cyclic.Group {
	return getGroup()
}

/////////////////////////////////////////////////////////////////////////////////////
// Unused & unimplemented methods of the test object ////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

func (m mockSession) Get(key string) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) InitRemoteKV(remote accountSync.RemoteStore, eventCb accountSync.KeyUpdateCallback, updateCb accountSync.RemoteStoreCallback, rng io.Reader) error {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetClientVersion() version.Version {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) Set(key string, object *versioned.Object) error {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) Delete(key string) error {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetCmixGroup() *cyclic.Group {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) ForwardRegistrationStatus(regStatus storage.RegistrationStatus) error {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetRegistrationStatus() storage.RegistrationStatus {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetRegCode(regCode string) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetRegCode() (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetNDF(def *ndf.NetworkDefinition) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetNDF() *ndf.NetworkDefinition {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetTransmissionID() *id.ID {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetTransmissionSalt() []byte {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetReceptionID() *id.ID {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetReceptionSalt() []byte {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetReceptionRSA() rsa.PrivateKey {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetTransmissionRSA() rsa.PrivateKey {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) IsPrecanned() bool {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetUsername(username string) error {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetUsername() (string, error) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) PortableUserInfo() user.Info {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetTransmissionRegistrationValidationSignature() []byte {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetReceptionRegistrationValidationSignature() []byte {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) GetRegistrationTimestamp() time.Time {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetTransmissionRegistrationValidationSignature(b []byte) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetReceptionRegistrationValidationSignature(b []byte) {
	//TODO implement me
	panic("implement me")
}

func (m mockSession) SetRegistrationTimestamp(tsNano int64) {
	//TODO implement me
	panic("implement me")
}
