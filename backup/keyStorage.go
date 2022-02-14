////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package backup

import (
	"bytes"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/xx_network/primitives/netTime"
)

const (
	passwordStorageVersion = 0
	passwordStorageKey     = "BackupPassword"
	cryptoStorageVersion   = 0
	cryptoStorageKey       = "BackupCryptoInfo"
)

// Length of marshalled fields.
const (
	keyLen    = backup.KeyLen
	saltLen   = backup.SaltLen
	paramsLen = backup.ParamsLen
)

// saveBackup saves the key, salt, and params to storage.
func saveBackup(key, salt []byte, params backup.Params, kv *versioned.KV) error {

	obj := &versioned.Object{
		Version:   cryptoStorageVersion,
		Timestamp: netTime.Now(),
		Data:      marshalBackup(key, salt, params),
	}

	return kv.Set(cryptoStorageKey, cryptoStorageVersion, obj)
}

// loadBackup loads the key, salt, and params from storage.
func loadBackup(kv *versioned.KV) (key, salt []byte, params backup.Params, err error) {
	obj, err := kv.Get(cryptoStorageKey, cryptoStorageVersion)
	if err != nil {
		return
	}

	return unmarshalBackup(obj.Data)
}

// deleteBackup deletes the key, salt, and params from storage.
func deleteBackup(kv *versioned.KV) error {
	return kv.Delete(cryptoStorageKey, cryptoStorageVersion)
}

// marshalBackup marshals the backup's key, salt, and params into a byte slice.
func marshalBackup(key, salt []byte, params backup.Params) []byte {
	buff := bytes.NewBuffer(nil)
	buff.Grow(keyLen + saltLen + paramsLen)

	// Write key to buffer
	buff.Write(key)

	// Write salt to buffer
	buff.Write(salt)

	// Write marshalled params to buffer
	buff.Write(params.Marshal())

	return buff.Bytes()
}

// unmarshalBackup unmarshalls the byte slice into a key, salt, and params.
func unmarshalBackup(buf []byte) (key, salt []byte, params backup.Params, err error) {
	buff := bytes.NewBuffer(buf)
	// Get key
	key = make([]byte, keyLen)
	n, err := buff.Read(key)
	if err != nil || n != keyLen {
		err = errors.Errorf("reading key failed: %+v", err)
		return
	}

	// Get salt
	salt = make([]byte, saltLen)
	n, err = buff.Read(salt)
	if err != nil || n != saltLen {
		err = errors.Errorf("reading salt failed: %+v", err)
		return
	}

	// Get params from remaining bytes
	err = params.Unmarshal(buff.Bytes())
	if err != nil {
		err = errors.Errorf("reading params failed: %+v", err)
	}

	return
}

// savePassword saves the user's backup password to storage.
func savePassword(password string, kv *versioned.KV) error {
	obj := &versioned.Object{
		Version:   passwordStorageVersion,
		Timestamp: netTime.Now(),
		Data:      []byte(password),
	}

	return kv.Set(passwordStorageKey, passwordStorageVersion, obj)
}

// loadPassword returns the user's backup password from storage.
func loadPassword(kv *versioned.KV) (string, error) {
	obj, err := kv.Get(passwordStorageKey, passwordStorageVersion)
	if err != nil {
		return "", err
	}

	return string(obj.Data), nil
}

// deletePassword deletes the user's backup password from storage.
func deletePassword(kv *versioned.KV) error {
	return kv.Delete(passwordStorageKey, passwordStorageVersion)
}
