////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package bindings

// This file contains functions for storing and loading channel private keys to
// and from storage.

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/storage/versioned"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"io"
)

// Storage values.
const (
	channelPrivateKeyStoreVersion = 0
	channelPrivateKeyStoreKey     = "channelPrivateKey/"
)

// GetSavedChannelPrivateKey loads the private key from storage for the given
// channel ID. And returns it encrypted with th given password.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker.
//   - channelIdBase64 - The [id.ID] of the channel in base 64 encoding.
//   - password - The password used to encrypt the private key.
//
// Returns:
//   - JSON of [EncryptedChannelPrivateKey].
func GetSavedChannelPrivateKey(cmixID int, channelIdBase64, password string) (
	[]byte, error) {
	cmix, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return nil, err
	}

	channelIdBytes, err := base64.StdEncoding.DecodeString(channelIdBase64)
	if err != nil {
		return nil, errors.Errorf("failed to decode channel ID: %+v", err)
	}

	channelID, err := id.Unmarshal(channelIdBytes)
	if err != nil {
		return nil, errors.Errorf("invalid channel ID: %+v", err)
	}

	stream := cmix.api.GetRng().GetStream()
	defer stream.Close()

	return getSavedChannelPrivateKey(
		channelID, password, cmix.api.GetStorage().GetKV(), stream)
}

// getSavedChannelPrivateKey loads the private key from file and returns it
// encrypted. This is a helper function for GetSavedChannelPrivateKey to make
// testing easier.
func getSavedChannelPrivateKey(channelID *id.ID, password string,
	kv *versioned.KV, csprng io.Reader) ([]byte, error) {
	privKey, err := loadChannelPrivateKey(channelID, kv)
	if err != nil {
		return nil, errors.Errorf(
			"failed to load private key from storage: %+v", err)
	}

	pkPacket, err :=
		cryptoBroadcast.ExportPrivateKey(channelID, privKey, password, csprng)
	if err != nil {
		return nil, errors.Errorf("failed to export private key: %+v", err)
	}

	return pkPacket, nil
}

// ImportChannelPrivateKey decrypts the given private channel ID and saves it to
// storage.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker.
//   - password - The password used to encrypt the private key.
//   - encryptedPrivKey - The encrypted channel private key packet.
func ImportChannelPrivateKey(
	cmixID int, password string, encryptedPrivKey []byte) error {
	cmix, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return err
	}

	return importChannelPrivateKey(
		password, encryptedPrivKey, cmix.api.GetStorage().GetKV())
}

// importChannelPrivateKey decrypts the given private channel ID and saves it to
// storage. This is a helper function for ImportChannelPrivateKey to make
// testing easier.
func importChannelPrivateKey(password string, encryptedPrivKey []byte, kv *versioned.KV) error {
	channelID, privKey, err :=
		cryptoBroadcast.ImportPrivateKey(password, encryptedPrivKey)
	if err != nil {
		return errors.Errorf("failed to decrypt private channel key: %+v", err)
	}

	return saveChannelPrivateKey(channelID, privKey, kv)
}

// GetSavedChannelPrivateKeyUNSAFE loads the private key from storage for the
// given channel ID.
//
// NOTE: This function is unsafe and only for debugging purposes only.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker.
//   - channelIdBase64 - The [id.ID] of the channel in base 64 encoding.
//
// Returns:
//   - The PEM file of the private key.
func GetSavedChannelPrivateKeyUNSAFE(
	cmixID int, channelIdBase64 string) (string, error) {
	cmix, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return "", err
	}

	channelIdBytes, err := base64.StdEncoding.DecodeString(channelIdBase64)
	if err != nil {
		return "", errors.Errorf("failed to decode channel ID: %+v", err)
	}

	channelID, err := id.Unmarshal(channelIdBytes)
	if err != nil {
		return "", errors.Errorf("invalid channel ID: %+v", err)
	}

	privKey, err :=
		loadChannelPrivateKey(channelID, cmix.api.GetStorage().GetKV())
	if err != nil {
		return "", errors.Errorf(
			"failed to load private key from storage: %+v", err)
	}

	return string(privKey.MarshalPem()), nil
}

////////////////////////////////////////////////////////////////////////////////
// Storage                                                                    //
////////////////////////////////////////////////////////////////////////////////

// saveChannelPrivateKey saves the [rsa.PrivateKey] for the given channel ID to
// storage. This is called everytime a user generates a channel so that they can
// access the channel's private key.
//
// The private key can retrieved from storage via loadChannelPrivateKey.
func saveChannelPrivateKey(
	channelID *id.ID, pk rsa.PrivateKey, kv *versioned.KV) error {
	return kv.Set(makeChannelPrivateKeyStoreKey(channelID),
		&versioned.Object{
			Version:   channelPrivateKeyStoreVersion,
			Timestamp: netTime.Now(),
			Data:      pk.MarshalPem(),
		},
	)
}

// loadChannelPrivateKey retrieves the [rsa.PrivateKey] for the given channel ID
// from storage.
//
// The private key is saved to storage via saveChannelPrivateKey.
func loadChannelPrivateKey(
	channelID *id.ID, kv *versioned.KV) (rsa.PrivateKey, error) {
	obj, err := kv.Get(
		makeChannelPrivateKeyStoreKey(channelID), channelPrivateKeyStoreVersion)
	if err != nil {
		return nil, err
	}

	return rsa.GetScheme().UnmarshalPrivateKeyPEM(obj.Data)
}

// makeChannelPrivateKeyStoreKey generates a unique storage key for the given
// channel that is used to save and load the channel's private key from storage.
func makeChannelPrivateKeyStoreKey(channelID *id.ID) string {
	return channelPrivateKeyStoreKey + channelID.String()
}
