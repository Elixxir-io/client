////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package sync

import (
	"encoding/base64"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Hard-coded constants for testing purposes.
const (

	// expectedTransactionJson is the expected result for calling json.Marshal
	// on a Mutate object with example data.
	expectedTransactionJson = `{"Timestamp":"2012-12-21T22:08:41Z","Key":"key","Value":"dmFsdWU="}`

	// expectedTransactionZeroTimeJson is the expected result for calling
	// json.Marshal on a Mutate object with example data, specifically
	// with a zero time.Time.
	expectedTransactionZeroTimeJson = `{"Timestamp":"0001-01-01T00:00:00Z","Key":"key","Value":"dmFsdWU="}`

	// expectedSerializedTransaction is the expected result after calling
	// Mutate.serialize with example data.
	expectedSerializedTransaction = `MCxBUUlEQkFVR0J3Z0pDZ3NNRFE0UEVCRVNFeFFWRmhjWXBEZURxZjlNY0sya1VIcWpmVW50SHZIVW9Od2lnYjd6WTBDQW9MZzMyMVgyYlREUUNSaXlPMkhCWG1hS3hLWEk0TDFiLW9Hb1duMDc4Tk5IYTZMbDZNZHMycmtJQ2JieFE2RTk3MDlIM25ENTk3QT0=`
)

// Smoke test for NewMutate.
func TestNewTransaction(t *testing.T) {
	// Initialize a mock time (not time.Now so that it can be constant)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	require.NoError(t, err)

	// Construct expected Mutate object
	key, val := "key", []byte("value")
	expectedTx := Mutate{
		Timestamp: testTime.UTC(),
		Key:       key,
		Value:     val,
	}

	require.Equal(t, expectedTx, NewMutate(testTime, key, val))
}

// Smoke & unit test for Mutate.MarshalJSON.
func TestTransaction_MarshalJSON(t *testing.T) {
	// Initialize a mock time (not time.Now so that it can be constant)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	require.NoError(t, err)

	// Construct a Mutate object
	key, val := "key", []byte("value")
	tx := NewMutate(testTime, key, val)

	// Marshal Mutate into JSON data
	marshalledData, err := json.Marshal(tx)
	require.NoError(t, err)

	// Check that marshaled data matches expected value
	require.Equal(t, expectedTransactionJson, string(marshalledData))

}

// Smoke & unit test for Mutate.UnmarshalJSON.
func TestTransaction_UnmarshalJSON(t *testing.T) {
	// Initialize a mock time (not time.Now so that it can be constant)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	require.NoError(t, err)

	// Construct a Mutate object
	key, val := "key", []byte("value")
	oldTx := NewMutate(testTime, key, val)

	// Marshal mutate into JSON data
	oldTxData, err := json.Marshal(oldTx)
	require.NoError(t, err)

	// Construct a new mutate and unmarshal the old mutate into it
	newTx := NewMutate(time.Time{}, "", make([]byte, 0))
	require.NoError(t, json.Unmarshal(oldTxData, &newTx))

	// Ensure that the newTx.UnmarshalJSON call places
	// oldTx's data into the new mutate object.
	require.Equal(t, oldTx, newTx)

	// Marshal the newTx into JSON
	newTxData, err := json.Marshal(newTx)
	require.NoError(t, err)

	// Ensure that newTx's marshalled data matches the expected JSON
	// output (if no data has been lost, this should be the case)
	require.Equal(t, expectedTransactionJson, string(newTxData))

}

// Edge check: check that a zero value time.Time object gets marshalled
// and unmarshalled properly.
func TestTransaction_UnmarshalJSON_ZeroTime(t *testing.T) {
	testTime := time.Time{}

	// Construct a Mutate object
	key, val := "key", []byte("value")
	oldTx := NewMutate(testTime, key, val)

	// Marshal mutate into JSON data
	oldTxData, err := json.Marshal(oldTx)
	require.NoError(t, err)

	require.Equal(t, expectedTransactionZeroTimeJson, string(oldTxData))

	// Construct a new mutate and unmarshal the old mutate into it
	newTx := NewMutate(time.Time{}, "", make([]byte, 0))
	require.NoError(t, json.Unmarshal(oldTxData, &newTx))

	require.True(t, newTx.Timestamp.Equal(testTime))
}

// Smoke test of Mutate.serialize.
func TestTransaction_Serialize(t *testing.T) {
	// Initialize a mock time (not time.Now so that it can be constant)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	require.NoError(t, err)

	// Construct a Mutate object
	key, val := "key", []byte("value")
	tx := NewMutate(testTime, key, val)

	// Serialize mutate
	secret, mockRng := []byte("secret"), &CountingReader{count: 0}
	txSerial, err := tx.serialize(secret, 0, mockRng)
	require.NoError(t, err)

	// Ensure serialization is consistent
	require.Equal(t, expectedSerializedTransaction,
		base64.StdEncoding.EncodeToString(txSerial))
}

// Unit test of DeserializeTransaction. Ensures that deserialize will construct
// the same Mutate that was serialized using Mutate.serialize.
func TestTransaction_Deserialize(t *testing.T) {
	// Initialize a mock time (not time.Now so that it can be constant)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	require.NoError(t, err)

	// Construct a Mutate object
	key, val := "key", []byte("value")
	tx := NewMutate(testTime, key, val)

	// Serialize mutate
	secret, mockRng := []byte("secret"), &CountingReader{count: 0}
	txSerial, err := tx.serialize(secret, 0, mockRng)
	require.NoError(t, err)

	// Deserialize mutate
	txDeserialize, err := deserializeTransaction(txSerial, secret)
	require.NoError(t, err)

	// Ensure deserialized object matches original object
	require.Equal(t, tx, txDeserialize)
}
