////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package sync

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/xx_network/primitives/netTime"
	"io"
	"sort"
	"sync"
)

const (
	xxdkTxLogHeader = "XXDKTXLOGHDR"
	xxdkTxLogDelim  = ","
	logHeader       = "Transaction Log"
)

// Error messages.
const (
	writeToBufferErr = "failed to write to buffer (%s): %+v"
	getLastWriteErr  = "failed to get last write operation from remote store: %+v"
	writeToStoreErr  = "failed to write to %s store: %+v"
)

// TransactionLog will log all Transaction's to a storage interface. It will
// contain all Transaction's in an ordered list, and will ensure to retain order
// when Append is called. This will store to a LocalStore and a RemoteStore when
// appending Transaction's.
type TransactionLog struct {
	// path is the filepath that the TransactionLog will be written to on remote
	// and local storage.
	path string

	// local is the store for writing/reading to a local store.
	//
	// EkvLocalStore is provided as an example.
	local LocalStore

	// remote is the store for writing/reading to a remote store.
	//
	// FileSystemRemoteStorage is provided as an example.
	remote RemoteStore

	// hdr is the Header of the TransactionLog.
	hdr *Header

	// txs is a list of transactions. This list must always be ordered by
	// timestamp.
	txs []Transaction

	// deviceSecret is the secret for the device that the TransactionLog will
	// be stored.
	deviceSecret []byte

	// rng is an io.Reader that will be used for encrypt. This should be a
	// secure random number generator (fastRNG.Stream is recommended).
	rng io.Reader

	lck sync.RWMutex
}

// NewTransactionLog constructs a new TransactionLog. Note that by default the
// log's header is empty. To set this field, call TransactionLog.SetHeader.
func NewTransactionLog(local LocalStore, remote RemoteStore,
	rng io.Reader, path string, deviceSecret []byte) *TransactionLog {
	// todo: attempt to load transaction log from local (refactor to be NewOrLoad...)
	//
	//

	// Return a new transaction log
	return &TransactionLog{
		path:         path,
		local:        local,
		remote:       remote,
		txs:          make([]Transaction, 0),
		deviceSecret: deviceSecret,
		rng:          rng,
	}
}

// SetHeader will set the Header of the TransactionLog. This new header will be
// what is used for serialization and saving when calling Append.
// todo: test this
func (tl *TransactionLog) SetHeader(h *Header) {
	tl.lck.Lock()
	defer tl.lck.Unlock()

	tl.hdr = h
}

// Append will add a transaction to the TransactionLog. This will save the
// serialized TransactionLog to local and remote storage.
func (tl *TransactionLog) Append(t Transaction) error {
	tl.lck.Lock()

	// Insert new transaction into list
	jww.INFO.Printf("[%s] Inserting transaction to log", logHeader)
	tl.append(t)

	// Serialize the transaction log
	dataToSave, err := tl.serialize()
	if err != nil {
		return err
	}

	// Release lock now that serialization is complete
	tl.lck.Unlock()

	// Save data to file store
	jww.INFO.Printf("[%s] Saving transaction log", logHeader)
	return tl.save(dataToSave)
}

// append will write the new Transaction to txs. txs must be ordered by
// timestamp, so it will the txs list is sorted after appending the new
// Transaction.
//
// Note that this operation is NOT thread-safe, and the caller should hold the
// lck.
func (tl *TransactionLog) append(newTransaction Transaction) {
	// Lazily insert new transaction
	tl.txs = append(tl.txs, newTransaction)

	// Sort transaction list. This operates in n * log(n) time complexity
	sort.SliceStable(tl.txs, func(i, j int) bool {
		firstTs, secondTs := tl.txs[i].Timestamp, tl.txs[j].Timestamp
		return firstTs.Before(secondTs)
	})

}

// serialize serializes the state of TransactionLog to byte data, so that it can
// be written to a store (remote, local or both).
//
// This is the inverse operation of TransactionLog.deserialize.
func (tl *TransactionLog) serialize() ([]byte, error) {
	buff := new(bytes.Buffer)

	// Serialize header
	headerSerialized, err := tl.hdr.serialize()
	if err != nil {
		return nil, err
	}

	// Write the length of the header info into the buffer
	headerInfoLen := len(headerSerialized)
	buff.Write(serializeInt(headerInfoLen))

	// Write serialized header to bufer
	buff.Write(headerSerialized)

	// Retrieve the last written timestamp from remote
	lastRemoteWrite, err := tl.remote.GetLastWrite()
	if err != nil {
		return nil, errors.Errorf(getLastWriteErr, err)
	}

	// Serialize the length of the list
	buff.Write(serializeInt(len(tl.txs)))

	// Serialize all transactions
	for i := 0; i < len(tl.txs); i++ {
		// Timestamp must be updated every write attempt time if new entry
		if tl.txs[i].Timestamp.After(lastRemoteWrite) {
			tl.txs[i].Timestamp = netTime.Now()
		}

		// Serialize transaction
		txSerialized, err := tl.txs[i].serialize(tl.deviceSecret, i, tl.rng)
		if err != nil {
			return nil, err
		}

		// Write the length of the transaction info into the buffer
		txInfoLen := len(txSerialized)
		buff.Write(serializeInt(txInfoLen))

		// Write to buffer
		buff.Write(txSerialized)

	}

	return buff.Bytes(), nil
}

// deserialize will deserialize TransactionLog byte data.
//
// This is the inverse operation of TransactionLog.serialize.
func (tl *TransactionLog) deserialize(data []byte) error {
	// Initialize buffer
	buff := bytes.NewBuffer(data)

	// Extract header length from buffer
	lengthOfHeaderInfo := deserializeInt(buff.Next(8))
	serializedHeader := buff.Next(int(lengthOfHeaderInfo))

	// Deserialize header
	hdr, err := deserializeHeader(serializedHeader)
	if err != nil {
		return err
	}

	tl.hdr = hdr

	// Deserialize length of transactions list
	listLen := binary.LittleEndian.Uint64(buff.Next(8))

	// Construct transactions list
	txs := make([]Transaction, listLen)

	// Iterate over transaction log
	for i := range txs {
		//Read length of transaction from buffer
		txInfoLen := deserializeInt(buff.Next(8))
		txInfo := buff.Next(int(txInfoLen))
		tx, err := deserializeTransaction(txInfo, tl.deviceSecret)
		if err != nil {
			// todo: better error
			return err
		}

		txs[i] = tx
	}

	tl.txs = txs

	return nil
}

// save writes the data passed int to file, both remotely and locally. The
// data passed in should be read in from curBuf.
func (tl *TransactionLog) save(dataToSave []byte) error {

	// Save to local storage (if set)
	if tl.local == nil {
		jww.FATAL.Panicf("[%s] Cannot write to a nil local store", logHeader)
	}

	jww.INFO.Printf("[%s] Writing transaction log to local store", logHeader)
	if err := tl.local.Write(tl.path, dataToSave); err != nil {
		return errors.Errorf(writeToStoreErr, "local", err)
	}

	// Save to remote storage (if set)
	if tl.remote == nil {
		jww.FATAL.Panicf("[%s] Cannot write to a nil remote store", logHeader)

	}

	jww.INFO.Printf("[%s] Writing transaction log to remote store", logHeader)
	if err := tl.remote.Write(tl.path, dataToSave); err != nil {
		return errors.Errorf(writeToStoreErr, "remote", err)
	}

	return nil
}

// serializeInt is a utility function which serializes an integer into a byte
// slice.
//
// This is the inverse operation of deserializeInt.
func serializeInt(i int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(i))
	return b
}

// deserializeInt is a utility function which deserializes byte data into an
// integer.
//
// This is the inverse operation of serializeInt.
func deserializeInt(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}
