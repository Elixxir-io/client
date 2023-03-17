////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package bindings

import (
	"encoding/json"
	"gitlab.com/elixxir/client/v4/sync"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// Remote Storage Interface and Implementation(s)                             //
////////////////////////////////////////////////////////////////////////////////

// RemoteStore is the mechanism that all remote storage implementations should
// adhere to.
type RemoteStore interface {
	// FileIO is used to write and read files. Refer to [sync.FileIO].
	sync.FileIO

	// GetLastModified returns when the file at the given file path was last
	// modified. If the implementation that adheres to this interface does not
	// support this, FileIO.Write or FileIO.Read should be implemented to either
	// write a separate timestamp file or add a prefix.
	GetLastModified(path string) ([]byte, error)

	// GetLastWrite retrieves the most recent successful write operation that
	// was received by RemoteStore.
	GetLastWrite() ([]byte, error)
}

// RemoteStoreFileSystem is a structure adhering to [RemoteStore]. This utilizes
// the [os.File] IO operations. Implemented for testing purposes for transaction
// logs.
type RemoteStoreFileSystem struct {
	api *sync.FileSystemRemoteStorage
}

// NewFileSystemRemoteStorage is a constructor for [RemoteStoreFileSystem].
//
// Parameters:
//   - baseDir - The base directory that all file operations will be performed.
//     It must contain a file delimiter (i.e., `/`).
func NewFileSystemRemoteStorage(baseDir string) *RemoteStoreFileSystem {
	return &RemoteStoreFileSystem{sync.NewFileSystemRemoteStorage(baseDir)}
}

// Read reads from the provided file path and returns the data at that path.
// An error is returned if it failed to read the file.
func (r *RemoteStoreFileSystem) Read(path string) ([]byte, error) {
	return r.api.Read(path)
}

// Write writes to the file path the provided data. An error is returned if it
// fails to write to file.
func (r *RemoteStoreFileSystem) Write(path string, data []byte) error {
	return r.api.Write(path, data)
}

// GetLastModified returns when the file at the given file path was last
// modified. If the implementation that adheres to this interface does not
// support this, [Write] or [Read] should be implemented to either write a
// separate timestamp file or add a prefix.
//
// Returns:
//   - []byte - A JSON marshalled [RemoteStoreReport].
func (r *RemoteStoreFileSystem) GetLastModified(path string) ([]byte, error) {
	ts, err := r.api.GetLastModified(path)
	if err != nil {
		return nil, err
	}

	rsr := &RemoteStoreReport{
		LastModified: ts.UnixNano(),
	}

	return json.Marshal(rsr)
}

// GetLastWrite retrieves the most recent successful write operation that was
// received by [RemoteStoreFileSystem].
//
// Returns:
//   - []byte - A JSON marshalled [RemoteStoreReport].
func (r *RemoteStoreFileSystem) GetLastWrite() ([]byte, error) {
	ts, err := r.api.GetLastWrite()
	if err != nil {
		return nil, err
	}

	rsr := &RemoteStoreReport{
		LastWrite: ts.UnixNano(),
	}

	return json.Marshal(rsr)
}

// remoteStoreFileSystemWrapper is an internal Go wrapper for
// RemoteStoreFileSystem that adheres to sync.RemoteStore.
// fixme: reviewer, is this the correct solution?
type remoteStoreFileSystemWrapper struct {
	bindingsAPI RemoteStore
}

// newRemoteStoreFileSystemWrapper constructs a remoteStoreFileSystemWrapper.
func newRemoteStoreFileSystemWrapper(
	bindingsAPI RemoteStore) *remoteStoreFileSystemWrapper {
	return &remoteStoreFileSystemWrapper{bindingsAPI: bindingsAPI}
}

// Read reads from the provided file path and returns the data at that path.
// An error is returned if it failed to read the file.
func (r *remoteStoreFileSystemWrapper) Read(path string) ([]byte, error) {
	return r.bindingsAPI.Read(path)
}

// Write writes to the file path the provided data. An error is returned if it
// fails to write to file.
func (r *remoteStoreFileSystemWrapper) Write(path string, data []byte) error {
	return r.bindingsAPI.Write(path, data)
}

// GetLastModified returns when the file at the given file path was last
// modified. If the implementation that adheres to this interface does not
// support this, [Write] or [Read] should be implemented to either write a
// separate timestamp file or add a prefix.
func (r *remoteStoreFileSystemWrapper) GetLastModified(
	path string) (time.Time, error) {
	reportData, err := r.bindingsAPI.GetLastModified(path)
	if err != nil {
		return time.Time{}, err
	}

	rsr := &RemoteStoreReport{}
	if err = json.Unmarshal(reportData, rsr); err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, rsr.LastModified), nil
}

// GetLastWrite retrieves the most recent successful write operation that was
// received by RemoteStore.
func (r *remoteStoreFileSystemWrapper) GetLastWrite() (time.Time, error) {
	reportData, err := r.bindingsAPI.GetLastWrite()
	if err != nil {
		return time.Time{}, err
	}

	rsr := &RemoteStoreReport{}
	if err = json.Unmarshal(reportData, rsr); err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, rsr.LastWrite), nil
}

////////////////////////////////////////////////////////////////////////////////
// RemoteKV Methods                                                           //
////////////////////////////////////////////////////////////////////////////////

// RemoteKV implements a remote KV to handle transaction logs. It writes and
// reads state data from another device to a remote storage interface.
type RemoteKV struct {
	rkv *sync.RemoteKV
}

// RemoteStoreReport represents the report from any call to a method of
// [RemoteStore].
//
// Example JSON:
//
//	{
//	 "lastModified": 1679173966663412908,
//	 "lastWrite": 1679130886663413268,
//	 "error": "Example error (may not exist if successful)"
//	}
type RemoteStoreReport struct {
	// LastModified is the timestamp (in nanoseconds) of the last time the
	// specific path was modified. Refer to sync.RemoteKV.GetLastModified.
	LastModified int64 `json:"lastModified"`

	// LastWrite is the timestamp (in nanoseconds) of the last write to the
	// remote storage interface by any device. Refer to
	// sync.RemoteKV.GetLastWrite.
	LastWrite int64 `json:"lastWrite"`

	Error string `json:"error,omitempty"`

	// Data []byte
}

// RemoteKVCallbacks is an interface for the [RemoteKV]. This will handle all
// callbacks used for the various operations [RemoteKV] supports.
type RemoteKVCallbacks interface {
	// KeyUpdated is the callback to be called any time a Key is updated by
	// another device tracked by the RemoteKV store.
	KeyUpdated(key, val string)

	// RemoteStoreResult is called to report network save results after the key
	// has been updated locally.
	RemoteStoreResult(newTx []byte, err string)

	//// UpsertCallbacks are the methods used for upserting a value for a given
	//// key. Refer to [sync.UpsertCallbacks].
	//sync.UpsertCallbacks

	GetUpsertFunc(key string) sync.UpsertCallback

	HasUpsertFunc(key string) bool
}

// NewOrLoadSyncRemoteKV will construct a [RemoteKV].
//
// Parameters:
//   - e2eID - ID of [E2e] object in tracker.
//   - txLogPath - the path that the state data for this device will be written
//     to locally (e.g. sync/txLog.txt).
//   - remoteKvCallbacks - A [RemoteKVCallbacks]. These will be the callbacks
//     that are called for RemoteStore operations.
//   - remote - A [RemoteStore]. This should be what the remote storage
//     operation wrapper wrapped should adhere.
func NewOrLoadSyncRemoteKV(e2eID int, remoteKvCallbacks RemoteKVCallbacks,
	remote RemoteStore) (*RemoteKV, error) {

	// Retrieve
	e2eCl, err := e2eTrackerSingleton.get(e2eID)
	if err != nil {
		return nil, err
	}

	// todo: properly define
	var deviceSecret []byte = []byte("dummy, replace")
	// deviceSecret = e2eCl.GetDeviceSecret()

	// Construct the key update CB
	var eventCb sync.KeyUpdateCallback = func(k, v string) {
		remoteKvCallbacks.KeyUpdated(k, v)
	}
	// Construct update CB
	var updateCb sync.RemoteStoreCallback = func(newTx sync.Transaction,
		err error) {
		remoteStoreCbUtil(remoteKvCallbacks, newTx, err)
	}

	// Construct local storage
	local := sync.NewEkvLocalStore(e2eCl.api.GetStorage().GetKV())

	// Construct txLog path
	txLogPath := "txLog/" + e2eCl.api.GetReceptionIdentity().ID.String()

	// Retrieve rng
	rng := e2eCl.api.GetRng().GetStream()

	// Construct or load a transaction log
	txLog, err := sync.NewOrLoadTransactionLog(txLogPath, local,
		newRemoteStoreFileSystemWrapper(remote),
		deviceSecret, rng)
	if err != nil {
		return nil, err
	}

	// Construct remote KV
	rkv, err := sync.NewOrLoadRemoteKV(txLog, e2eCl.api.GetStorage().GetKV(),
		remoteKvCallbacks, eventCb, updateCb)
	if err != nil {
		return nil, err
	}

	return &RemoteKV{rkv: rkv}, nil
}

// Write writes a transaction to the remote and local store.
//
// Parameters:
//   - path - The key that this data will be written to (i.e., the device
//     name).
//   - data - The data that will be stored (i.e., state data).
//   - cb - A [RemoteStoreCallback]. This may be nil if you do not care about the
//     network report.
func (s *RemoteKV) Write(path string, data []byte, cb RemoteKVCallbacks) error {
	var updateCb sync.RemoteStoreCallback = func(newTx sync.Transaction, err error) {
		remoteStoreCbUtil(cb, newTx, err)
	}
	return s.rkv.Set(path, data, updateCb)
}

// Read retrieves the data stored in the underlying KV. Returns an error if the
// data at this key cannot be retrieved.
//
// Parameters:
//   - path - The key that this data will be written to (i.e., the device name).
func (s *RemoteKV) Read(path string) ([]byte, error) {
	return s.rkv.Get(path)
}

// remoteStoreCbUtil is a utility function for the RemoteStoreCallback.
func remoteStoreCbUtil(cb RemoteKVCallbacks, newTx sync.Transaction, err error) {
	if err != nil {
		cb.RemoteStoreResult(nil, err.Error())
	}

	serialized, err := newTx.MarshalJSON()
	if err != nil {
		cb.RemoteStoreResult(nil, err.Error())
	}

	cb.RemoteStoreResult(serialized, "")
}
