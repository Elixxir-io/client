///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package xxmutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/elixxir/client/api"
	"gitlab.com/elixxir/client/bindings"
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/crypto/contact"
	"gitlab.com/xx_network/primitives/id"
)

// RestoreContactsUpdater interface provides a callback function
// for receiving update information from RestoreContactsFromBackup.
type RestoreContactsUpdater interface {
	// RestoreContactsCallback is called to report the current # of contacts
	// that have been found and how many have been restored
	// against the total number that need to be
	// processed. If an error occurs it it set on the err variable as a
	// plain string.
	RestoreContactsCallback(numFound, numRestored, total int, err string)
}

// RestoreContactsReport is a gomobile friendly report structure
// for determining which IDs restored, which failed, and why.
type RestoreContactsReport struct {
	restored []*id.ID
	failed   []*id.ID
	errs     []error
}

// LenRestored returns the length of ID's restored.
func (r *RestoreContactsReport) LenRestored() int {
	return len(r.restored)
}

// LenFailed returns the length of the ID's failed.
func (r *RestoreContactsReport) LenFailed() int {
	return len(r.failed)
}

// GetRestoredAt returns the restored ID at index
func (r *RestoreContactsReport) GetRestoredAt(index int) []byte {
	return r.restored[index].Bytes()
}

// GetFailedAt returns the failed ID at index
func (r *RestoreContactsReport) GetFailedAt(index int) []byte {
	return r.failed[index].Bytes()
}

// GetErrorAt returns the error string at index
func (r *RestoreContactsReport) GetErrorAt(index int) string {
	return r.errs[index].Error()
}

// RestoreContactsFromBackup takes as input the jason output of the
// `NewClientFromBackup` function, unmarshals it into IDs, looks up
// each ID in user discovery, and initiates a session reset request.
// This function will not return until every id in the list has been sent a
// request. It should be called again and again until it completes.
// xxDK users should not use this function. This function is used by
// the mobile phone apps and are not intended to be part of the xxDK. It
// should be treated as internal functions specific to the phone apps.
func RestoreContactsFromBackup(backupPartnerIDs []byte, client *bindings.Client,
	udManager *bindings.UserDiscovery,
	updatesCb RestoreContactsUpdater) (*RestoreContactsReport, error) {

	// Constants/control settings
	numRoutines := 8
	maxChanSize := 10000
	restoreTimeout := time.Duration(30 * time.Second)

	api := client.GetInternalClient()

	store := stateStore{
		apiStore: api.GetStorage(),
	}

	// Unmarshal IDs and then check restore state
	var idList []*id.ID
	if err := json.Unmarshal(backupPartnerIDs, &idList); err != nil {
		return nil, err
	}
	lookupIDs, resetContacts, restored := checkRestoreState(idList, store)

	// State variables, how many we have looked up successfully
	// and how many we have already reset.
	totalCnt := len(idList)
	lookupCnt := len(resetContacts)
	resetCnt := totalCnt - len(resetContacts) - len(lookupIDs)
	report := &RestoreContactsReport{
		restored: restored,
		failed:   make([]*id.ID, 0),
		errs:     make([]error, 0),
	}

	// Before we start, report initial state
	updatesCb.RestoreContactsCallback(lookupCnt, resetCnt, totalCnt, "")

	// Initialize channels
	chanSize := int(math.Min(float64(maxChanSize), float64(len(idList))))
	// Jobs are processed via the following pipeline:
	//   lookupCh -> foundCh -> resetContactCh -> restoredCh
	// foundCh and restoredCh are used to track progress
	lookupCh := make(chan *id.ID, chanSize)
	foundCh := make(chan *contact.Contact, chanSize)
	resetContactCh := make(chan *contact.Contact, chanSize)
	restoredCh := make(chan *contact.Contact, chanSize)
	failCh := make(chan failure, chanSize)

	// Start routines for processing
	lcWg := sync.WaitGroup{}
	lcWg.Add(numRoutines)
	rsWg := sync.WaitGroup{}
	rsWg.Add(numRoutines)
	for i := 0; i < numRoutines; i++ {
		go LookupContacts(lookupCh, foundCh, failCh, udManager, lcWg)
		go ResetSessions(resetContactCh, restoredCh, failCh, api, rsWg)
	}

	// Load channels based on previous state
	go func() {
		for i := range lookupIDs {
			lookupCh <- lookupIDs[i]
		}
	}()
	go func() {
		for i := range resetContacts {
			lookupCnt += 1
			resetContactCh <- resetContacts[i]
		}
	}()

	// Failure processing, done separately (in a single thread)
	// because failures should not reset the timer
	failWg := sync.WaitGroup{}
	failWg.Add(1)
	go func() {
		defer failWg.Done()
		for fail := range failCh {
			report.failed = append(report.failed, fail.ID)
			report.errs = append(report.errs, fail.Err)
		}
	}()

	// Event Processing
	done := false
	var err error
	for !done {
		// NOTE: Timer is reset every loop
		timeoutTimer := time.NewTimer(restoreTimeout)
		select {
		case <-timeoutTimer.C:
			err = errors.New("restoring accounts timed out")
			done = true
		case c := <-foundCh:
			store.set(c, contactFound)
			lookupCnt += 1
			// NOTE: Prevent blocking by using routine here
			go func() { resetContactCh <- c }()
		case c := <-restoredCh:
			store.set(c, contactRestored)
			report.restored = append(report.restored, c.ID)
			resetCnt += 1
		}
		if resetCnt == totalCnt {
			done = true
		}
		updatesCb.RestoreContactsCallback(lookupCnt, resetCnt, totalCnt,
			"")
	}

	// Cleanup
	close(lookupCh)
	close(resetContactCh)
	close(failCh)
	// Now wait for subroutines to close before closing their output chans
	lcWg.Wait()
	close(foundCh)
	rsWg.Wait()
	close(restoredCh)
	failWg.Wait()

	return report, err
}

// LookupContacts routine looks up contacts
// xxDK users should not use this function. This function is used by
// the mobile phone apps and are not intended to be part of the xxDK. It
// should be treated as internal functions specific to the phone apps.
func LookupContacts(in chan *id.ID, out chan *contact.Contact,
	failCh chan failure, udManager *bindings.UserDiscovery,
	wg sync.WaitGroup) {
	defer wg.Done()
	// Start looking up contacts with user discovery and feed this
	// contacts channel.
	for lookupID := range in {
		c, err := LookupContact(lookupID, udManager)
		if err == nil {
			out <- c
			continue
		}
		// If an error, figure out if I should report or retry
		errStr := err.Error()
		if strings.Contains(errStr, "failed to lookup ID") {
			failCh <- failure{ID: lookupID, Err: err}
			continue
		}
		jww.WARN.Printf("could not lookup %s: %v", lookupID, err)
		// Retry later
		in <- lookupID
	}
}

// ResetSessions routine reads the in channel, sends a reset session
// request, then marks it done by sending to the out channel.
// xxDK users should not use this function. This function is used by
// the mobile phone apps and are not intended to be part of the xxDK. It
// should be treated as internal functions specific to the phone apps.
func ResetSessions(in, out chan *contact.Contact, failCh chan failure,
	api api.Client, wg sync.WaitGroup) {
	defer wg.Done()
	me := api.GetUser().GetContact()
	msg := "Account reset from backup"
	for c := range in {
		_, err := api.ResetSession(*c, me, msg)
		if err == nil {
			out <- c
			continue
		}
		// If an error, figure out if I should report or retry
		// Note: Always retry here for now.
		jww.WARN.Printf("could not reset %s: %v", c.ID, err)
		in <- c
	}
}

// LookupContact lookups up a contact using the user discovery manager
// xxDK users should not use this function. This function is used by
// the mobile phone apps and are not intended to be part of the xxDK. It
// should be treated as internal functions specific to the phone apps.
func LookupContact(userID *id.ID, udManager *bindings.UserDiscovery) (
	*contact.Contact, error) {
	// This is a little wonky, but wait until we get called then
	// set the result to the contact objects details if there is
	// no error
	lookup := &lookupcb{}
	waiter := sync.Mutex{}
	var result *contact.Contact
	var err error
	lookup.CB = func(c *bindings.Contact, errStr string) {
		defer waiter.Unlock()
		if errStr != "" {
			err = errors.New(errStr)
		}
		result = c.GetAPIContact()
	}
	// Take lock once to make sure I will wait
	waiter.Lock()

	// in MS, so 90 seconds
	timeout := 90 * 1000
	udManager.Lookup(userID[:], lookup, timeout)

	// Now force a wait for callback to exit
	waiter.Lock()
	defer waiter.Unlock()

	return result, err
}

// lookupcb provides the callback interface for UserDiscovery lookup function.
type lookupcb struct {
	CB func(c *bindings.Contact, err string)
}

// Callback implements desired interface
func (l *lookupcb) Callback(c *bindings.Contact, err string) { l.CB(c, err) }

// restoreState is the internal state of a contact
type restoreState byte

const (
	contactNotFound restoreState = iota
	contactFound
	contactRestored
)

type failure struct {
	ID  *id.ID
	Err error
}

////
// stateStore wraps a kv and stores contact state for the restoration
// TODO: Right now, it uses 1 contact-per-key approach, but it might make sense
// to wrap this in a mutex and load/store a whole list
////
const stateStoreFmt = "restoreContactsFromBackup/v1/%s"

type stateStore struct {
	apiStore *storage.Session
	// TODO: We could put a syncmap or something here instead of
	// 1-key-per-id
}

func (s stateStore) key(id *id.ID) string {
	return fmt.Sprintf(stateStoreFmt, id)
}

func (s stateStore) set(user *contact.Contact, state restoreState) error {
	key := s.key(user.ID)
	// First byte is state var, second is contact object
	data := []byte{byte(state)}
	data = append(data, user.Marshal()...)
	val := &versioned.Object{
		Version:   0,
		Timestamp: time.Now(),
		Data:      data,
	}
	return s.apiStore.Set(key, val)
}
func (s stateStore) get(id *id.ID) (restoreState, *contact.Contact, error) {
	key := s.key(id)
	val, err := s.apiStore.Get(key)
	if err != nil {
		return contactNotFound, nil, err
	}
	user, err := contact.Unmarshal(val.Data[1:])
	if err != nil {
		return contactFound, nil, err
	}
	return restoreState(val.Data[0]), &user, nil
}

// stateStore END

func checkRestoreState(IDs []*id.ID, store stateStore) ([]*id.ID,
	[]*contact.Contact, []*id.ID) {
	var idsToLookup []*id.ID
	var contactsToReset []*contact.Contact
	var contactsRestored []*id.ID
	for i := range IDs {
		id := IDs[i]
		idState, user, err := store.get(id)
		if err != nil {
			// Ignore errors here since they always will result
			// in a retry.
			jww.WARN.Printf("Error on restore check for %s: %v",
				id, err)
		}
		switch idState {
		case contactNotFound:
			idsToLookup = append(idsToLookup, id)
		case contactFound:
			contactsToReset = append(contactsToReset, user)
		case contactRestored:
			contactsRestored = append(contactsRestored, user.ID)
		}
	}
	return idsToLookup, contactsToReset, contactsRestored
}
