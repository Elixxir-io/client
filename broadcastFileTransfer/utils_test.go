////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcastFileTransfer

import (
	"bytes"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/cmix"
	"gitlab.com/elixxir/client/cmix/gateway"
	"gitlab.com/elixxir/client/cmix/identity"
	"gitlab.com/elixxir/client/cmix/identity/receptionID"
	"gitlab.com/elixxir/client/cmix/message"
	"gitlab.com/elixxir/client/cmix/rounds"
	"gitlab.com/elixxir/client/e2e"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/client/storage"
	userStorage "gitlab.com/elixxir/client/storage/user"
	"gitlab.com/elixxir/client/storage/versioned"
	"gitlab.com/elixxir/client/xxdk"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/ekv"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/elixxir/primitives/version"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/ndf"
	"gitlab.com/xx_network/primitives/netTime"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// newFile generates a file with random data of size numParts * partSize.
// Returns the full file and the file parts. If the partSize allows, each part
// starts with a "|<[PART_001]" and ends with a ">|".
func newFile(numParts uint16, partSize int, prng io.Reader, t *testing.T) (
	[]byte, [][]byte) {
	const (
		prefix = "|<[PART_%3d]"
		suffix = ">|"
	)
	// Create file buffer of the expected size
	fileBuff := bytes.NewBuffer(make([]byte, 0, int(numParts)*partSize))
	partList := make([][]byte, numParts)

	// Create new rand.Rand with the seed generated from the io.Reader
	b := make([]byte, 8)
	_, err := prng.Read(b)
	if err != nil {
		t.Errorf("Failed to generate random seed: %+v", err)
	}
	seed := binary.LittleEndian.Uint64(b)
	randPrng := rand.New(rand.NewSource(int64(seed)))

	for partNum := range partList {
		s := RandStringBytes(partSize, randPrng)
		if len(s) >= (len(prefix) + len(suffix)) {
			partList[partNum] = []byte(
				prefix + s[:len(s)-(len(prefix)+len(suffix))] + suffix)
		} else {
			partList[partNum] = []byte(s)
		}

		fileBuff.Write(partList[partNum])
	}

	return fileBuff.Bytes(), partList
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandStringBytes generates a random string of length n consisting of the
// characters in letterBytes.
func RandStringBytes(n int, prng *rand.Rand) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[prng.Intn(len(letterBytes))]
	}
	return string(b)
}

////////////////////////////////////////////////////////////////////////////////
// Mock xxdk.E2e                                                              //
////////////////////////////////////////////////////////////////////////////////

type mockE2e struct {
	rid xxdk.ReceptionIdentity
	c   cmix.Client
	s   storage.Session
	rng *fastRNG.StreamGenerator
}

func newMockE2e(rid *id.ID, c cmix.Client, s storage.Session,
	rng *fastRNG.StreamGenerator) *mockE2e {
	return &mockE2e{
		rid: xxdk.ReceptionIdentity{ID: rid},
		c:   c,
		s:   s,
		rng: rng,
	}
}

func (m *mockE2e) GetStorage() storage.Session                  { return m.s }
func (m *mockE2e) GetReceptionIdentity() xxdk.ReceptionIdentity { return m.rid }
func (m *mockE2e) GetCmix() cmix.Client                         { return m.c }
func (m *mockE2e) GetRng() *fastRNG.StreamGenerator             { return m.rng }
func (m *mockE2e) GetE2E() e2e.Handler                          { return nil }

////////////////////////////////////////////////////////////////////////////////
// Mock cMix                                                                  //
////////////////////////////////////////////////////////////////////////////////
type cmixMsg struct {
	rid         id.Round
	targetedMsg cmix.TargetedCmixMessage
	msg         format.Message
}

type mockCmixHandler struct {
	sync.Mutex
	processorMap map[format.Fingerprint]message.Processor
	messageList  map[format.Fingerprint]cmixMsg
}

func newMockCmixHandler() *mockCmixHandler {
	return &mockCmixHandler{
		processorMap: make(map[format.Fingerprint]message.Processor),
		messageList:  make(map[format.Fingerprint]cmixMsg),
	}
}

type mockCmix struct {
	myID          *id.ID
	numPrimeBytes int
	health        bool
	handler       *mockCmixHandler
	healthCBs     map[uint64]func(b bool)
	healthIndex   uint64
	round         id.Round
	prng          *rand.Rand
	sync.Mutex
}

func newMockCmix(
	myID *id.ID, handler *mockCmixHandler, storage *mockStorage) *mockCmix {
	return &mockCmix{
		myID:          myID,
		numPrimeBytes: storage.GetCmixGroup().GetP().ByteLen(),
		health:        true,
		handler:       handler,
		healthCBs:     make(map[uint64]func(b bool)),
		healthIndex:   0,
		round:         0,
		prng:          rand.New(rand.NewSource(42)),
	}
}

func (m *mockCmix) Follow(cmix.ClientErrorReport) (stoppable.Stoppable, error) { panic("implement me") }

func (m *mockCmix) GetMaxMessageLength() int {
	msg := format.NewMessage(m.numPrimeBytes)
	return msg.ContentsSize()
}

func (m *mockCmix) Send(*id.ID, format.Fingerprint, message.Service, []byte,
	[]byte, cmix.CMIXParams) (rounds.Round, ephemeral.Id, error) {
	panic("implement me")
}

func (m *mockCmix) SendMany(messages []cmix.TargetedCmixMessage,
	_ cmix.CMIXParams) (rounds.Round, []ephemeral.Id, error) {
	m.handler.Lock()
	defer m.handler.Unlock()
	rid := m.round
	m.round++
	for _, targetedMsg := range messages {
		msg := format.NewMessage(m.numPrimeBytes)
		msg.SetContents(targetedMsg.Payload)
		msg.SetMac(targetedMsg.Mac)
		msg.SetKeyFP(targetedMsg.Fingerprint)
		m.handler.messageList[targetedMsg.Fingerprint] =
			cmixMsg{rid, targetedMsg, msg}

		if m.prng.Intn(20) != 5 {
			mp, exists := m.handler.processorMap[targetedMsg.Fingerprint]
			if exists {
				go func(mp message.Processor, rid id.Round,
					targetedMsg cmix.TargetedCmixMessage, msg format.Message) {
					mp.Process(
						msg,
						receptionID.EphemeralIdentity{Source: targetedMsg.Recipient},
						rounds.Round{ID: rid},
					)
				}(mp, rid, targetedMsg, msg)
			}
		}
	}
	return rounds.Round{ID: rid}, []ephemeral.Id{}, nil
}

func (m *mockCmix) SendWithAssembler(*id.ID, cmix.MessageAssembler,
	cmix.CMIXParams) (rounds.Round, ephemeral.Id, error) {
	panic("implement me")
}

func (m *mockCmix) AddIdentity(*id.ID, time.Time, bool)            { panic("implement me") }
func (m *mockCmix) RemoveIdentity(*id.ID)                          { panic("implement me") }
func (m *mockCmix) GetIdentity(*id.ID) (identity.TrackedID, error) { panic("implement me") }

func (m *mockCmix) AddFingerprint(_ *id.ID, fp format.Fingerprint, mp message.Processor) error {
	m.handler.Lock()
	defer m.handler.Unlock()
	m.handler.processorMap[fp] = mp

	p, exists := m.handler.messageList[fp]
	if exists {
		go mp.Process(
			p.msg,
			receptionID.EphemeralIdentity{Source: p.targetedMsg.Recipient},
			rounds.Round{ID: p.rid},
		)
	}

	return nil
}

func (m *mockCmix) DeleteFingerprint(_ *id.ID, fp format.Fingerprint) {
	m.handler.Lock()
	defer m.handler.Unlock()
	delete(m.handler.processorMap, fp)
}

func (m *mockCmix) DeleteClientFingerprints(*id.ID) {
	m.handler.Lock()
	defer m.handler.Unlock()
	m.handler.processorMap = make(map[format.Fingerprint]message.Processor)
}

func (m *mockCmix) AddService(*id.ID, message.Service, message.Processor)    { panic("implement me") }
func (m *mockCmix) DeleteService(*id.ID, message.Service, message.Processor) { panic("implement me") }
func (m *mockCmix) DeleteClientService(*id.ID)                               { panic("implement me") }
func (m *mockCmix) TrackServices(message.ServicesTracker)                    { panic("implement me") }
func (m *mockCmix) CheckInProgressMessages()                                 {}
func (m *mockCmix) IsHealthy() bool                                          { return m.health }
func (m *mockCmix) WasHealthy() bool                                         { return true }

func (m *mockCmix) AddHealthCallback(f func(bool)) uint64 {
	m.Lock()
	defer m.Unlock()
	m.healthIndex++
	m.healthCBs[m.healthIndex] = f
	go f(true)
	return m.healthIndex
}

func (m *mockCmix) RemoveHealthCallback(healthID uint64) {
	m.Lock()
	defer m.Unlock()
	if _, exists := m.healthCBs[healthID]; !exists {
		jww.FATAL.Panicf("No health callback with ID %d exists.", healthID)
	}
	delete(m.healthCBs, healthID)
}

func (m *mockCmix) HasNode(*id.ID) bool            { panic("implement me") }
func (m *mockCmix) NumRegisteredNodes() int        { panic("implement me") }
func (m *mockCmix) TriggerNodeRegistration(*id.ID) { panic("implement me") }

func (m *mockCmix) GetRoundResults(_ time.Duration,
	roundCallback cmix.RoundEventCallback, rids ...id.Round) {
	go roundCallback(true, false, map[id.Round]cmix.RoundResult{
		rids[0]: {
			Status: cmix.Succeeded,
			Round: rounds.Round{
				Timestamps: map[states.Round]time.Time{
					states.COMPLETED: netTime.Now(),
				},
			},
		}})
}

func (m *mockCmix) LookupHistoricalRound(id.Round, rounds.RoundResultCallback) error {
	panic("implement me")
}
func (m *mockCmix) SendToAny(func(host *connect.Host) (interface{}, error),
	*stoppable.Single) (interface{}, error) {
	panic("implement me")
}
func (m *mockCmix) SendToPreferred([]*id.ID, gateway.SendToPreferredFunc,
	*stoppable.Single, time.Duration) (interface{}, error) {
	panic("implement me")
}
func (m *mockCmix) SetGatewayFilter(gateway.Filter)   { panic("implement me") }
func (m *mockCmix) GetHostParams() connect.HostParams { panic("implement me") }
func (m *mockCmix) GetAddressSpace() uint8            { panic("implement me") }
func (m *mockCmix) RegisterAddressSpaceNotification(string) (chan uint8, error) {
	panic("implement me")
}
func (m *mockCmix) UnregisterAddressSpaceNotification(string) { panic("implement me") }
func (m *mockCmix) GetInstance() *network.Instance            { panic("implement me") }
func (m *mockCmix) GetVerboseRounds() string                  { panic("implement me") }

////////////////////////////////////////////////////////////////////////////////
// Mock Storage Session                                                       //
////////////////////////////////////////////////////////////////////////////////

type mockStorage struct {
	kv        *versioned.KV
	cmixGroup *cyclic.Group
}

func newMockStorage() *mockStorage {
	b := make([]byte, 768)
	rng := fastRNG.NewStreamGenerator(1000, 10, csprng.NewSystemRNG).GetStream()
	_, _ = rng.Read(b)
	rng.Close()

	return &mockStorage{
		kv:        versioned.NewKV(ekv.MakeMemstore()),
		cmixGroup: cyclic.NewGroup(large.NewIntFromBytes(b), large.NewInt(2)),
	}
}

func (m *mockStorage) GetClientVersion() version.Version     { panic("implement me") }
func (m *mockStorage) Get(string) (*versioned.Object, error) { panic("implement me") }
func (m *mockStorage) Set(string, *versioned.Object) error   { panic("implement me") }
func (m *mockStorage) Delete(string) error                   { panic("implement me") }
func (m *mockStorage) GetKV() *versioned.KV                  { return m.kv }
func (m *mockStorage) GetCmixGroup() *cyclic.Group           { return m.cmixGroup }
func (m *mockStorage) GetE2EGroup() *cyclic.Group            { panic("implement me") }
func (m *mockStorage) ForwardRegistrationStatus(storage.RegistrationStatus) error {
	panic("implement me")
}
func (m *mockStorage) GetRegistrationStatus() storage.RegistrationStatus      { panic("implement me") }
func (m *mockStorage) SetRegCode(string)                                      { panic("implement me") }
func (m *mockStorage) GetRegCode() (string, error)                            { panic("implement me") }
func (m *mockStorage) SetNDF(*ndf.NetworkDefinition)                          { panic("implement me") }
func (m *mockStorage) GetNDF() *ndf.NetworkDefinition                         { panic("implement me") }
func (m *mockStorage) GetTransmissionID() *id.ID                              { panic("implement me") }
func (m *mockStorage) GetTransmissionSalt() []byte                            { panic("implement me") }
func (m *mockStorage) GetReceptionID() *id.ID                                 { panic("implement me") }
func (m *mockStorage) GetReceptionSalt() []byte                               { panic("implement me") }
func (m *mockStorage) GetReceptionRSA() *rsa.PrivateKey                       { panic("implement me") }
func (m *mockStorage) GetTransmissionRSA() *rsa.PrivateKey                    { panic("implement me") }
func (m *mockStorage) IsPrecanned() bool                                      { panic("implement me") }
func (m *mockStorage) SetUsername(string) error                               { panic("implement me") }
func (m *mockStorage) GetUsername() (string, error)                           { panic("implement me") }
func (m *mockStorage) PortableUserInfo() userStorage.Info                     { panic("implement me") }
func (m *mockStorage) GetTransmissionRegistrationValidationSignature() []byte { panic("implement me") }
func (m *mockStorage) GetReceptionRegistrationValidationSignature() []byte    { panic("implement me") }
func (m *mockStorage) GetRegistrationTimestamp() time.Time                    { panic("implement me") }
func (m *mockStorage) SetTransmissionRegistrationValidationSignature([]byte)  { panic("implement me") }
func (m *mockStorage) SetReceptionRegistrationValidationSignature([]byte)     { panic("implement me") }
func (m *mockStorage) SetRegistrationTimestamp(int64)                         { panic("implement me") }
