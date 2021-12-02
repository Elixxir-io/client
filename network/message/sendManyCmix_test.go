package message

import (
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/interfaces/message"
	"gitlab.com/elixxir/client/interfaces/params"
	"gitlab.com/elixxir/client/network/gateway"
	"gitlab.com/elixxir/client/network/internal"
	"gitlab.com/elixxir/client/storage"
	"gitlab.com/elixxir/client/switchboard"
	"gitlab.com/elixxir/comms/client"
	"gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/comms/network"
	ds "gitlab.com/elixxir/comms/network/dataStructures"
	"gitlab.com/elixxir/comms/testutils"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/e2e"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/elixxir/primitives/states"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/netTime"
	"testing"
	"time"
)

// Unit test
func Test_attemptSendManyCmix(t *testing.T) {
	sess1 := storage.InitTestingSession(t)
	events := &dummyEvent{}

	numRecipients := 3
	recipients := make([]*id.ID, numRecipients)
	sw := switchboard.New()
	l := TestListener{
		ch: make(chan bool),
	}
	for i := 0; i < numRecipients; i++ {
		sess := storage.InitTestingSession(t)
		sw.RegisterListener(sess.GetUser().TransmissionID, message.Raw, l)
		recipients[i] = sess.GetUser().ReceptionID
	}

	comms, err := client.NewClientComms(sess1.GetUser().TransmissionID, nil, nil, nil)
	if err != nil {
		t.Errorf("Failed to start client comms: %+v", err)
	}
	inst, err := network.NewInstanceTesting(comms.ProtoComms, getNDF(), nil, nil, nil, t)
	if err != nil {
		t.Errorf("Failed to start instance: %+v", err)
	}
	now := netTime.Now()
	nid1 := id.NewIdFromString("zezima", id.Node, t)
	nid2 := id.NewIdFromString("jakexx360", id.Node, t)
	nid3 := id.NewIdFromString("westparkhome", id.Node, t)
	grp := cyclic.NewGroup(large.NewInt(7), large.NewInt(13))
	sess1.Cmix().Add(nid1, grp.NewInt(1), 0, nil)
	sess1.Cmix().Add(nid2, grp.NewInt(2), 0, nil)
	sess1.Cmix().Add(nid3, grp.NewInt(3), 0, nil)

	timestamps := []uint64{
		uint64(now.Add(-30 * time.Second).UnixNano()), // PENDING
		uint64(now.Add(-25 * time.Second).UnixNano()), // PRECOMPUTING
		uint64(now.Add(-5 * time.Second).UnixNano()),  // STANDBY
		uint64(now.Add(5 * time.Second).UnixNano()),   // QUEUED
		0} // REALTIME

	ri := &mixmessages.RoundInfo{
		ID:                         3,
		UpdateID:                   0,
		State:                      uint32(states.QUEUED),
		BatchSize:                  0,
		Topology:                   [][]byte{nid1.Marshal(), nid2.Marshal(), nid3.Marshal()},
		Timestamps:                 timestamps,
		Errors:                     nil,
		ClientErrors:               nil,
		ResourceQueueTimeoutMillis: 0,
		Signature:                  nil,
		AddressSpaceSize:           4,
	}

	if err = testutils.SignRoundInfoRsa(ri, t); err != nil {
		t.Errorf("Failed to sign mock round info: %v", err)
	}

	pubKey, err := testutils.LoadPublicKeyTesting(t)
	if err != nil {
		t.Errorf("Failed to load a key for testing: %v", err)
	}
	rnd := ds.NewRound(ri, pubKey, nil)
	inst.GetWaitingRounds().Insert(rnd)
	i := internal.Internal{
		Session:          sess1,
		Switchboard:      sw,
		Rng:              fastRNG.NewStreamGenerator(1, 1, csprng.NewSystemRNG),
		Comms:            comms,
		Health:           nil,
		TransmissionID:   sess1.GetUser().TransmissionID,
		Instance:         inst,
		NodeRegistration: nil,
	}
	p := gateway.DefaultPoolParams()
	p.MaxPoolSize = 1
	sender, err := gateway.NewSender(p, i.Rng, getNDF(), &MockSendCMIXComms{t: t}, i.Session, nil)
	if err != nil {
		t.Errorf("%+v", errors.New(err.Error()))
		return
	}
	m := NewManager(i, params.Network{Messages: params.Messages{
		MessageReceptionBuffLen:        20,
		MessageReceptionWorkerPoolSize: 20,
		MaxChecksGarbledMessage:        20,
		GarbledMessageWait:             time.Hour,
	}}, nil, sender)
	msgCmix := format.NewMessage(m.Session.Cmix().GetGroup().GetP().ByteLen())
	msgCmix.SetContents([]byte("test"))
	e2e.SetUnencrypted(msgCmix, m.Session.User().GetCryptographicIdentity().GetTransmissionID())
	messages := make([]format.Message, numRecipients)
	for i := 0; i < numRecipients; i++ {
		messages[i] = msgCmix
	}

	msgList := make([]message.TargetedCmixMessage, numRecipients)
	for i := 0; i < numRecipients; i++ {
		msgList[i] = message.TargetedCmixMessage{
			Recipient: recipients[i],
			Message:   msgCmix,
		}
	}

	_, _, err = sendManyCmixHelper(sender, msgList, params.GetDefaultCMIX(), &SkipNodes{
		blacklistedNodes: map[string]interface{}{},
	}, m.Instance, m.Session, m.nodeRegistration,
		m.Rng, events, m.TransmissionID, &MockSendCMIXComms{t: t}, nil)
	if err != nil {
		t.Errorf("Failed to sendcmix: %+v", err)
	}
}
