////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

// Package channels provides a channels implementation on top of broadcast
// which is capable of handing the user facing features of channels, including
// replies, reactions, and eventually admin commands.
package channels

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/broadcast"
	"gitlab.com/elixxir/client/v4/cmix"
	"gitlab.com/elixxir/client/v4/cmix/message"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/storage/versioned"
	"gitlab.com/elixxir/client/v4/xxdk"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/crypto/fastRNG"
	"gitlab.com/elixxir/crypto/rsa"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"sync"
	"time"
)

const storageTagFormat = "channelManagerStorageTag-%s"

type manager struct {
	// Sender Identity
	me cryptoChannel.PrivateIdentity

	// List of all channels
	channels map[id.ID]*joinedChannel
	mux      sync.RWMutex

	// External references
	kv  *versioned.KV
	net Client
	rng *fastRNG.StreamGenerator

	// Events model
	*events

	// Nicknames
	*nicknameManager

	// Send tracker
	st *sendTracker

	// Makes the function that is used to create broadcasts be a pointer so that
	// it can be replaced in tests
	broadcastMaker broadcast.NewBroadcastChannelFunc
}

// Client contains the methods from cmix.Client that are required by the
// [Manager].
type Client interface {
	GetMaxMessageLength() int
	SendWithAssembler(recipient *id.ID, assembler cmix.MessageAssembler,
		cmixParams cmix.CMIXParams) (rounds.Round, ephemeral.Id, error)
	IsHealthy() bool
	AddIdentity(id *id.ID, validUntil time.Time, persistent bool)
	AddIdentityWithHistory(
		id *id.ID, validUntil, beginning time.Time, persistent bool)
	AddService(clientID *id.ID, newService message.Service,
		response message.Processor)
	DeleteClientService(clientID *id.ID)
	RemoveIdentity(id *id.ID)
	GetRoundResults(timeout time.Duration, roundCallback cmix.RoundEventCallback,
		roundList ...id.Round)
	AddHealthCallback(f func(bool)) uint64
	RemoveHealthCallback(uint64)
}

// EventModelBuilder initialises the event model using the given path.
type EventModelBuilder func(path string) (EventModel, error)

// AddServiceFn adds a service to be controlled by the client thread control.
// These will be started and stopped with the network follower.
//
// This type must match [Cmix.AddService].
type AddServiceFn func(sp xxdk.Service) error

// NewManager creates a new channel Manager from a [channel.PrivateIdentity]. It
// prefixes the KV with a tag derived from the public key that can be retried
// for reloading using [Manager.GetStorageTag].
func NewManager(identity cryptoChannel.PrivateIdentity, kv *versioned.KV,
	net Client, rng *fastRNG.StreamGenerator, modelBuilder EventModelBuilder,
	addService AddServiceFn) (Manager, error) {
	// Prefix the kv with the username so multiple can be run
	storageTag := getStorageTag(identity.PubKey)
	jww.INFO.Printf("[CH] NewManager for %s (pubKey:%x tag:%s)",
		identity.Codename, identity.PubKey, storageTag)
	kv = kv.Prefix(storageTag)

	if err := storeIdentity(kv, identity); err != nil {
		return nil, err
	}

	model, err := modelBuilder(storageTag)
	if err != nil {
		return nil, errors.Errorf("Failed to build event model: %+v", err)
	}

	m := setupManager(identity, kv, net, rng, model)

	return m, addService(m.leases.StartProcesses)
}

// LoadManager restores a channel Manager from disk stored at the given storage
// tag.
func LoadManager(storageTag string, kv *versioned.KV, net Client,
	rng *fastRNG.StreamGenerator, modelBuilder EventModelBuilder) (Manager, error) {
	jww.INFO.Printf("[CH] LoadManager for tag %s", storageTag)

	// Prefix the kv with the username so multiple can be run
	kv = kv.Prefix(storageTag)

	// Load the identity
	identity, err := loadIdentity(kv)
	if err != nil {
		return nil, err
	}

	model, err := modelBuilder(storageTag)
	if err != nil {
		return nil, errors.Errorf("Failed to build event model: %+v", err)
	}

	m := setupManager(identity, kv, net, rng, model)

	return m, nil
}

func setupManager(identity cryptoChannel.PrivateIdentity, kv *versioned.KV,
	net Client, rng *fastRNG.StreamGenerator, model EventModel) *manager {
	m := manager{
		me:              identity,
		kv:              kv,
		net:             net,
		rng:             rng,
		events:          initEvents(model, kv),
		broadcastMaker:  broadcast.NewBroadcastChannel,
	}

	m.st = loadSendTracker(net, kv, m.events.triggerEvent,
		m.events.triggerAdminEvent, model.UpdateFromUUID, rng)

	m.loadChannels()

	m.nicknameManager = loadOrNewNicknameManager(kv)

	return &m
}

// GenerateChannel creates a new channel with the user as the admin and returns
// the broadcast.Channel object. This function only create a channel and does
// not join it.
//
// The private key is saved to storage and can be accessed with
// ExportChannelAdminKey.
func (m *manager) GenerateChannel(
	name, description string, privacyLevel cryptoBroadcast.PrivacyLevel) (
	*cryptoBroadcast.Channel, error) {
	jww.INFO.Printf("[CH] GenerateChannel %q with description %q and privacy "+
		"level %s", name, description, privacyLevel)
	ch, _, err := m.generateChannel(
		name, description, privacyLevel, m.net.GetMaxMessageLength())
	return ch, err
}

// generateChannel generates a new channel with a custom packet payload length.
func (m *manager) generateChannel(name, description string,
	privacyLevel cryptoBroadcast.PrivacyLevel, packetPayloadLength int) (
	*cryptoBroadcast.Channel, rsa.PrivateKey, error) {

	// Generate channel
	stream := m.rng.GetStream()
	ch, pk, err := cryptoBroadcast.NewChannel(
		name, description, privacyLevel, packetPayloadLength, stream)
	stream.Close()
	if err != nil {
		return nil, nil, err
	}

	// Save private key to storage
	err = saveChannelPrivateKey(ch.ReceptionID, pk, m.kv)
	if err != nil {
		return nil, nil, err
	}

	return ch, pk, nil
}

// JoinChannel joins the given channel. It will return the error
// ChannelAlreadyExistsErr if the channel has already been joined.
func (m *manager) JoinChannel(channel *cryptoBroadcast.Channel) error {
	jww.INFO.Printf(
		"[CH] JoinChannel %q with ID %s", channel.Name, channel.ReceptionID)
	err := m.addChannel(channel)
	if err != nil {
		return err
	}

	// Report joined channel to the event model
	go m.events.model.JoinChannel(channel)

	return nil
}

// LeaveChannel leaves the given channel. It will return the error
// ChannelDoesNotExistsErr if the channel was not previously joined.
func (m *manager) LeaveChannel(channelID *id.ID) error {
	jww.INFO.Printf("[CH] LeaveChannel %s", channelID)
	err := m.removeChannel(channelID)
	if err != nil {
		return err
	}

	go m.events.model.LeaveChannel(channelID)

	return nil
}

// ReplayChannel replays all messages from the channel within the network's
// memory (~3 weeks) over the event model. It does this by wiping the underlying
// state tracking for message pickup for the channel, causing all messages to be
// re-retrieved from the network.
//
// Returns the error ChannelDoesNotExistsErr if the channel was not previously
// joined.
func (m *manager) ReplayChannel(channelID *id.ID) error {
	jww.INFO.Printf("[CH] ReplayChannel %s", channelID)
	m.mux.RLock()
	defer m.mux.RUnlock()

	jc, exists := m.channels[*channelID]
	if !exists {
		return ChannelDoesNotExistsErr
	}

	c := jc.broadcast.Get()

	// Stop the broadcast that will completely wipe it from the underlying cmix
	// object
	jc.broadcast.Stop()

	// Re-instantiate the broadcast, re-registering it from scratch
	b, err := m.initBroadcast(c)
	if err != nil {
		return err
	}
	jc.broadcast = b

	return nil
}

// GetChannels returns the IDs of all channels that have been joined.
//
// Use manager.getChannelsUnsafe if you already have taken the mux.
func (m *manager) GetChannels() []*id.ID {
	jww.INFO.Print("[CH] GetChannels")
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.getChannelsUnsafe()
}

// GetChannel returns the underlying cryptographic structure for a given
// channel.
//
// Returns the error ChannelDoesNotExistsErr if the channel was not previously
// joined.
func (m *manager) GetChannel(channelID *id.ID) (*cryptoBroadcast.Channel, error) {
	jww.INFO.Printf("[CH] GetChannel %s", channelID)
	jc, err := m.getChannel(channelID)
	if err != nil {
		return nil, err
	} else if jc.broadcast == nil {
		return nil, errors.New("broadcast.Channel on joinedChannel is nil")
	}
	return jc.broadcast.Get(), nil
}

////////////////////////////////////////////////////////////////////////////////
// Other Channel Actions                                                      //
////////////////////////////////////////////////////////////////////////////////

// GetIdentity returns the public identity of the user associated with this
// channel manager.
func (m *manager) GetIdentity() cryptoChannel.Identity {
	return m.me.Identity
}

// ExportPrivateIdentity encrypts the private identity using the password and
// exports it to a portable string.
func (m *manager) ExportPrivateIdentity(password string) ([]byte, error) {
	jww.INFO.Print("[CH] ExportPrivateIdentity")
	rng := m.rng.GetStream()
	defer rng.Close()
	return m.me.Export(password, rng)
}

// GetStorageTag returns the tag at where this manager is stored. To be used
// when loading the manager. The storage tag is derived from the public key.
func (m *manager) GetStorageTag() string {
	return getStorageTag(m.me.PubKey)
}

// getStorageTag generates a storage tag from an Ed25519 public key.
func getStorageTag(pub ed25519.PublicKey) string {
	return fmt.Sprintf(storageTagFormat, base64.StdEncoding.EncodeToString(pub))
}

// Muted returns true if the user is currently muted in the given channel.
func (m *manager) Muted(channelID *id.ID) bool {
	jww.INFO.Printf("[CH] Muted in channel %s", channelID)
	return m.events.mutedUsers.isMuted(channelID, m.me.PubKey)
}

// GetMutedUsers returns the list of the public keys for each muted user in
// the channel. If there are no muted user or if the channel does not exist,
// an empty list is returned.
func (m *manager) GetMutedUsers(channelID *id.ID) []ed25519.PublicKey {
	jww.INFO.Printf("[CH] GetMutedUsers in channel %s", channelID)
	return m.mutedUsers.getMutedUsers(channelID)
}
