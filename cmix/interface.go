////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"time"

	"gitlab.com/elixxir/client/v4/cmix/gateway"
	"gitlab.com/elixxir/client/v4/cmix/identity"
	"gitlab.com/elixxir/client/v4/cmix/message"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/stoppable"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
)

type Client interface {
	// Follow starts the tracking of the network in a new thread.
	// Errors that occur are reported on the ClientErrorReport function if
	// passed. The returned stoppable can be used to stop the follower.
	// Only one follower may run at a time.
	Follow(report ClientErrorReport) (stoppable.Stoppable, error)

	// SetTrackNetworkPeriod allows changing the frequency that follower threads
	// are started.
	//
	// Note that the frequency of the follower threads affect the power usage
	// of the device following the network.
	//   - Low period -> Higher frequency of polling -> Higher battery usage
	//   - High period -> Lower frequency of polling -> Lower battery usage
	// This may be used to enable a low power (or battery optimization) mode
	// for the end user.
	SetTrackNetworkPeriod(d time.Duration)

	/* === Sending ========================================================== */

	// GetMaxMessageLength returns the max message size for the current network.
	GetMaxMessageLength() int

	// Send sends a "raw" cMix message payload to the provided recipient.
	// Returns the round ID of the round the payload was sent or an error if it
	// fails.
	// This does not have end-to-end encryption on it and is used exclusively as
	// a send for higher order cryptographic protocols. Do not use unless
	// implementing a protocol on top.
	//   recipient - cMix ID of the recipient.
	//   fingerprint - Key Fingerprint. 256-bit field to store a 255-bit
	//      fingerprint, the highest order bit must be 0 (panic otherwise). If your
	//      system does not use key fingerprints, this must be random bits.
	//   service - Reception Service. The backup way for a client to identify
	//    messages on receipt via trial hashing and to identify notifications.
	//      If unused, use message.GetRandomService to fill the field with
	//      random data.
	//   payload - Contents of the message. Cannot exceed the payload size for a
	//      cMix message (panic otherwise).
	//   mac - 256-bit field to store a 255-bit mac, highest order bit must be 0
	//      (panic otherwise). If used, fill with random bits.
	// Will return an error if the network is unhealthy or if it fails to send
	// (along with the reason). Blocks until successful sends or errors.
	// WARNING: Do not roll your own crypto.
	Send(recipient *id.ID, fingerprint format.Fingerprint,
		service Service, payload, mac []byte, cmixParams CMIXParams) (
		rounds.Round, ephemeral.Id, error)

	// SendMany sends many "raw" cMix message payloads to the provided
	// recipients all in the same round.
	// Returns the round ID of the round the payloads was sent or an error if it
	// fails.
	// This does not have end-to-end encryption on it and is used exclusively as
	// a send for higher order cryptographic protocols. Do not use unless
	// implementing a protocol on top.
	// Due to sending multiple payloads, this leaks more metadata than a
	// standard cMix send and should be in general avoided.
	//   recipient - cMix ID of the recipient.
	//   fingerprint - Key Fingerprint. 256-bit field to store a 255-bit
	//      fingerprint, highest order bit must be 0 (panic otherwise). If your
	//      system does not use key fingerprints, this must be random bits.
	//   service - Reception Service. The backup way for a client to identify
	//      messages on receipt via trial hashing and to identify notifications.
	//      If unused, use message.GetRandomService to fill the field with
	//      random data.
	//   payload - Contents of the message. Cannot exceed the payload size for a
	//      cMix message (panic otherwise).
	//   mac - 256-bit field to store a 255-bit mac, highest order bit must be 0
	//      (panic otherwise). If used, fill with random bits.
	// Will return an error if the network is unhealthy or if it fails to send
	// (along with the reason). Blocks until successful send or err.
	// WARNING: Do not roll your own crypto.
	SendMany(messages []TargetedCmixMessage,
		params CMIXParams) (rounds.Round, []ephemeral.Id, error)

	// SendWithAssembler sends a variable cmix payload to the provided recipient.
	// The payload sent is based on the Complier function passed in, which accepts
	// a round ID and returns the necessary payload data.
	// Returns the round ID of the round the payload was sent or an error if it
	// fails.
	// This does not have end-to-end encryption on it and is used exclusively as
	// a send for higher order cryptographic protocols. Do not use unless
	// implementing a protocol on top.
	//   recipient - cMix ID of the recipient.
	//   assembler - MessageAssembler function, accepting round ID and returning
	//   fingerprint
	//   format.Fingerprint, service message.Service, payload, mac []byte
	// Will return an error if the network is unhealthy or if it fails to send
	// (along with the reason). Blocks until successful sends or errors.
	// WARNING: Do not roll your own crypto.
	SendWithAssembler(recipient *id.ID, assembler MessageAssembler,
		cmixParams CMIXParams) (rounds.Round, ephemeral.Id, error)

	// SendManyWithAssembler sends variable cMix payloads to the provided recipients.
	// The payloads sent are based on the ManyMessageAssembler function passed in,
	// which accepts a round ID and returns the necessary payload data.
	// Returns the round IDs of the rounds the payloads were sent or an error if it
	// fails.
	// This does not have end-to-end encryption on it and is used exclusively as
	// a send operation for higher order cryptographic protocols. Do not use unless
	// implementing a protocol on top.
	//
	//	recipients - cMix IDs of the recipients.
	//	assembler - ManyMessageAssembler function, accepting round ID and returning
	// 	            a list of TargetedCmixMessage.
	//
	// Will return an error if the network is unhealthy or if it fails to send
	// (along with the reason). Blocks until successful sends or errors.
	// WARNING: Do not roll your own crypto.
	SendManyWithAssembler(recipients []*id.ID, assembler ManyMessageAssembler,
		params CMIXParams) (rounds.Round, []ephemeral.Id, error)

	/* === Message Reception ================================================ */
	/* Identities are all network identities which the client is currently
	   trying to pick up message on. An identity must be added to receive
	   messages, fake ones will be used to poll the network if none are present.
	   On creation of the network handler, the identity in session storage will
	   be automatically added. */

	// AddIdentity adds an identity to be tracked. If persistent is false,
	// the identity will not be stored to disk and will be dropped on reload.
	// If the fallthrough processor is not nil, it will be used to process
	// messages for this id in the event there isn't a service or fingerprint
	// that matches the message.
	//
	// validUntil is the time the identity self-destructs. To set for forever,
	// use identity.Forever.
	AddIdentity(id *id.ID, validUntil time.Time, persistent bool,
		fallthroughProcessor message.Processor)

	// AddIdentityWithHistory adds an identity to be tracked. If persistent is
	// false, the identity will not be stored to disk and will be dropped on
	// reload. It will pick up messages slowly back in the history or up back
	// until beginning or the start of message retention, which should be ~500
	// houses back.
	// If the fallthrough processor is not nil, it will be used to process
	// messages for this id in the event there isn't a service or fingerprint
	// that matches the message.
	AddIdentityWithHistory(id *id.ID, validUntil, beginning time.Time, persistent bool,
		fallthroughProcessor message.Processor)

	// RemoveIdentity removes a currently tracked identity.
	RemoveIdentity(id *id.ID)

	// GetIdentity returns a currently tracked identity.
	GetIdentity(get *id.ID) (identity.TrackedID, error)

	/* Fingerprints are the primary mechanism of identifying a picked up message
	   over cMix. They are a unique one time use a 255-bit vector generally
	   associated with a specific encryption key, but can be used for an
	   alternative protocol. When registering a fingerprint, a message.Processor
	   is registered to handle the message. */

	// AddFingerprint adds a fingerprint that will be handled by a specific
	// processor for messages received by the given identity. If a nil identity
	// is passed, it will automatically use the default identity in the session.
	AddFingerprint(identity *id.ID, fingerprint format.Fingerprint,
		mp message.Processor) error

	// DeleteFingerprint deletes a single fingerprint associated with the given
	// identity, if it exists. If a nil identity is passed, it will
	// automatically use the default identity in the session.
	DeleteFingerprint(identity *id.ID, fingerprint format.Fingerprint)

	// DeleteClientFingerprints deletes all fingerprint associated with the
	// given identity, if it exists. A specific identity must be supplied; a
	// nil identity will result in a panic.
	DeleteClientFingerprints(identity *id.ID)

	/* Service - predefined hash based tags appended to all cMix messages that,
	   though trial hashing, are used to determine if a message applies to this
	   client.

	   Services are used for 2 purposes: they can be processed by the
	   notifications system, or they can be used to implement custom non-
	   fingerprint processing of payloads. i.e. key negotiation, broadcast
	   negotiation.

	   A tag is appended to the message of the format tag = H(H(messageContents),
	   preimage) and trial hashing is used to determine if a message adheres to
	   a tag.
	   WARNING: If a preimage is known by an adversary, they can determine which
	   messages are for the client on reception (which is normally hidden due to
	   collision between ephemeral IDs).

	   Due to the extra overhead of trial hashing, services  are processed after
	   fingerprints. If a fingerprint match occurs on the message, services will
	   not be handled.

	   Services are address to the session. When starting a new client, all
	   services must be re-added before StartNetworkFollower is called.

	   Compressed Services allow a server with many optional tags. They
	   achieve this by using a bloom filter to compress multiple tags
	   together. The rate of false positives increases exponentially after more than
	   4 tags are used in sending on the same compressed service.
	*/

	// AddService adds a service that can call a message handing function or be
	// used for notifications. In general, a single service can only be
	// registered for the same identifier/tag pair.
	//   preimage - The preimage that is triggered on.
	//   type - A descriptive string of the service. Generally used in
	//      notifications.
	//   source - A byte buffer of related data. Generally used in notifications.
	//     Example: Sender ID
	// There can be multiple "default" services; if the "default" tag is used,
	// then the identifier must be the client reception ID.
	// A service may have a nil response unless it is default. In general a
	// nil service is used to detect notifications when pickup is done by
	// fingerprints.
	AddService(clientID *id.ID, newService message.Service,
		response message.Processor)

	// UpsertCompressedService adds a compressed service which can call a message
	// handing function or be used for notifications. Online a single compressed
	// service can be registered to an identifier. If the same identifier is used,
	// it will replace the old one.
	UpsertCompressedService(clientID *id.ID, newService message.CompressedService,
		response message.Processor)

	// PauseNodeRegistrations stops all node registrations and returns a
	// function to resume them.
	PauseNodeRegistrations(timeout time.Duration) error

	// ChangeNumberOfNodeRegistrations changes the number of parallel node
	// registrations up to the initialized maximum.
	ChangeNumberOfNodeRegistrations(toRun int, timeout time.Duration) error

	// DeleteService deletes a message service. If only a single response is
	// associated with the preimage, the entire preimage is removed. If there is
	// more than one response, only the given response is removed. If nil is
	// passed in for response, all triggers for the preimage will be removed.
	// The processor is only used in deletion when deleting a default service
	DeleteService(clientID *id.ID, toDelete message.Service,
		processor message.Processor)

	// DeleteClientService deletes the mapping associated with an ID.
	// deletes both services and compressed services
	DeleteClientService(clientID *id.ID)

	// DeleteCompressedService - If only a single response is associated with the preimage,
	// the entire preimage is removed. If there is more than one response, only the
	// given response is removed. If nil is passed in for response, all triggers for
	// the preimage will be removed.
	DeleteCompressedService(clientID *id.ID, toDelete message.CompressedService,
		processor message.Processor)

	// TrackServices registers a callback that is called every time a service is
	// added or removed. It is also called once when registered. The callback
	// receives the new service lists every time they are modified. Callbacks
	// only occur when the network follower is running. Multiple
	// [message.ServicesTracker] can be registered.
	TrackServices(tracker message.ServicesTracker)

	// GetServices returns the current list of registered services and
	// compressed services. This returns the same lists as the last lists
	// provided to trackers registered with [TrackServices].
	GetServices() (message.ServiceList, message.CompressedServiceList)

	/* === In inProcess ===================================================== */
	/* It is possible to receive a message over cMix before the fingerprints or
	   triggers are registered. As a result, when handling fails, messages are
	   put in the inProcess que for a set number of retries. */

	// CheckInProgressMessages retries processing all messages in check in
	// progress messages. Call this after adding fingerprints or triggers while
	// the follower is running.
	CheckInProgressMessages()

	/* === Health Monitor =================================================== */
	/* The health monitor is a system that tracks if the client sees a live
	   network. It can either be polled or set up with events. */

	// IsHealthy returns true if currently healthy.
	IsHealthy() bool

	// WasHealthy returns true if the network has ever been healthy in this run.
	WasHealthy() bool

	// AddHealthCallback adds a callback that gets called whenever the network
	// health changes. Returns a registration ID that can be used to unregister.
	AddHealthCallback(f func(bool)) uint64

	// RemoveHealthCallback removes a health callback using its registration ID.
	RemoveHealthCallback(uint64)

	/* === Nodes ============================================================ */
	/* Keys must be registered with nodes in order to send messages through
	   them. This process is, in general, automatically handled by the Network
	   client. */

	// HasNode can be used to determine if a keying relationship exists with a
	// node.
	HasNode(nid *id.ID) bool

	// NumRegisteredNodes returns the total number of nodes we have a keying
	// relationship with.
	NumRegisteredNodes() int

	// TriggerNodeRegistration triggers the negotiation of a keying relationship
	// with a given node.
	TriggerNodeRegistration(nid *id.ID)

	/* === Rounds =========================================================== */
	/* A complete set of round info is not kept on the client, and sometimes
	   the network will need to be queried to get round info. Historical rounds
	   is the system internal to the Network client to do this. It can be used
	   externally as well. */

	// GetRoundResults adjudicates on the rounds requested. Checks if they are
	// older rounds or in progress rounds.
	GetRoundResults(timeout time.Duration, roundCallback RoundEventCallback,
		roundList ...id.Round)

	// LookupHistoricalRound looks up the passed historical round on the network.
	// GetRoundResults does this lookup when needed, generally that is
	// preferable
	LookupHistoricalRound(
		rid id.Round, callback rounds.RoundResultCallback) error

	/* === Sender =========================================================== */
	/* The sender handles sending comms to the network. It tracks connections to
	   gateways and handles proxying to gateways for targeted comms. It can be
	   used externally to contact gateway directly, bypassing the majority of
	   the network package. */

	// SendToAny can be used to send the comm to any gateway in the network.
	SendToAny(sendFunc func(host *connect.Host) (interface{}, error),
		stop *stoppable.Single) (interface{}, error)

	// SendToPreferred sends to a specific gateway, doing so through another
	// gateway as a proxy if not directly connected.
	SendToPreferred(targets []*id.ID, sendFunc gateway.SendToPreferredFunc,
		stop *stoppable.Single, timeout time.Duration) (interface{}, error)

	// GetHostParams returns the host params used when connecting to gateways.
	GetHostParams() connect.HostParams

	/* === Address Space ==================================================== */
	/* The network compasses identities into a smaller address space to cause
	   collisions and hide the actual recipient of messages. These functions
	   allow for the tracking of this addresses space. In general, address space
	   issues are completely handled by the network package. */

	// GetAddressSpace returns the current address size of IDs. Blocks until an
	// address size is known.
	GetAddressSpace() uint8

	// RegisterAddressSpaceNotification returns a channel that will trigger for
	// every address space size update. The provided tag is the unique ID for
	// the channel. Returns an error if the tag is already used.
	RegisterAddressSpaceNotification(tag string) (chan uint8, error)

	// UnregisterAddressSpaceNotification stops broadcasting address space size
	// updates on the channel with the specified tag.
	UnregisterAddressSpaceNotification(tag string)

	/* === Accessors ======================================================== */

	// GetInstance returns the network instance object, which tracks the
	// state of the network.
	GetInstance() *network.Instance

	// GetVerboseRounds returns stringification of verbose round info.
	GetVerboseRounds() string
}

type ClientErrorReport func(source, message, trace string)

// ManyMessageAssembler func accepts a round ID, returning a TargetedCmixMessage.
// This allows users to pass in a payload which will contain the
// round ID over which the message is sent.
type ManyMessageAssembler func(rid id.Round) ([]TargetedCmixMessage, error)

// manyMessageAssembler is an internal wrapper around ManyMessageAssembler which
// returns a list of assembledCmixMessage.
type manyMessageAssembler func(rid id.Round) ([]assembledCmixMessage, error)

// A Service is an operator which creates a tag on the message which can be
// used, without leaking metadata, to find if a message is for a specific
// party. The tag fits in the 200 bit "SIH" (Service Identification Hash)
// field on the cmix message.  They come in two flavors, message.Service,
// Which has a single tag which is matched on, and
// message.CompressedService which used and encrypted bloom filter
// to compress multiple SIH tags into the field.
// It takes in the ID that is being sent to as well as the contents
// of the message.
type Service interface {
	Hash(pickup *id.ID, contents []byte) ([]byte, error)
}

// MessageAssembler func accepts a round ID, returning fingerprint, service,
// payload & mac. This allows users to pass in a payload which will contain the
// round ID over which the message is sent.
type MessageAssembler func(rid id.Round) (fingerprint format.Fingerprint,
	service Service, payload, mac []byte, err error)

// messageAssembler is an internal wrapper around MessageAssembler which
// returns a format.Message This is necessary to preserve the interaction
// between sendCmixHelper and critical messages
type messageAssembler func(rid id.Round) (format.Message, error)
