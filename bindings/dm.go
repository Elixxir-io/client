///////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package bindings

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sync"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/elixxir/client/v4/dm"
	"gitlab.com/elixxir/client/v4/dm/storage"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	"gitlab.com/elixxir/crypto/codename"
	"gitlab.com/elixxir/crypto/message"
	"gitlab.com/elixxir/primitives/notifications"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
)

// DMReceiverBuilder builds an event model.
type DMReceiverBuilder interface {
	Build(path string) DMReceiver
}

// DMClient is the bindings level interface for the direct messaging client. It
// implements all the [dm.Client] functions but converts from basic types that
// are friendly to gomobile and Javascript WASM interfaces (e.g., []byte, int,
// and string).
//
// Users of the bindings API can create multiple DMClient objects, which are
// tracked via a private singleton.
type DMClient struct {
	api dm.Client
	// NOTE: This matches the integer in the dmClientTracker singleton
	id int
}

// NewDMClient creates a new [DMClient] from a private identity
// ([codename.PrivateIdentity]), used for direct messaging.
//
// This is for instantiating a manager for an identity. For generating
// a new identity, use [codename.GenerateIdentity]. You should instantiate
// every load as there is no load function and associated state in
// this module.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker (int). This can be retrieved
//     using [Cmix.GetID].
//   - notificationsID - ID of [Notifications] object in tracker. This can be
//     retrieved using [Notifications.GetID].
//   - privateIdentity - Bytes of a private identity
//     ([codename.PrivateIdentity]) that is generated by
//     [codename.GenerateIdentity].
//   - receiverBuilder - An interface that contains a function that initialises
//     and returns an [EventModel] that is bindings-compatible.
//   - cbs - Callbacks is an interface that provides updates about information
//     relating to DM conversations. The interface may be nil, but if one is
//     provided, each method must be implemented.
func NewDMClient(cmixID, notificationsID int, privateIdentity []byte,
	receiverBuilder DMReceiverBuilder, cbs DmCallbacks) (*DMClient, error) {
	pi, err := codename.UnmarshalPrivateIdentity(privateIdentity)
	if err != nil {
		return nil, err
	}

	// Get user from singleton
	user, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return nil, err
	}

	// Get notification manager from singleton
	nm, err := notifTrackerSingleton.get(notificationsID)
	if err != nil {
		return nil, err
	}

	eb := func(path string) (dm.EventModel, error) {
		return NewDMReceiver(receiverBuilder.Build(path)), nil
	}

	// We path to the string of the public key for this user
	dmPath := base64.RawStdEncoding.EncodeToString(pi.PubKey[:])
	receiver, err := eb(dmPath)
	if err != nil {
		return nil, err
	}

	receptionID := dm.DeriveReceptionID(pi.PubKey, pi.GetDMToken())

	nickMgr := dm.NewNicknameManager(receptionID,
		user.api.GetStorage().GetKV())

	sendTracker := dm.NewSendTracker(user.api.GetStorage().GetKV())

	dmKV, err := user.api.GetStorage().GetKV().Prefix("dm")
	if err != nil {
		return nil, err
	}

	m, err := dm.NewDMClient(&pi, receiver, sendTracker, nickMgr, nm.manager,
		user.api.GetCmix(), dmKV, user.api.GetRng(), wrapDmCallbacks(cbs))
	if err != nil {
		return nil, err
	}

	// Add channel to singleton and return
	return dmClients.add(m), nil
}

// NewDMClientWithGoEventModel creates a new [DMClient] from a private identity
// ([codename.PrivateIdentity]). This is not compatible with GoMobile bindings
// because it receives the go event model.
//
// This is for instantiating a manager for an identity. For generating
// a new identity, use [codename.GenerateIdentity]. You should instantiate
// every load as there is no load function and associated state in
// this module.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker (int). This can be retrieved
//     using [Cmix.GetID].
//   - notificationsID - ID of [Notifications] object in tracker. This can be
//     retrieved using [Notifications.GetID].
//   - privateIdentity - Bytes of a private identity
//     ([codename.PrivateIdentity]) that is generated by
//     [codename.GenerateIdentity].
//   - receiver - The [dm.EventModel].
//   - cbs - Callbacks is an interface that provides updates about information
//     relating to DM conversations. The interface may be nil, but if one is
//     provided, each method must be implemented.
func NewDMClientWithGoEventModel(cmixID, notificationsID int,
	privateIdentity []byte, receiver dm.EventModel, cbs DmCallbacks) (*DMClient, error) {
	pi, err := codename.UnmarshalPrivateIdentity(privateIdentity)
	if err != nil {
		return nil, err
	}

	// Get user from singleton
	user, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return nil, err
	}

	// Get notification manager from singleton
	nm, err := notifTrackerSingleton.get(notificationsID)
	if err != nil {
		return nil, err
	}

	receptionID := dm.DeriveReceptionID(pi.PubKey, pi.GetDMToken())

	nickMgr := dm.NewNicknameManager(receptionID,
		user.api.GetStorage().GetKV())

	sendTracker := dm.NewSendTracker(user.api.GetStorage().GetKV())

	dmKV, err := user.api.GetStorage().GetKV().Prefix("dm")
	if err != nil {
		return nil, err
	}

	m, err := dm.NewDMClient(&pi, receiver, sendTracker, nickMgr, nm.manager,
		user.api.GetCmix(), dmKV, user.api.GetRng(), wrapDmCallbacks(cbs))
	if err != nil {
		return nil, err
	}

	// Add channel to singleton and return
	return dmClients.add(m), nil
}

// NewDmManagerMobile loads an existing [DMClient] for the given storage
// tag backed with SqlLite for mobile use.
//
// Parameters:
//   - cmixID - ID of [Cmix] object in tracker. This can be retrieved using
//     [Cmix.GetID].
//   - notificationsID - ID of [Notifications] object in tracker. This can be
//     retrieved using [Notifications.GetID].
//   - privateIdentity - Bytes of a private identity
//     ([codename.PrivateIdentity]) that is generated by
//     [codename.GenerateIdentity].
//   - dbFilePath - absolute string path to the SqlLite database file
//   - cbs - Callbacks is an interface that provides updates about information
//     relating to DM conversations. The interface may be nil, but if one is
//     provided, each method must be implemented.
func NewDmManagerMobile(cmixID, notificationsID int, privateIdentity []byte,
	dbFilePath string, cbs DmCallbacks) (*DMClient, error) {

	// Get user from singleton
	user, err := cmixTrackerSingleton.get(cmixID)
	if err != nil {
		return nil, err
	}

	// Get notification manager from singleton
	nm, err := notifTrackerSingleton.get(notificationsID)
	if err != nil {
		return nil, err
	}

	wrap := wrapDmCallbacks(cbs)

	model, err := storage.NewEventModel(dbFilePath, wrap)
	if err != nil {
		return nil, err
	}

	pi, err := codename.UnmarshalPrivateIdentity(privateIdentity)
	if err != nil {
		return nil, err
	}

	receptionID := dm.DeriveReceptionID(pi.PubKey, pi.GetDMToken())

	nickMgr := dm.NewNicknameManager(receptionID,
		user.api.GetStorage().GetKV())

	sendTracker := dm.NewSendTracker(user.api.GetStorage().GetKV())

	dmKV, err := user.api.GetStorage().GetKV().Prefix("dm")
	if err != nil {
		return nil, err
	}

	m, err := dm.NewDMClient(&pi, model, sendTracker, nickMgr, nm.manager,
		user.api.GetCmix(), dmKV, user.api.GetRng(), wrapDmCallbacks(cbs))
	if err != nil {
		return nil, err
	}

	// Add channel to singleton and return
	return dmClients.add(m), nil
}

////////////////////////////////////////////////////////////////////////////////
// DM Share URL                                                          //
////////////////////////////////////////////////////////////////////////////////

// DMShareURL is returned from [DMClient.GetShareURL]. It includes the
// user's share URL.
//
// JSON example for a user:
//
//	{
//	 "url": "https://internet.speakeasy.tech/?l=32&m=5&p=EfDzQDa4fQ5BoqNIMbECFDY9ckRr_fadd8F1jE49qJc%3D&t=4231817746&v=1",
//	 "password": "hunter2",
//	}
type DMShareURL struct {
	URL      string `json:"url"`
	Password string `json:"password"`
}

// DMUser is returned from [DecodeDMShareURL]. It includes the token
// and public key of the user who created the URL.
//
// JSON example for a user:
//
//	{
//	 "token": 4231817746,
//	 "publicKey": "EfDzQDa4fQ5BoqNIMbECFDY9ckRr/fadd8F1jE49qJc="
//	}
type DMUser struct {
	Token     int32  `json:"token"`
	PublicKey []byte `json:"publicKey"`
}

// GetShareURL generates a URL that can be used to share a URL to initiate d
// direct messages with this user.
//
// Parameters:
//   - host - The URL to append the DM info to.
//
// Returns:
//   - JSON of [DMShareURL].
func (dmc *DMClient) GetShareURL(host string) ([]byte, error) {
	// todo: in a later ticket, RNG will be utilized for password protected DMs
	//  This note is for this ticketholder: RNG is part of the DMClient, but
	//  there is no accessor. Simply add the accessor to the interface and call
	//   dmc.GetRNG().GetStream.
	url, err := dm.ShareURL(
		host, 0, int32(dmc.api.GetToken()), dmc.api.GetPublicKey(), nil)
	if err != nil {
		return nil, err
	}

	su := DMShareURL{
		URL: url,
	}

	return json.Marshal(su)
}

// DecodeDMShareURL decodes the user's URL into a DMUser.
//
// Parameters:
//   - url - The user's share URL. Should be received from another user or
//     generated via [DMClient.GetShareURL].
//
// Returns:
//   - JSON of DMUser.
func DecodeDMShareURL(url string) ([]byte, error) {
	token, pubKey, err := dm.DecodeShareURL(url, "")
	if err != nil {
		return nil, err
	}

	dmShareReport := &DMUser{
		Token:     token,
		PublicKey: pubKey.Bytes(),
	}

	return json.Marshal(dmShareReport)
}

// GetID returns the tracker ID for the DMClient object.
func (dmc *DMClient) GetID() int {
	return dmc.id
}

// GetPublicKey returns the bytes of the public key for this client.
func (dmc *DMClient) GetPublicKey() []byte {
	return dmc.api.GetPublicKey().Bytes()
}

// GetToken returns the DM token of this client.
func (dmc *DMClient) GetToken() int64 {
	return int64(dmc.api.GetToken())
}

// GetIdentity returns the public identity associated with this client.
func (dmc *DMClient) GetIdentity() []byte {
	return dmc.api.GetIdentity().Marshal()
}

// ExportPrivateIdentity encrypts and exports the private identity to a portable
// string.
func (dmc *DMClient) ExportPrivateIdentity(password string) ([]byte, error) {
	return dmc.api.ExportPrivateIdentity(password)
}

// GetNickname gets the nickname associated with this DM user.
func (dmc *DMClient) GetNickname() (string, error) {
	nick, exists := dmc.api.GetNickname()
	if !exists {
		return "", errors.New("no nickname found")
	}
	return nick, nil
}

// SetNickname sets the nickname to use for this user.
func (dmc *DMClient) SetNickname(nick string) error {
	return dmc.api.SetNickname(nick)
}

// BlockPartner prevents receiving messages and notifications from the partner.
//
// Parameters:
//   - partnerPubKey - The partner's Ed25519 public key to block.
func (dmc *DMClient) BlockPartner(partnerPubKey []byte) {
	dmc.api.BlockPartner(partnerPubKey)
}

// UnblockPartner unblocks a blocked partner to allow DM messages.
//
// Parameters:
//   - partnerPubKey - The partner's Ed25519 public key to unblock.
func (dmc *DMClient) UnblockPartner(partnerPubKey []byte) {
	dmc.api.UnblockPartner(partnerPubKey)
}

// IsBlocked indicates if the given partner is blocked.
//
// Parameters:
//   - partnerPubKey - The partner's Ed25519 public key to check.
func (dmc *DMClient) IsBlocked(partnerPubKey []byte) bool {
	return dmc.api.IsBlocked(partnerPubKey)
}

// GetBlockedPartners returns all partners who are blocked by this user.
//
// Returns:
//   - []byte - JSON of of an array of [ed25519.PublicKey].
//
// Example return:
//
//	[
//	  "TYWuCfyGBjNWDtl/Roa6f/o206yYPpuB6sX2kJZTe98=",
//	  "4JLRzgtW1SZ9c5pE+v0WwrGPj1t19AuU6Gg5IND5ymA=",
//	  "CWDqF1bnhulW2pko+zgmbDZNaKkmNtFdUgY4bTm2DhA="
//	]
func (dmc *DMClient) GetBlockedPartners() []byte {
	blockedJSON, err := json.Marshal(dmc.api.GetBlockedPartners())
	if err != nil {
		jww.FATAL.Panicf(
			"[DM] Failed to JSON marshal blocked sender list: %+v", err)
	}
	return blockedJSON
}

// GetNotificationLevel returns the notification level for the given channel.
//
// Parameters:
//   - partnerPubKey - The partner's Ed25519 public key.
//
// Returns:
//   - int - The [dm.NotificationLevel] to set for the DM conversation.
func (dmc *DMClient) GetNotificationLevel(partnerPubKey []byte) (int, error) {
	level, err := dmc.api.GetNotificationLevel(partnerPubKey)
	return int(level), err
}

// SetMobileNotificationsLevel sets the notification level for the given DM
// conversation partner.
//
// Parameters:
//   - partnerPubKey - The partner's Ed25519 public key.
//   - level - The [dm.NotificationLevel] to set for the DM conversation.
func (dmc *DMClient) SetMobileNotificationsLevel(
	partnerPubKey []byte, level int) error {
	return dmc.api.SetMobileNotificationsLevel(
		partnerPubKey, dm.NotificationLevel(level))
}

// GetDmNotificationReportsForMe checks the notification data against the filter
// list to determine which notifications belong to the user. A list of
// notification reports is returned detailing all notifications for the user.
//
// Parameters:
//   - notificationFilterJSON - JSON of [dm.NotificationFilter].
//   - notificationDataCSV - CSV containing notification data.
//
// Example JSON of a slice of [dm.NotificationFilter]:
//
//	{
//	  "identifier": "MWL6mvtZ9UUm7jP3ainyI4erbRl+wyVaO5MOWboP0rA=",
//	  "myID": "AqDqg6Tcs359dBNRBCX7XHaotRDhz1ZRQNXIsGaubvID",
//	  "tags": [
//	    "61334HtH85DPIifvrM+JzRmLqfV5R4AMEmcPelTmFX0=",
//	    "zc/EPwtx5OKTVdwLcI15bghjJ7suNhu59PcarXE+m9o=",
//	    "FvArzVJ/082UEpMDCWJsopCLeLnxJV6NXINNkJTk3k8="
//	  ],
//	  "PublicKeys": {
//	    "61334HtH85DPIifvrM+JzRmLqfV5R4AMEmcPelTmFX0=": "b3HygDv8gjteune9wgBm3YtVuAo2foOusRmj0m5nl6E=",
//	    "FvArzVJ/082UEpMDCWJsopCLeLnxJV6NXINNkJTk3k8=": "uOLitBZcCh2TEW406jXHJ+Rsi6LybsH8R1u4Mxv/7hA=",
//	    "zc/EPwtx5OKTVdwLcI15bghjJ7suNhu59PcarXE+m9o=": "lqLD1EzZBxB8PbILUJIfFq4JI0RKThpUQuNlTNgZAWk="
//	  },
//	  "allowedTypes": {"1": {}, "2": {}}
//	}
//
// Returns:
//   - []byte - JSON of a slice of [dm.NotificationReport].
//
// Example return:
//
//	[
//	  {"partner": "WUSO3trAYeBf4UeJ5TEL+Q4usoyFf0shda0YUmZ3z8k=", "type": 1},
//	  {"partner": "5MY652JsVv5YLE6wGRHIFZBMvLklACnT5UtHxmEOJ4o=", "type": 2}
//	]
func GetDmNotificationReportsForMe(notificationFilterJSON []byte,
	notificationDataCSV string) ([]byte, error) {
	var nf dm.NotificationFilter
	if err := json.Unmarshal(notificationFilterJSON, &nf); err != nil || nf.MyID == nil {
		// Attempt to unmarshal as the entire NotificationUpdateJSON
		var nuj DmNotificationUpdateJSON
		if err2 := json.Unmarshal(notificationFilterJSON, &nuj); err2 != nil {
			return nil, errors.Errorf(
				"failed to JSON unmarshal %T:\n%v\n%v", nf, err, err2)
		}
		nf = nuj.NotificationFilter
	}

	notifData, err := notifications.DecodeNotificationsCSV(notificationDataCSV)
	if err != nil {
		return nil, err
	}

	nrs := dm.GetNotificationReportsForMe(nf, notifData)

	return json.Marshal(nrs)
}

// SendText is used to send a formatted direct message to a user.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - message - The contents of the message. The message should be at most 510
//     bytes. This is expected to be Unicode, and thus a string data type is
//     expected
//   - leaseTimeMS - The lease of the message. This will be how long the message
//     is valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here.
//   - cmixParamsJSON - JSON of [xxdk.CMIXParams]. If left empty, then
//     [GetDefaultCMixParams] will be used internally.
//
// Returns:
//   - []byte - SON of [ChannelSendReport].
func (dmc *DMClient) SendText(partnerPubKeyBytes []byte, partnerToken int32,
	message string, leaseTimeMS int64, cmixParamsJSON []byte) ([]byte, error) {
	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}
	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	// Send message
	msgID, rnd, ephID, err := dmc.api.SendText(partnerPubKey, uint32(partnerToken),
		message, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// SendReply is used to send a formatted direct message reply.
//
// If the message ID that the reply is sent to does not exist, then the other
// side will post the message as a normal message and not as a reply.
//
// The message will auto delete leaseTime after the round it is sent in, lasting
// forever if [ValidForever] is used.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - replyMessage - The contents of the reply message. The message should be
//     at most 510 bytes. This is expected to be Unicode, and thus a string data
//     type is expected
//   - replyToBytes - The bytes of the [message.ID] of the message you wish to
//     reply to. This may be found in the [ChannelSendReport] if replying to
//     your own. Alternatively, if reacting to another user's message, you may
//     retrieve it via the [ChannelMessageReceptionCallback] registered using
//     [ChannelsManager.RegisterReceiveHandler].
//   - leaseTimeMS - The lease of the message. This will be how long the message
//     is valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here.
//   - cmixParamsJSON - JSON of [xxdk.CMIXParams]. If left empty, then
//     [GetDefaultCMixParams] will be used internally.
//
// Returns:
//   - []byte - A JSON marshalled ChannelSendReport
func (dmc *DMClient) SendReply(partnerPubKeyBytes []byte, partnerToken int32,
	replyMessage string, replyToBytes []byte, leaseTimeMS int64,
	cmixParamsJSON []byte) ([]byte, error) {

	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}
	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	// Unmarshal message ID
	replyTo, err := message.UnmarshalID(replyToBytes)
	if err != nil {
		return nil, err
	}

	// Send Reply
	msgID, rnd, ephID, err := dmc.api.SendReply(partnerPubKey,
		uint32(partnerToken), replyMessage, replyTo, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// SendReaction is used to send a reaction to a direct message.
// The reaction must be a single emoji with no other characters,
// and will be rejected otherwise.
//
// Clients will drop the reaction if they do not recognize the reactTo message.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - reaction - The user's reaction. This should be a single emoji with no
//     other characters. As such, a Unicode string is expected.
//   - reactToBytes - The bytes of the [message.ID] of the message you wish to
//     react to. This may be found in the [ChannelSendReport] if replying to
//     your own. Alternatively, if reacting to another user's message, you may
//     retrieve it via the [ChannelMessageReceptionCallback] registered using
//     [ChannelsManager.RegisterReceiveHandler].
//   - cmixParamsJSON - JSON of [xxdk.CMIXParams]. If left empty, then
//     [GetDefaultCMixParams] will be used internally.
//
// Returns:
//   - []byte - A JSON marshalled ChannelSendReport.
func (dmc *DMClient) SendReaction(partnerPubKeyBytes []byte, partnerToken int32,
	reaction string, reactToBytes []byte,
	cmixParamsJSON []byte) ([]byte, error) {

	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}
	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	// Unmarshal message ID
	reactTo, err := message.UnmarshalID(reactToBytes)
	if err != nil {
		return nil, err
	}

	// Send reaction
	msgID, rnd, ephID, err := dmc.api.SendReaction(partnerPubKey,
		uint32(partnerToken), reaction, reactTo, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// SendSilent is used to send to a channel a message with no notifications.
// Its primary purpose is to communicate new nicknames without calling [Send].
//
// It takes no payload intentionally as the message should be very lightweight.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - cmixParamsJSON - A JSON marshalled [xxdk.CMIXParams]. This may be empty,
//     and GetDefaultCMixParams will be used internally.
func (dmc *DMClient) SendSilent(partnerPubKeyBytes []byte,
	partnerToken int32, cmixParamsJSON []byte) ([]byte, error) {
	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}

	msgID, rnd, ephID, err := dmc.api.SendSilent(partnerPubKey, uint32(partnerToken),
		params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// SendInvite is used to send to a DM partner an invitation to another
// channel.
//
// The reception of an invitation will be handled by [DMReceiver.Receive],
// passing in a [dm.MessageType] of value [dm.InvitationType]. The message
// will be JSON encoded. Example invite JSON:
//
//	{
//	   "text": "Check this channel out!",
//	   "inviteLink": "https://internet.speakeasy.tech/?0Name=name&1Description=description&2Level=Public&3Created=1687359213751145652&e=gnnLqhgsNJE7uFTLRsv1q%2FzgHBesVsezln4mg4mQZ70%3D&k=aOULKJDhSkNOou7CwsybaNTrdfrUS55%2Ffv%2FuHjX2Mc4%3D&l=928&m=0&p=1&s=cN2iHg6b5FdViS4q46QMolQUF0BZt98NEiO6NKrL1d0%3D&v=1",
//	   "password": "secret"
//	}
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - inviteToChannelJson - A JSON marshalled channel. This should be the data
//     of the invitee channel. This can be retrieved from [GetChannelJSON].
//   - message - The contents of the message. The message should be at most 510
//     bytes. This is expected to be Unicode, and thus a string data type is
//     expected.
//   - host - The URL to append the channel info to.
//   - cmixParamsJSON - A JSON marshalled [xxdk.CMIXParams]. This may be empty,
//     and GetDefaultCMixParams will be used internally.
func (dmc *DMClient) SendInvite(partnerPubKeyBytes []byte,
	partnerToken int32, inviteToChannelJson []byte, message string,
	host string, cmixParamsJSON []byte) ([]byte, error) {

	// Retrieve channel that will be used for the invitation
	var inviteToChan *cryptoBroadcast.Channel
	err := json.Unmarshal(inviteToChannelJson, &inviteToChan)
	if err != nil {
		return nil,
			errors.WithMessage(err, "could not unmarshal channel json")
	}

	// Unmarshal cmix params
	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}

	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	// Send invite
	msgID, rnd, ephID, err := dmc.api.SendInvite(partnerPubKey,
		uint32(partnerToken), message, inviteToChan, host, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// DeleteMessage sends a message to the partner to delete a message this user
// sent. Also deletes it from the local database.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - targetMessageIdBytes - The bytes of the [message.ID] of the message to
//     delete. This may be found in the [ChannelSendReport].
//   - cmixParamsJSON - A JSON marshalled [xxdk.CMIXParams]. This may be empty,
//     and GetDefaultCMixParams will be used internally.
func (dmc *DMClient) DeleteMessage(partnerPubKeyBytes []byte, partnerToken int32,
	targetMessageIdBytes []byte, cmixParamsJSON []byte) ([]byte, error) {

	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)

	// Unmarshal message ID
	targetMessage, err := message.UnmarshalID(targetMessageIdBytes)
	if err != nil {
		return nil, err
	}

	// Unmarshal cmix params
	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}

	// Send invite
	msgID, rnd, ephID, err := dmc.api.DeleteMessage(
		partnerPubKey, uint32(partnerToken), targetMessage, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// Send is used to send a raw message. In general, it
// should be wrapped in a function that defines the wire protocol.
//
// If the final message, before being sent over the wire, is too long, this will
// return an error. Due to the underlying encoding using compression, it is not
// possible to define the largest payload that can be sent, but it will always
// be possible to send a payload of 802 bytes at minimum.
//
// The meaning of leaseTimeMS depends on the use case.
//
// Parameters:
//   - partnerPubKeyBytes - The bytes of the public key of the partner's ED25519
//     signing key.
//   - partnerToken - The token used to derive the reception ID for the partner.
//   - messageType - The message type of the message. This will be a valid
//     [dm.MessageType].
//   - plaintext - The contents of the message. This need not be of data type
//     string, as the message could be a specified format that the channel may
//     recognize.
//   - leaseTimeMS - The lease of the message. This will be how long the message
//     is valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here.
//   - cmixParamsJSON - JSON of [xxdk.CMIXParams]. If left empty, then
//     [GetDefaultCMixParams] will be used internally.
//
// Returns:
//   - []byte - A JSON marshalled ChannelSendReport.
func (dmc *DMClient) Send(partnerPubKeyBytes []byte,
	partnerToken int32, messageType int, plaintext []byte, leaseTimeMS int64,
	cmixParamsJSON []byte) ([]byte, error) {

	params, err := parseCMixParams(cmixParamsJSON)
	if err != nil {
		return nil, err
	}
	partnerPubKey := ed25519.PublicKey(partnerPubKeyBytes)
	msgTy := dm.MessageType(messageType)

	// Send message
	msgID, rnd, ephID, err := dmc.api.Send(partnerPubKey,
		uint32(partnerToken), msgTy, plaintext, params.CMIX)
	if err != nil {
		return nil, err
	}

	// Construct send report
	return constructDMSendReport(msgID, rnd.ID, ephID)
}

// constructChannelSendReport is a helper function which returns a JSON
// marshalled ChannelSendReport.
func constructDMSendReport(dmMsgID message.ID,
	roundId id.Round, ephId ephemeral.Id) ([]byte, error) {
	// Construct send report
	sendReport := ChannelSendReport{
		MessageID:  dmMsgID.Bytes(),
		RoundsList: makeRoundsList(roundId),
		EphId:      ephId.Int64(),
	}

	// Marshal send report
	return json.Marshal(sendReport)
}

func GetDMInstance(instanceID int) (*DMClient, error) {
	instance, ok := dmClients.tracked[instanceID]
	if !ok {
		return nil, errors.Errorf("no dm instance id: %d", instanceID)
	}
	return instance, nil
}

// Simple mux'd map list of clients.
var dmClients = &dmClientTracker{
	tracked: make(map[int]*DMClient),
	count:   0,
}

type dmClientTracker struct {
	tracked map[int]*DMClient
	count   int
	sync.RWMutex
}

func (dct *dmClientTracker) add(c dm.Client) *DMClient {
	dct.Lock()
	defer dct.Unlock()

	dmID := dct.count
	dct.count++

	dct.tracked[dmID] = &DMClient{
		api: c,
		id:  dmID,
	}

	return dct.tracked[dmID]
}
func (dct *dmClientTracker) get(id int) (*DMClient, error) {
	dct.RLock()
	defer dct.RUnlock()

	c, exist := dct.tracked[id]
	if !exist {
		return nil, errors.Errorf("DMClient ID %d does not exist",
			id)
	}

	return c, nil
}
func (dct *dmClientTracker) delete(id int) {
	dct.Lock()
	defer dct.Unlock()

	delete(dct.tracked, id)
	dct.count--
}

////////////////////////////////////////////////////////////////////////////////
// UI Callbacks                                                               //
////////////////////////////////////////////////////////////////////////////////

type DmCallbacks interface {
	EventUpdate(eventType int64, jsonData []byte)
}

// DM event types
const (
	// DmNotificationUpdate indicates the data is [DmNotificationUpdateJSON].
	DmNotificationUpdate = 1000

	// DmBlockedUser indicates the data is [DmBlockedUserJSON].
	DmBlockedUser = 2000

	// DmMessageReceived indicates the data is [DmMessageReceivedJSON].
	DmMessageReceived int64 = 3000

	// DmMessageDeleted indicates the data is [DmMessageDeletedJSON].
	DmMessageDeleted int64 = 4000
)

type dmCallbacks struct {
	eventUpdate func(eventType int64, jsonMarshallable any)
}

func wrapDmCallbacks(dmc DmCallbacks) *dmCallbacks {
	if dmc == nil {
		return nil
	}
	return &dmCallbacks{func(eventType int64, jsonMarshallable any) {
		jsonData, err := json.Marshal(jsonMarshallable)
		if err != nil {
			jww.FATAL.Panicf(
				"[CH] Failed to JSON marshal %T: %+v", jsonMarshallable, err)
		}
		dmc.EventUpdate(eventType, jsonData)
	}}
}

func (dmCBS *dmCallbacks) NotificationUpdate(nf dm.NotificationFilter,
	changed []dm.NotificationState, deleted []ed25519.PublicKey) {
	dmCBS.eventUpdate(DmNotificationUpdate, DmNotificationUpdateJSON{
		NotificationFilter: nf,
		Changed:            changed,
		Deleted:            deleted,
	})
}

func (dmCBS *dmCallbacks) BlockedUser(user ed25519.PublicKey, blocked bool) {
	dmCBS.eventUpdate(DmBlockedUser, DmBlockedUserJSON{
		User:    user,
		Blocked: blocked,
	})
}

func (dmCBS *dmCallbacks) MessageReceived(uuid uint64, pubKey ed25519.PublicKey,
	messageUpdate, conversationUpdate bool) {
	dmCBS.eventUpdate(DmMessageReceived, DmMessageReceivedJSON{
		UUID:               uuid,
		PubKey:             pubKey,
		MessageUpdate:      messageUpdate,
		ConversationUpdate: conversationUpdate,
	})
}

func (dmCBS *dmCallbacks) MessageDeleted(messageID message.ID) {
	dmCBS.eventUpdate(DmMessageDeleted, DmMessageDeletedJSON{
		MessageID: messageID,
	})
}

// DmNotificationUpdateJSON contains updates describing DM notifications.
//
// Fields:
//   - nfJSON - The [dm.NotificationFilter], which is passed into
//     [GetDmNotificationReportsForMe] to filter DM notifications for the user.
//   - changedStateListJSON - A slice of [dm.NotificationState] that includes
//     all added or changed notification states for DM conversations.
//   - deletedListJSON - A slice of [ed25519.PublicKey] that includes
//     conversation that were deleted.
//
// Example JSON:
//  {
//    "notificationFilter": {
//      "identifier": "MWL6mvtZ9UUm7jP3ainyI4erbRl+wyVaO5MOWboP0rA=",
//      "myID": "aXCGa8Exf8ah0jKgQ5RpsJxRSCclgLnCVfHN/iKmyD4D",
//      "tags": [
//        "V/6lH5Ovo2EnQVJLX/g6wFmYReNlMFnprLAAlhZ8S5g=",
//        "+sSL0it/lwW7mTMTqJek1rvM1X04tm3Vu8lN6ISBG0k="
//      ],
//      "publicKeys": {
//        "+sSL0it/lwW7mTMTqJek1rvM1X04tm3Vu8lN6ISBG0k=": "WujWUQ/IRIZIRVDocUCU+jefl4SL55VCFjfh9enXh8A=",
//        "V/6lH5Ovo2EnQVJLX/g6wFmYReNlMFnprLAAlhZ8S5g=": "nUXMBXLZIF1zhFulPpufEndQQnFwK9nIoMmdVqT0qDQ="
//      },
//      "allowedTypes": {
//        "1": {},
//        "2": {}
//      }
//    },
//    "changed": [
//      {
//        "pubKey": "nUXMBXLZIF1zhFulPpufEndQQnFwK9nIoMmdVqT0qDQ=",
//        "level": 40
//      },
//      {
//        "pubKey": "2IOMwtynDdZNLrfwuC+yjJR/AlsqtXSVi2m6Z8xDvsk=",
//        "level": 10
//      }
//    ],
//    "deleted": [
//      "0gire0TcHxTCX/o/T7cl1UMhH/Wo+m6KyxY63VOafIo="
//    ]
//  }
type DmNotificationUpdateJSON struct {
	NotificationFilter dm.NotificationFilter  `json:"notificationFilter"`
	Changed            []dm.NotificationState `json:"changed"`
	Deleted            []ed25519.PublicKey    `json:"deleted"`
}

// DmBlockedUserJSON contains a user's public key and if they are blocked or
// unblocked.
//
// Fields:
//   - User - The DM partner's [ed25519.PublicKey].
//   - Blocked - True if the user is blocked and false if they are unblocked.
//
// Example JSON:
//  {
//    "user": "pB87FR7Ci0EDVUEg+aTHl+CJFmzW9qCQEynURJgRBtM=",
//    "blocked": true
//  }
type DmBlockedUserJSON struct {
	User    ed25519.PublicKey `json:"user"`
	Blocked bool              `json:"blocked"`
}

// DmMessageReceivedJSON is returned any time a DM message is received or
// updated.
//
// Fields:
//   - UUID - The UUID of the message in the database.
//   - PubKey - The public key of the sender.
//   - MessageUpdate - Is true if the message already exists and was edited.
//   - ConversationUpdate - Is true if the conversation was created or modified.
//
// Example JSON:
//  {
//    "uuid": 3458558585156768347,
//    "pubKey": "Ky0C1gc/j6ingV0+2v39Oc8ukBOf+Gp9HNiBwM7aIdQ=",
//    "messageUpdate": true,
//    "conversationUpdate": true
//  }
type DmMessageReceivedJSON struct {
	UUID               uint64            `json:"uuid"`
	PubKey             ed25519.PublicKey `json:"pubKey"`
	MessageUpdate      bool              `json:"messageUpdate"`
	ConversationUpdate bool              `json:"conversationUpdate"`
}

// DmMessageDeletedJSON is returned any time a DM message.
//
// Fields:
//   - MessageID - The [message.ID] of the deleted message in the database.
//
// Example JSON:
//  {
//    "messageID": "yGO7PZsOpEs+A1DgEIAyTXxpOwBEtMpShqV7h5EtJYw="
//  }
type DmMessageDeletedJSON struct {
	MessageID message.ID `json:"messageID"`
}
