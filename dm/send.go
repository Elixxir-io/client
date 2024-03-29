////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/v4/cmix"
	"gitlab.com/elixxir/client/v4/cmix/message"
	"gitlab.com/elixxir/client/v4/cmix/rounds"
	"gitlab.com/elixxir/client/v4/emoji"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	"gitlab.com/elixxir/crypto/dm"
	"gitlab.com/elixxir/crypto/fastRNG"
	cryptoMessage "gitlab.com/elixxir/crypto/message"
	"gitlab.com/elixxir/crypto/nike"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/netTime"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

const (
	// Versions for various message types
	textVersion       = 0
	reactionVersion   = 0
	invitationVersion = 0
	silentVersion     = 0
	deleteVersion     = 0

	// SendMessageTag is the base tag used when generating a debug tag for
	// sending a message.
	SendMessageTag = "Message"

	// SendReplyTag is the base tag used when generating a debug tag for
	// sending a reply.
	SendReplyTag = "Reply"

	// SendReactionTag is the base tag used when generating a debug tag for
	// sending a reaction.
	SendReactionTag = "Reaction"

	// SendSilentTag is the base tag used when generating a debug tag for
	// sending a silent message.
	SendSilentTag = "Silent"

	// SendInviteTag is the base tag used when generating a debug tag for
	// sending an invitation.
	SendInviteTag = "Invite"

	// DeleteMessageTag is the base tag used when generating a debug tag for
	// delete message.
	DeleteMessageTag = "Delete"

	directMessageDebugTag = "dm"
	// The size of the nonce used in the message ID.
	messageNonceSize = 4
)

var (
	emptyPubKeyBytes = make([]byte, ed25519.PublicKeySize)
	emptyPubKey      = ed25519.PublicKey(emptyPubKeyBytes)
)

// SendText is used to send a formatted message to another user.
func (dc *dmClient) SendText(partnerPubKey ed25519.PublicKey,
	partnerToken uint32,
	msg string, params cmix.CMIXParams) (
	cryptoMessage.ID, rounds.Round, ephemeral.Id, error) {

	pubKeyStr := base64.RawStdEncoding.EncodeToString(partnerPubKey)

	tag := makeDebugTag(partnerPubKey, []byte(msg), SendReplyTag)
	jww.INFO.Printf("[DM][%s] SendText(%s)", tag, pubKeyStr)
	txt := &Text{
		Version: textVersion,
		Text:    msg,
	}

	params = params.SetDebugTag(tag)

	txtMarshaled, err := proto.Marshal(txt)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{}, err
	}

	return dc.Send(partnerPubKey, partnerToken, TextType, txtMarshaled,
		params)
}

// SendReply is used to send a formatted direct message reply.
//
// If the message ID that the reply is sent to does not exist,
// then the other side will post the message as a normal
// message and not as a reply.
func (dc *dmClient) SendReply(partnerPubKey ed25519.PublicKey,
	partnerToken uint32, msg string, replyTo cryptoMessage.ID,
	params cmix.CMIXParams) (cryptoMessage.ID, rounds.Round,
	ephemeral.Id, error) {

	pubKeyStr := base64.RawStdEncoding.EncodeToString(partnerPubKey)

	tag := makeDebugTag(partnerPubKey, []byte(msg), SendReplyTag)
	jww.INFO.Printf("[DM][%s] SendReply(%s, to %s)", tag, pubKeyStr,
		replyTo)
	txt := &Text{
		Version:        textVersion,
		Text:           msg,
		ReplyMessageID: replyTo[:],
	}

	params = params.SetDebugTag(tag)

	txtMarshaled, err := proto.Marshal(txt)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{}, err
	}

	return dc.Send(partnerPubKey, partnerToken, ReplyType, txtMarshaled,
		params)
}

// SendReaction is used to send a reaction to a direct
// message. The reaction must be a single emoji with no other
// characters, and will be rejected otherwise.
//
// Clients will drop the reaction if they do not recognize the reactTo
// message.
func (dc *dmClient) SendReaction(partnerPubKey ed25519.PublicKey,
	partnerToken uint32, reaction string, reactTo cryptoMessage.ID,
	params cmix.CMIXParams) (cryptoMessage.ID,
	rounds.Round, ephemeral.Id, error) {
	tag := makeDebugTag(partnerPubKey, []byte(reaction),
		SendReactionTag)
	jww.INFO.Printf("[DM][%s] SendReaction(%s, to %s)", tag,
		base64.RawStdEncoding.EncodeToString(partnerPubKey),
		reactTo)

	if err := emoji.ValidateReaction(reaction); err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, err
	}

	react := &Reaction{
		Version:           reactionVersion,
		Reaction:          reaction,
		ReactionMessageID: reactTo[:],
	}

	params = params.SetDebugTag(tag)

	reactMarshaled, err := proto.Marshal(react)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, err
	}

	return dc.Send(partnerPubKey, partnerToken, ReactionType,
		reactMarshaled, params)
}

// SendSilent is used to send to a channel a message with no notifications.
// Its primary purpose is to communicate new nicknames without calling
// SendMessage.
//
// It takes no payload intentionally as the message should be very
// lightweight.
func (dc *dmClient) SendSilent(partnerPubKey ed25519.PublicKey,
	partnerToken uint32, params cmix.CMIXParams) (
	cryptoMessage.ID, rounds.Round, ephemeral.Id, error) {
	// Formulate custom tag
	tag := makeDebugTag(partnerPubKey, nil, SendSilentTag)

	// Modify the params for the custom tag
	params = params.SetDebugTag(tag)

	jww.INFO.Printf("[DM][%s] SendSilent(%s)", tag,
		base64.RawStdEncoding.EncodeToString(partnerPubKey))

	// Form message
	silent := &SilentMessage{
		Version: silentVersion,
	}

	// Marshal message
	silentMarshaled, err := proto.Marshal(silent)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, err
	}

	// Send silent message
	return dc.Send(partnerPubKey, partnerToken, SilentType,
		silentMarshaled, params)
}

// SendInvite is used to send to a DM partner an invitation to another
// channel.
func (dc *dmClient) SendInvite(partnerPubKey ed25519.PublicKey,
	partnerToken uint32, msg string, inviteTo *cryptoBroadcast.Channel,
	host string, params cmix.CMIXParams) (
	cryptoMessage.ID, rounds.Round, ephemeral.Id, error) {
	// fixme: As of writing, maxUses is not a functional parameter. It
	//  is passed down to the lower levels, but requires server side changes to
	//  enforce, which have not been implemented. Until that is done,
	//  maxUses will be hard-coded here. Once it is done, this function
	//  signature and all corresponding interface(s) should be modified
	//  such that maxUses is a parameter w/ proper documentation.
	const maxUses = 0

	// Formulate custom tag
	tag := makeDebugTag(
		partnerPubKey, []byte(msg),
		SendInviteTag)

	// Modify the params for the custom tag
	params = params.SetDebugTag(tag)

	jww.INFO.Printf("[DM][%s] SendInvite(%s, for %s)", tag,
		base64.RawStdEncoding.EncodeToString(partnerPubKey),
		inviteTo.ReceptionID)

	rng := dc.rng.GetStream()
	defer rng.Close()
	inviteUrl, passsord, err := inviteTo.ShareURL(host, maxUses, rng)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{},
			errors.WithMessage(err, "could not form URL")
	}

	invitation := &ChannelInvitation{
		Version:    invitationVersion,
		Text:       msg,
		InviteLink: inviteUrl,
		Password:   passsord,
	}

	invitationMarshaled, err := proto.Marshal(invitation)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, err
	}

	return dc.Send(partnerPubKey, partnerToken, InvitationType,
		invitationMarshaled, params)
}

// DeleteMessage sends a message to the partner to delete a message this user
// sent. Also deletes it from the local database.
func (dc *dmClient) DeleteMessage(partnerPubKey ed25519.PublicKey,
	partnerToken uint32, targetMessage cryptoMessage.ID,
	params cmix.CMIXParams) (cryptoMessage.ID, rounds.Round, ephemeral.Id, error) {
	// Delete the message
	if !dc.receiver.DeleteMessage(targetMessage, dc.pubKey) {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, errors.Errorf(
			"no message with id %s and public key %X", targetMessage, dc.pubKey)
	}

	tag := makeDebugTag(partnerPubKey, targetMessage.Marshal(), DeleteMessageTag)
	jww.INFO.Printf("[DM][%s] DeleteMessage(%s)", tag, targetMessage)

	txt := &DeleteMessage{
		Version:         deleteVersion,
		TargetMessageID: targetMessage.Marshal(),
	}

	params = params.SetDebugTag(tag)
	deleteMarshaled, err := proto.Marshal(txt)
	if err != nil {
		return cryptoMessage.ID{}, rounds.Round{}, ephemeral.Id{}, err
	}

	return dc.Send(
		partnerPubKey, partnerToken, DeleteType, deleteMarshaled, params)
}

// Send is used to send a raw direct message to a DM partner. In general, it
// should be wrapped in a function that defines the wire protocol.
//
// If the final message, before being sent over the wire, is too long, this will
// return an error. Due to the underlying encoding using compression, it is not
// possible to define the largest payload that can be sent, but it will always
// be possible to send a payload of 802 bytes at minimum.
// DeleteMessage is used to send a formatted message to another user.
func (dc *dmClient) Send(partnerEdwardsPubKey ed25519.PublicKey,
	partnerToken uint32, messageType MessageType, msg []byte,
	params cmix.CMIXParams) (
	cryptoMessage.ID, rounds.Round, ephemeral.Id, error) {

	if partnerToken == 0 {
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{},
			errors.Errorf("invalid dmToken value: %d", partnerToken)

	}

	if partnerEdwardsPubKey == nil ||
		partnerEdwardsPubKey.Equal(emptyPubKey) {
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{},
			errors.Errorf("invalid public key value: %v",
				partnerEdwardsPubKey)
	}

	if dc.myToken == partnerToken &&
		!dc.me.PubKey.Equal(partnerEdwardsPubKey) {
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{},
			errors.Errorf("can only use myToken on self send: "+
				"myToken: %d, myKey: %v, partnerKey: %v, partnerToken: %d",
				dc.myToken, dc.me.PubKey, partnerEdwardsPubKey, partnerToken)
	}

	partnerPubKey := ecdh.Edwards2EcdhNikePublicKey(partnerEdwardsPubKey)

	partnerID := deriveReceptionID(partnerPubKey.Bytes(), partnerToken)

	sihTag := dm.MakeSenderSihTag(partnerEdwardsPubKey, dc.me.Privkey)
	mt := messageType.Marshal()
	service := message.CompressedService{
		Identifier: partnerEdwardsPubKey,
		Tags:       []string{sihTag},
		Metadata:   mt[:],
	}

	// Note: We log sends on exit, and append what happened to the message
	// this cuts down on clutter in the log.
	sendPrint := fmt.Sprintf("[DM][%s] Sending from %s to %s type %s at %s",
		params.DebugTag, base64.StdEncoding.EncodeToString(dc.me.PubKey),
		partnerID, messageType,
		netTime.Now())
	defer func() { jww.INFO.Println(sendPrint) }()

	rng := dc.rng.GetStream()
	defer rng.Close()

	nickname, _ := dc.nm.GetNickname()

	// Generate random nonce to be used for message ID
	// generation. This makes it so two identical messages sent on
	// the same round have different message IDs.
	msgNonce := make([]byte, messageNonceSize)
	n, err := rng.Read(msgNonce)
	if err != nil {
		sendPrint += fmt.Sprintf(", failed to generate nonce: %+v", err)
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{},
			errors.Errorf("Failed to generate nonce: %+v", err)
	} else if n != messageNonceSize {
		sendPrint += fmt.Sprintf(
			", got %d bytes for %d-byte nonce", n, messageNonceSize)
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{},
			errors.Errorf(
				"Generated %d bytes for %d-byte nonce", n,
				messageNonceSize)
	}

	directMessage := &DirectMessage{
		DMToken:        dc.myToken,
		PayloadType:    uint32(messageType),
		Payload:        msg,
		Nickname:       nickname,
		Nonce:          msgNonce,
		LocalTimestamp: netTime.Now().UnixNano(),
	}

	if params.DebugTag == cmix.DefaultDebugTag {
		params.DebugTag = directMessageDebugTag
	}

	sendPrint += fmt.Sprintf(", pending send %s", netTime.Now())
	uuid, err := dc.st.DenotePendingSend(partnerEdwardsPubKey,
		dc.me.PubKey, partnerToken, messageType, directMessage)
	if err != nil {
		sendPrint += fmt.Sprintf(", pending send failed %s",
			err.Error())
		errDenote := dc.st.FailedSend(uuid)
		if errDenote != nil {
			sendPrint += fmt.Sprintf(
				", failed to denote failed dm send: %s",
				errDenote.Error())
		}
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{}, err
	}

	rndID, ephIDs, err := send(dc.net, dc.selfReceptionID,
		partnerID, partnerPubKey, dc.privateKey, service,
		partnerToken, directMessage, params, dc.rng)
	if err != nil {
		sendPrint += fmt.Sprintf(", err on send: %+v", err)
		errDenote := dc.st.FailedSend(uuid)
		if errDenote != nil {
			sendPrint += fmt.Sprintf(
				", failed to denote failed dm send: %s",
				errDenote.Error())
		}
		return cryptoMessage.ID{}, rounds.Round{},
			ephemeral.Id{}, err
	}

	// Now that we have a round ID, derive the msgID
	// FIXME: cryptoMesage.DeriveDirectMessageID should take a round ID,
	// and the callee shouldn't have been modifying the data we sent.
	directMessage.RoundID = uint64(rndID.ID)
	jww.INFO.Printf("[DM] DeriveDirectMessage(%s...) Send", partnerID)
	msgID := cryptoMessage.DeriveDirectMessageID(partnerID,
		directMessage)

	sendPrint += fmt.Sprintf(", send eph %v rnd %s MsgID %s",
		ephIDs, rndID.ID, msgID)

	err = dc.st.Sent(uuid, msgID, rndID)
	if err != nil {
		sendPrint += fmt.Sprintf(", dm send denote failed: %s ",
			err.Error())
	}
	return msgID, rndID, ephIDs[1], err

}

// DeriveReceptionID returns a reception ID for direct messages sent
// to the user. It generates this ID by hashing the public key and
// an arbitrary idToken together. The ID type is set to "User".
func DeriveReceptionID(publicKey ed25519.PublicKey, idToken uint32) *id.ID {
	nikePubKey := ecdh.Edwards2EcdhNikePublicKey(publicKey)
	return deriveReceptionID(nikePubKey.Bytes(), idToken)
}

func deriveReceptionID(keyBytes []byte, idToken uint32) *id.ID {
	h, err := blake2b.New256(nil)
	if err != nil {
		jww.FATAL.Panicf("%+v", err)
	}
	h.Write(keyBytes)
	tokenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tokenBytes, idToken)
	h.Write(tokenBytes)
	idBytes := h.Sum(nil)
	idBytes = append(idBytes, byte(id.User))
	receptionID, err := id.Unmarshal(idBytes)
	if err != nil {
		jww.FATAL.Panicf("%+v", err)
	}
	return receptionID
}

func send(net cMixClient, myID *id.ID, partnerID *id.ID,
	partnerPubKey nike.PublicKey, myPrivateKey nike.PrivateKey,
	service cmix.Service, partnerToken uint32,
	msg *DirectMessage, params cmix.CMIXParams,
	rngGenerator *fastRNG.StreamGenerator) (rounds.Round,
	[]ephemeral.Id, error) {

	// Send to Partner
	assemble := func(rid id.Round) ([]cmix.TargetedCmixMessage, error) {
		rng := rngGenerator.GetStream()
		defer rng.Close()

		// Copy msg to dmMsg, which leaves the original
		// message data alone for resend purposes.
		// (deep copy isn't necessary because we only
		// change the rid)
		dmMsg := *msg

		// SEND
		dmMsg.RoundID = uint64(rid)

		// Serialize the message
		dmSerial, err := proto.Marshal(&dmMsg)
		if err != nil {
			return nil, err
		}

		payloadLen := calcDMPayloadLen(net)

		ciphertext := dm.Cipher.Encrypt(dmSerial, myPrivateKey,
			partnerPubKey, rng, payloadLen)

		fpBytes, encryptedPayload, mac, err := createCMIXFields(
			ciphertext, payloadLen, rng)
		if err != nil {
			return nil, err
		}

		fp := format.NewFingerprint(fpBytes)

		sendMsg := cmix.TargetedCmixMessage{
			Recipient:   partnerID,
			Payload:     encryptedPayload,
			Fingerprint: fp,
			Service:     service,
			Mac:         mac,
		}

		// SELF SEND
		// Copy msg to selfMsg, which leaves the original
		// message data alone for resend purposes.
		// (deep copy isn't necessary because we only
		// change the rid and token which are basic types)
		selfMsg := *msg
		// NOTE: We use the same RoundID as in the dmMsg
		//       object. This enables the same msgID on sender
		//       and recipient.
		selfMsg.RoundID = uint64(rid)
		selfMsg.SelfRoundID = uint64(rid)
		// NOTE: Very important to overwrite these fields
		// for self sending!
		selfMsg.DMToken = partnerToken

		// Serialize the message
		selfDMSerial, err := proto.Marshal(&selfMsg)
		if err != nil {
			return nil, err
		}

		selfService := createRandomService(rng)

		payloadLen = calcDMPayloadLen(net)

		// FIXME: Why does this one return an error when the
		// other doesn't!?
		selfCiphertext, err := dm.Cipher.EncryptSelf(selfDMSerial,
			myPrivateKey, partnerPubKey, payloadLen)
		if err != nil {
			return nil, err
		}

		fpBytes, encryptedPayload, mac, err = createCMIXFields(
			selfCiphertext, payloadLen, rng)
		if err != nil {
			return nil, err
		}

		fp = format.NewFingerprint(fpBytes)

		selfSendMsg := cmix.TargetedCmixMessage{
			Recipient:   myID,
			Payload:     encryptedPayload,
			Fingerprint: fp,
			Service:     selfService,
			Mac:         mac,
		}

		return []cmix.TargetedCmixMessage{sendMsg, selfSendMsg}, nil
	}
	return net.SendManyWithAssembler([]*id.ID{partnerID, myID}, assemble, params)
}

// makeDebugTag is a debug helper that creates non-unique msg identifier.
//
// This is set as the debug tag on messages and enables some level of tracing a
// message (if its contents/chan/type are unique).
func makeDebugTag(id ed25519.PublicKey,
	msg []byte, baseTag string) string {

	h, _ := blake2b.New256(nil)
	h.Write(msg)
	h.Write(id)

	tripCode := base64.RawStdEncoding.EncodeToString(h.Sum(nil))[:12]
	return fmt.Sprintf("%s-%s", baseTag, tripCode)
}

func calcDMPayloadLen(net cMixClient) int {
	// As we don't use the mac or fp fields, we can extend
	// our payload size
	// (-2 to eliminate the first byte of mac and fp)
	return net.GetMaxMessageLength() +
		format.MacLen + format.KeyFPLen - 2

}

// Helper function that splits up the ciphertext into the appropriate cmix
// packet subfields
func createCMIXFields(ciphertext []byte, payloadSize int,
	rng io.Reader) (fpBytes, encryptedPayload, mac []byte, err error) {

	fpBytes = make([]byte, format.KeyFPLen)
	mac = make([]byte, format.MacLen)
	encryptedPayload = make([]byte, payloadSize-
		len(fpBytes)-len(mac)+2)

	// The first byte of mac and fp are random
	prefixBytes := make([]byte, 2)
	n, err := rng.Read(prefixBytes)
	if err != nil || n != len(prefixBytes) {
		err = fmt.Errorf("rng read failure: %+v", err)
		return nil, nil, nil, err
	}
	// Note: the first bit must be 0 for these...
	fpBytes[0] = 0x7F & prefixBytes[0]
	mac[0] = 0x7F & prefixBytes[1]

	// ciphertext[0:FPLen-1] == fp[1:FPLen]
	start := 0
	end := format.KeyFPLen - 1
	copy(fpBytes[1:format.KeyFPLen], ciphertext[start:end])
	// ciphertext[FPLen-1:FPLen+MacLen-2] == mac[1:MacLen]
	start = end
	end = start + format.MacLen - 1
	copy(mac[1:format.MacLen], ciphertext[start:end])
	// ciphertext[FPLen+MacLen-2:] == encryptedPayload
	start = end
	end = start + len(encryptedPayload)
	copy(encryptedPayload, ciphertext[start:end])

	// Fill anything left w/ random data
	numLeft := end - start - len(encryptedPayload)
	if numLeft > 0 {
		jww.WARN.Printf("[DM] small ciphertext, added %d bytes",
			numLeft)
		n, err := rng.Read(encryptedPayload[end-start:])
		if err != nil || n != numLeft {
			err = fmt.Errorf("rng read failure: %+v", err)
			return nil, nil, nil, err
		}
	}

	return fpBytes, encryptedPayload, mac, nil
}

func createRandomService(rng io.Reader) message.Service {
	// NOTE: 64 is entirely arbitrary, 33 bytes are used for the ID
	// and the rest will be base64'd into a string for the tag.
	data := make([]byte, 64)
	n, err := rng.Read(data)
	if err != nil {
		jww.FATAL.Panicf("rng failure: %+v", err)
	}
	if n != len(data) {
		jww.FATAL.Panicf("rng read failure, short read: %d < %d", n,
			len(data))
	}
	return message.Service{
		Identifier: data[:33],
		Tag:        base64.RawStdEncoding.EncodeToString(data[33:]),
	}
}
