////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package bot functions for working with the user discovery bot (UDB)
package bots

import (
	"encoding/base64"
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/privategrity/client/io"
	"gitlab.com/privategrity/crypto/hash"
	"strconv"
	"strings"
	"gitlab.com/privategrity/client/user"
	"gitlab.com/privategrity/crypto/format"
	"gitlab.com/privategrity/client/parse"
	"gitlab.com/privategrity/client/listener"
)

// UdbID is the ID of the user discovery bot, which is always 13
const udbID = user.ID(13)

// Register sends a registration message to the UDB. It does this by sending 2
// PUSHKEY messages to the UDB, then calling UDB's REGISTER command.
// If any of the commands fail, it returns an error.
func Register(valueType, value string, publicKey []byte) error {
	keyFP := fingerprint(publicKey)

	// check if key already exists and push one if it doesn't
	if !keyExists(udbID, keyFP) {
		err := pushKey(udbID, keyFP, publicKey)
		if err != nil {
			return fmt.Errorf("Could not PUSHKEY: %s", err.Error())
		}
	}

	// Send register command
	regResult := sendCommand(udbID, fmt.Sprintf("REGISTER %s %s %s",
		valueType, value, keyFP))
	if regResult != "REGISTRATION COMPLETE" {
		return fmt.Errorf("Registration failed: %s", regResult)
	}
	return nil
}

// Search returns a userID and public key based on the search criteria
// it accepts a valueType of EMAIL and value of an e-mail address, and
// returns a map of userid -> public key
func Search(valueType, value string) (map[uint64][]byte, error) {
	response := sendCommand(udbID, fmt.Sprintf("SEARCH %s %s", valueType, value))
	empty := fmt.Sprintf("SEARCH %s NOTFOUND", value)
	if response == empty {
		return nil, nil
	}
	// While search returns more than 1 result, we only process the first
	cMixUID, keyFP := parseSearch(response)
	if cMixUID == 0 {
		return nil, fmt.Errorf("%s", keyFP)
	}

	// Get the full key and decode it
	responses := sendCommandMulti(2, udbID, fmt.Sprintf("GETKEY %s", keyFP))
	publicKey := make([]byte, 256)
	for i := 0; i < 2; i++ {
		idx, keymat := parseGetKey(responses[i])
		for j := range keymat {
			publicKey[j+idx] = keymat[j]
		}

	}

	actualFP := fingerprint(publicKey)
	if keyFP != actualFP {
		return nil, fmt.Errorf("Fingerprint for %s did not match %s!", keyFP,
			actualFP)
	}

	retval := make(map[uint64][]byte)
	retval[cMixUID] = publicKey

	return retval, nil
}

// parseSearch parses the responses from SEARCH. It returns the user's id and
// the user's public key fingerprint
func parseSearch(msg string) (uint64, string) {
	resParts := strings.Split(msg, " ")
	if len(resParts) != 5 {
		return 0, fmt.Sprintf("Invalid response from search: %s", msg)
	}

	cMixUID, err := strconv.ParseUint(resParts[3], 10, 64)
	if err != nil {
		return 0, fmt.Sprintf("Couldn't parse search cMix UID: %s", msg)
	}

	return cMixUID, resParts[4]
}

// parseGetKey parses the responses from GETKEY. It returns the index offset
// value (0 or 128) and the part of the corresponding public key.
func parseGetKey(msg string) (int, []byte) {
	resParts := strings.Split(msg, " ")
	if len(resParts) != 4 {
		jww.WARN.Printf("Invalid response from GETKEY: %s", msg)
		return -1, nil
	}

	idx, err := strconv.ParseInt(resParts[2], 10, 32)
	if err != nil {
		jww.WARN.Printf("Couldn't parse GETKEY Index: %s", msg)
		return -1, nil
	}
	keymat, err := base64.StdEncoding.DecodeString(resParts[3])
	if err != nil || len(keymat) != 128 {
		jww.WARN.Printf("Couldn't decode GETKEY keymat: %s", msg)
		return -1, nil
	}

	return int(idx), keymat
}

// pushKey uploads the users' public key
func pushKey(udbID user.ID, keyFP string, publicKey []byte) error {
	publicKeyParts := make([]string, 2)
	publicKeyParts[0] = base64.StdEncoding.EncodeToString(publicKey[:128])
	publicKeyParts[1] = base64.StdEncoding.EncodeToString(publicKey[128:])
	cmd := "PUSHKEY %s %d %s"
	expected := fmt.Sprintf("PUSHKEY COMPLETE %s", keyFP)
	sendCommand(udbID, fmt.Sprintf(cmd, keyFP, 0, publicKeyParts[0]))
	r := sendCommand(udbID, fmt.Sprintf(cmd, keyFP, 128, publicKeyParts[1]))
	if r != expected {
		return fmt.Errorf("PUSHKEY Failed: %s", r)
	}
	return nil
}

type udbListener chan *format.Message

func (l *udbListener) Hear(msg *parse.Message, isHeardElsewhere bool) {
	newFormatMessage, _ := format.NewMessage(uint64(msg.Sender),
		uint64(msg.Receiver), string(msg.Body))
	*l <- &newFormatMessage[0]
}

// keyExists checks for the existence of a key on the bot
func keyExists(udbID user.ID, keyFP string) bool {
	// FIXME hook up new listeners with the UDB here
	cmd := fmt.Sprintf("GETKEY %s", keyFP)
	expected := fmt.Sprintf("GETKEY %s NOTFOUND", keyFP)
	getKeyResponse := sendCommand(udbID, cmd)
	if getKeyResponse != expected {
		// Listen twice to ensure we get the full error message
		// Note that the sendCommand helper listens on a seperate one. We are
		// ensuring that this function waits for 2 messages
		<-getSendListener()
		<-getSendListener()
		return true
	}
	return false
}

// fingerprint generates the same fingerprint that the udb should generate
// TODO: Maybe move this helper to crypto module?
func fingerprint(publicKey []byte) string {
	h, _ := hash.NewCMixHash() // why does this return an err and not panic?
	h.Write(publicKey)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

var sendCommandListenerID string
var sendCommandListener udbListener
// TODO how many types do we actually need to replicate the old UDB's behavior?
// does UDB even need a type? it's got string-based command sending with the
// type as a string in front right now. maybe we could actually just use 0.
// actually we can't use 0 - the listener will match
// TODO UDB messages should populate the type field to avoid getting the first
// message character parsed out.
const udbType = 8

func getSendListener() udbListener {
	if sendCommandListenerID == "" {
		// need to add a new listener to a map
		sendCommandListener = make(udbListener, 1)
		sendCommandListenerID = listener.Listeners.Listen(udbID,
			udbType, &sendCommandListener)
	}
	return sendCommandListener
}

func typeCommand(command string) string {
	typedCommand := parse.Pack(&parse.TypedBody{
		BodyType: udbType,
		Body:     []byte(command),
	})

	return string(typedCommand)
}

// sendCommand sends a command to the udb. This can block forever, but
// only does so if the send command succeeds. Our assumption is that
// we will eventually receive a response from the server. Callers
// to registration that need timeouts should implement it themselves.
func sendCommand(botID user.ID, command string) string {
	// prepend command with the UDB type
	err := io.Messaging.SendMessage(botID, typeCommand(command))
	if err != nil {
		return err.Error()
	}
	response := <-getSendListener()

	return response.GetPayload()
}

// sendCommandMulti waits for responseCnt responses, but does what sendCommand
// does
func sendCommandMulti(responseCnt int, botID user.ID,
	command string) []string {
	// FIXME hook up UDB with the new listeners here
	err := io.Messaging.SendMessage(botID, typeCommand(command))

	responses := make([]string, 0)
	if err != nil {
		responses = append(responses, err.Error())
		return responses
	}

	for i := 0; i < responseCnt; i++ {
		response := <-getSendListener()
		responses = append(responses, response.GetPayload())
	}
	return responses
}
