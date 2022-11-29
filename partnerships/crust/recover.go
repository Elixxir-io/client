////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"io"
	"net/http"
	"strings"
)

// Recovery URLs and tokens.
const (
	cidRequestURL     = "https://pin.crustcode.com/psa/cids/"
	recoveryUrlV0     = "https://gw-nft.crustapps.net/api/v0/cat?arg="
	recoveryUrl       = "https://gw-nft.crustapps.net/ipfs/"
	recoveryBasicAuth = "c3ViLTVGcXdqWW9MUXE5Z2NXSGM2azVZd3RuZHg3Q01pQ1FlS1N2THpYb2plZ3ZYY005bToweDIwZjYxODc5ODhiNjIxZjk3ZDQwNGZlZmMzZTQ5MWU5OTU0MWY5MzdjNDNiYWQyNWE3NGQ2OTRjMjA2NWYzODFkOTc5YmY0YTQzYmI3MGZlYzY1MzIwMGI2MmFhZmRiOWFjNzEwODc1YzlkMjhlYTJjNTA2ZDcyZDc1Y2RjNzA2"
)

// RecoveryResponse is the response from RecoverBackup.
type RecoveryResponse struct {
	// Value is the base64 encoded file that was backup up to the network.
	Value string
}

// cidResponse is the response from the requestCid call to the PIN service.
type cidResponse struct {
	Address string `json:"address"`
	// Cids is the CID associated with our username. This
	// value allows us to request the file from the network.
	Cids []string `json:"cids"`
}

// RecoverBackup retrieves the backup file uploaded to the distributed file
// server. The user must have called UploadBackup successfully for a proper
// file recover.
func RecoverBackup(username string) ([]byte, error) {
	jww.INFO.Printf("[CRUST] Requesting CID...")
	cidResp, err := requestCid(username)
	if err != nil {
		return nil, errors.Errorf("failed to request CID: %+v", err)
	}

	jww.INFO.Printf("[CRUST] Received CID.")
	jww.INFO.Printf("[CRUST] Requesting file (V0)...")

	jww.INFO.Printf("[CRUST] Requesting file (V1)...")
	backupFile, err := requestBackupFile(cidResp)
	if err != nil {
		return nil, errors.Errorf("failed to retrieve backup file: %+v", err)
	}

	jww.INFO.Printf("[CRUST] File is recovered")

	return backupFile, nil
}

// requestCid requests the CID associated with this username.
// This allows the user to request their backup file using requestBackupFile.
func requestCid(username string) (*cidResponse, error) {

	// Construct request to get CID
	req, err := http.NewRequest(http.MethodGet, cidRequestURL+username, nil)
	if err != nil {
		return nil, err
	}

	// Initialize request to fill out Form section
	err = req.ParseForm()
	if err != nil {
		return nil, errors.Errorf(parseFormErr, err)
	}

	// Retrieve basic auth from token
	recoveryAuthUser, recoveryAuthPass, err := getRecoveryAuth()
	if err != nil {
		return nil, err
	}

	// Add auth header
	req.SetBasicAuth(recoveryAuthUser, recoveryAuthPass)

	// Send request
	responseData, err := sendRequest(req)
	if err != nil {
		return nil, errors.Errorf("failed request: %+v", err)
	}

	// Parse request
	cidResp := &cidResponse{}
	err = json.Unmarshal(responseData, cidResp)
	if err != nil {
		return nil, err
	}

	// Sanity check that there is at least one CID in the response
	if len(cidResp.Cids) < 1 {
		return nil, errors.Errorf("CID response from Crust does not contain any CIDs.")
	}

	jww.INFO.Printf("[CRUST] CID response: %v", cidResp)

	return cidResp, nil
}

// requestBackupFile sends the CID to the network to retrieve the backed up
// file.
func requestBackupFile(cid *cidResponse) ([]byte, error) {

	// Construct restore GET request
	response, err := http.Get(recoveryUrl + cid.Cids[0])
	if err != nil {
		return nil, err
	}

	// Read response
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

// requestBackupFileV0 is the http.MethodPost version to retrieve the file
// according to spec. This is kept for historical purposes, in the case
// the code needs to be revised.
func requestBackupFileV0(cid *cidResponse) ([]byte, error) {
	// Construct request
	req, err := http.NewRequest(http.MethodPost, recoveryUrlV0+cid.Cids[0], nil)
	if err != nil {
		return nil, err
	}

	// Initialize request to fill out Form section
	err = req.ParseForm()
	if err != nil {
		return nil, errors.Errorf(parseFormErr, err)
	}

	// Retrieve basic auth from token
	recoveryAuthUser, recoveryAuthPass, err := getRecoveryAuth()
	if err != nil {
		return nil, err
	}

	// Add auth header
	req.SetBasicAuth(recoveryAuthUser, recoveryAuthPass)

	// Send request
	responseData, err := sendRequest(req)
	if err != nil {
		return nil, errors.Errorf("failed request: %+v", err)
	}

	return responseData, nil
}

// getRecoveryAuth is a helper function which parses the recovery token provided
// in recoveryBasicAuth and returns it such that it can be provided to the HTTP
// request.
func getRecoveryAuth() (username, pass string, err error) {
	recoveryAuthDecoded, err := base64.StdEncoding.DecodeString(recoveryBasicAuth)
	if err != nil {
		return "", "", err
	}

	recoveryAuth := strings.Split(string(recoveryAuthDecoded), ":")
	if len(recoveryAuth) != 2 {
		return "", "", errors.Errorf("failed to retrieve recovery auth")
	}

	username, pass = recoveryAuth[0], recoveryAuth[1]

	return
}
