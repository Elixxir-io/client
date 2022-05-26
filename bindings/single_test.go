package bindings

import (
	"encoding/json"
	"gitlab.com/elixxir/client/cmix/identity/receptionID"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"testing"
	"time"
)

func TestSingleUseJsonMarshals(t *testing.T) {
	rids := []id.Round{1, 5, 9}
	rl := makeRoundsList(rids)
	rid := id.NewIdFromString("zezima", id.User, t)
	eid, _, _, err := ephemeral.GetId(rid, 16, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("Failed to generate ephemeral id: %+v", err)
	}
	ephId := receptionID.EphemeralIdentity{
		EphId:  eid,
		Source: rid,
	}
	payload := make([]byte, 64)
	rng := csprng.NewSystemRNG()
	rng.Read(payload)
	sendReport := SingleUseSendReport{
		RoundsList: rl,
		EphID:      ephId,
	}
	srm, err := json.Marshal(sendReport)
	if err != nil {
		t.Errorf("Failed to marshal send report to JSON: %+v", err)
	} else {
		t.Logf("Marshalled send report:\n%s\n", string(srm))
	}

	responseReport := SingleUseResponseReport{
		RoundsList:  rl,
		Payload:     payload,
		ReceptionID: ephId,
		Err:         nil,
	}
	rrm, err := json.Marshal(responseReport)
	if err != nil {
		t.Errorf("Failed to marshal response report to JSON: %+v", err)
	} else {
		t.Logf("Marshalled response report:\n%s\n", string(rrm))
	}

	callbackReport := SingleUseCallbackReport{
		RoundsList: rl,
		Payload:    payload,
		Partner:    rid,
		EphID:      ephId,
	}
	crm, err := json.Marshal(callbackReport)
	if err != nil {
		t.Errorf("Failed to marshal callback report to JSON: %+v", err)
	} else {
		t.Logf("Marshalled callback report:\n%s\n", string(crm))
	}
}
