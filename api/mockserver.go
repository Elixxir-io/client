////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// This sets up a dummy/mock server instance for testing purposes
package api

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/client/cmixproto"
	"gitlab.com/elixxir/client/globals"
	"gitlab.com/elixxir/client/parse"
	pb "gitlab.com/elixxir/comms/mixmessages"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"gitlab.com/elixxir/primitives/id"
	"gitlab.com/elixxir/primitives/ndf"
	"sync"
	"time"
)

const InvalidClientVersion = "1.1.0"

// APIMessage are an implementation of the interface in bindings and API
// easy to use from Go
type APIMessage struct {
	Payload     []byte
	SenderID    *id.User
	RecipientID *id.User
}

func (m APIMessage) GetSender() *id.User {
	return m.SenderID
}

func (m APIMessage) GetRecipient() *id.User {
	return m.RecipientID
}

func (m APIMessage) GetPayload() []byte {
	return m.Payload
}

func (m APIMessage) GetMessageType() int32 {
	return int32(cmixproto.Type_NO_TYPE)
}

func (m APIMessage) GetCryptoType() parse.CryptoType {
	return parse.None
}

func (m APIMessage) GetTimestamp() time.Time {
	return time.Now()
}

func (m APIMessage) Pack() []byte {
	// assuming that the type is independently populated.
	// that's probably a bad idea
	// there's no good reason to have the same method body for each of these
	// two methods!
	return m.Payload
}

// Blank struct implementing ServerHandler interface for testing purposes (Passing to StartServer)
type TestInterface struct {
	LastReceivedMessage pb.Slot
}

// Returns message contents for MessageID, or a null/randomized message
// if that ID does not exist of the same size as a regular message
func (m *TestInterface) GetMessage(userId *id.User,
	msgId, ipaddr string) (*pb.Slot, error) {
	return &pb.Slot{}, nil
}

// Return any MessageIDs in the globals for this User
func (m *TestInterface) CheckMessages(userId *id.User,
	messageID, ipaddr string) ([]string, bool) {
	return make([]string, 0), false
}

// PutMessage adds a message to the outgoing queue and
// calls SendBatch when it's size is the batch size
func (m *TestInterface) PutMessage(msg *pb.Slot, ipaddr string) error {
	m.LastReceivedMessage = *msg
	return nil
}

func (m *TestInterface) ConfirmNonce(message *pb.RequestRegistrationConfirmation, ipaddr string) (*pb.RegistrationConfirmation, error) {
	regConfirmation := &pb.RegistrationConfirmation{
		ClientSignedByServer: &pb.RSASignature{},
	}

	return regConfirmation, nil
}

// Blank struct implementing Registration Handler interface for testing purposes (Passing to StartServer)
type MockRegistration struct {
	//LastReceivedMessage pb.CmixMessage
}

func (s *MockRegistration) RegisterNode(ID []byte,
	NodeTLSCert, GatewayTLSCert, RegistrationCode, Addr, Addr2 string) error {
	return nil
}

func (s *MockRegistration) GetUpdatedNDF(clientNdfHash []byte) ([]byte, error) {

	ndfData := buildMockNDF()
	ndfJson, _ := json.Marshal(ndfData)
	return ndfJson, nil
}

func buildMockNDF() ndf.NetworkDefinition {

	ExampleJSON := `{"Timestamp":"2019-06-04T20:48:48-07:00","gateways":[{"Address":"0.0.0.0:7900","Tls_certificate":"-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"},{"Address":"0.0.0.0:7901","Tls_certificate":"-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"},{"Address":"0.0.0.0:7902","Tls_certificate":"-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"}],"nodes":[{"Id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Dsa_public_key":"-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAERwUmUlL9YP\nq6MSn+bUr6qNZPsVYoQAo8nTjZWiuSjJa2XWnh7sftnISWkwkiiRxo7qfq3sAiD5\nB8+tM6kONeICBXukldXJerxoVBspYa+RiPuDWy2pwGRDBpfty3QqJOpu5g2ThYFJ\nD5Xu0yCuX8ZJRj33nliI8dQgKdQQva6p2VuXzyRT8LwXMfRwLuSB6Schc9mF8C\nkWCb4m0ujlEKe1xKoKt2zG9b1o7XyaVhxguSUAuEznifMzsEUfuONJOy+XoQELex\nF0wvLzNzABcyxkM3lx52uG41mKgJiV6Z0ZyuBRvt+V3VL/38tPn9lsTaFi8N6/IH\nRyy0bWP5s44=\n-----END PUBLIC KEY-----\n","Address":"0.0.0.0:5900","Tls_certificate":"-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"},{"Id":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Dsa_public_key":"-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAFbADcqA8KQh\nxzgylW6VS1dYYelO5DjPZVVSjfdcbj1twu4ZHDNZLOexpv4nGY8xS6vesELXcVOR\n/CHXgh/3byBZYm0zkrBi/FsJJ3nP2uZ1+QCRldI2KzqcLOWH/CAYj8koork9k1Dp\nFq7rMSDgw4pktqvFj9Eev8dSZuRnoCfZbt/6vxi1r30AYAjDYOwcysqcVyUa1tPa\nLEh3JksttXUCd5cvfqatWedTs5Vxo7ICW1toGBHABYvSJkwK0YFfi5RLw+Oda1sA\njJ+aLcIxQjrpoRC2alXCdwmZXVb+O6zluQctw6LJjt4J704ueSvR4VNNhr0uLYGW\nk7e+WoQCS98=\n-----END PUBLIC KEY-----\n","Address":"0.0.0.0:5901","Tls_certificate":"-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"},{"Id":[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Dsa_public_key":"-----BEGIN PUBLIC KEY-----\nMIIDNTCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAQCN19tTnkS3\nitBQXXR/h8OKl+rliFBLgO6h6GvZL4yQDZFtBAOmkrs3wLoDroJRGCeqz/IUb+JF\njslEr/mpm2kcmK77hr535dq7HsWz1fFl9YyGTaOH055FLSV9QEPAV9j3zWADdQ1v\nuSQll+QfWi6lIibWV4HNQ2ywRFoOY8OBLCJB90UXLeJpaPanpqiM8hjda2VGRDbi\nIixEE2lCOWITydiz2DmvXrLhVGF49+g5MDwbWO65dmasCe//Ff6Z4bJ6n049xv\nVtac8nX6FO3eBsV5d+rG6HZXSG3brCKRCSKYCTX1IkTSiutYxYqvwaluoCjOakh0\nKkqvQ8IeVZ+B\n-----END PUBLIC KEY-----\n","Address":"0.0.0.0:5902","Tls_certificate":"-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"}],"registration":{"Address":"0.0.0.0:5000","Tls_certificate":""},"udb":{"Id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3],"Dsa_public_key":"-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBACvR2lUslz3D\nB/MUo0rHVIHVkhVJCxNjtgTOYgJ9ckArSXQbYzr/fcigcNGjUO2LbK5NFp9GK43C\nrLxMUnJ9nkyIVPaWvquJFZItjcDK3NiNGyD4XyM0eRj4dYeSxQM48hvFbmtbjlXn\n9SQTnGIlr1XnTI4RVHZSQOL6kFJIaLw6wYrQ4w08Ng+p45brp5ercAHnLiftNUWP\nqROhQkdSEpS9LEwfotUSY1jP2AhQfaIMxaeXsZuTU1IYvdhMFRL3DR0r5Ww2Upf8\ng0Ace0mtnsUQ2OG+7MTh2jYIEWRjvuoe3RCz603ujW6g7BfQ1H7f4YFwc5xOOJ3u\nr4dj49dCCjc=\n-----END PUBLIC KEY-----\n"},"E2e":{"Prime":"E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AEDF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF453B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE92096EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F278DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873847AEF49F66E43873","Small_prime":"02","Generator":"02"},"CMIX":{"Prime":"9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44FFE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE235567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA153E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B","Small_prime":"F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F","Generator":"5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C46A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7"}}`
	retNDF, _, _ := ndf.DecodeNDF(ExampleJSON)
	/*
		var grp ndf.Group
		grp.Prime = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
		grp.Generator = "2"
		grp.SmallPrime = "2"
		retNDF := ndf.NetworkDefinition{Timestamp: time.Now(), Registration: reg, Nodes: Nodes, CMIX: grp, E2E: grp}*/
	return *retNDF
}

// Registers a user and returns a signed public key
func (s *MockRegistration) RegisterUser(registrationCode,
	key string) (hash []byte, err error) {
	return nil, nil
}

func (s *MockRegistration) GetCurrentClientVersion() (version string, err error) {
	return globals.SEMVER, nil
}

func getDHPubKey() *cyclic.Int {
	cmixGrp := cyclic.NewGroup(
		large.NewIntFromString("9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48"+
			"C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F"+
			"FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5"+
			"B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2"+
			"35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41"+
			"F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE"+
			"92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15"+
			"3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B", 16),
		large.NewIntFromString("5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613"+
			"D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4"+
			"6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472"+
			"085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5"+
			"AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA"+
			"3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71"+
			"BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0"+
			"DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7", 16))

	dh := cmixGrp.RandomCoprime(cmixGrp.NewMaxInt())
	return cmixGrp.ExpG(dh, cmixGrp.NewMaxInt())
}

// Pass-through for Registration Nonce Communication
func (m *TestInterface) RequestNonce(message *pb.NonceRequest, ipaddr string) (*pb.Nonce, error) {
	dh := getDHPubKey().Bytes()
	return &pb.Nonce{
		DHPubKey: dh,
	}, nil
}

// Mock dummy storage interface for testing.
type DummyStorage struct {
	Location string
	LastSave []byte
	mutex    sync.Mutex
}

func (d *DummyStorage) SetLocation(l string) error {
	d.Location = l
	return nil
}

func (d *DummyStorage) GetLocation() string {
	return d.Location
}

func (d *DummyStorage) Save(b []byte) error {
	d.LastSave = make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		d.LastSave[i] = b[i]
	}
	return nil
}

func (d *DummyStorage) Lock() {
	d.mutex.Lock()
}

func (d *DummyStorage) Unlock() {
	d.mutex.Unlock()
}

func (d *DummyStorage) Load() []byte {
	return d.LastSave
}

type DummyReceiver struct {
	LastMessage APIMessage
}

func (d *DummyReceiver) Receive(message APIMessage) {
	d.LastMessage = message
}

//registration handler for getUpdatedNDF error case
type MockPerm_NDF_ErrorCase struct {
}

func (s *MockPerm_NDF_ErrorCase) RegisterNode(ID []byte,
	NodeTLSCert, GatewayTLSCert, RegistrationCode, Addr, Addr2 string) error {
	return nil
}

func (s *MockPerm_NDF_ErrorCase) GetUpdatedNDF(clientNdfHash []byte) ([]byte, error) {
	errMsg := fmt.Sprintf("Permissioning server does not have an ndf to give to client")
	return nil, errors.New(errMsg)
}

func (s *MockPerm_NDF_ErrorCase) RegisterUser(registrationCode,
	key string) (hash []byte, err error) {
	return nil, nil
}

func (s *MockPerm_NDF_ErrorCase) GetCurrentClientVersion() (version string, err error) {
	return globals.SEMVER, nil
}

//Mock Permissioning handler for error cases involving check version
type MockPerm_CheckVersion_ErrorCase struct {
}

func (s *MockPerm_CheckVersion_ErrorCase) RegisterNode(ID []byte,
	NodeTLSCert, GatewayTLSCert, RegistrationCode, Addr, Addr2 string) error {
	return nil
}
func (s *MockPerm_CheckVersion_ErrorCase) GetUpdatedNDF(clientNdfHash []byte) ([]byte, error) {
	ndfData := buildMockNDF()
	ndfJson, _ := json.Marshal(ndfData)
	return ndfJson, nil
}
func (s *MockPerm_CheckVersion_ErrorCase) RegisterUser(registrationCode,
	key string) (hash []byte, err error) {
	return nil, nil
}
func (s *MockPerm_CheckVersion_ErrorCase) GetCurrentClientVersion() (version string, err error) {
	return globals.SEMVER, errors.New("Could not get version")
}

//Registration handler for handling a bad client version (aka client is not up to date)
type MockPerm_CheckVersion_BadVersion struct {
}

func (s *MockPerm_CheckVersion_BadVersion) RegisterNode(ID []byte,
	NodeTLSCert, GatewayTLSCert, RegistrationCode, Addr, Addr2 string) error {
	return nil
}

func (s *MockPerm_CheckVersion_BadVersion) GetUpdatedNDF(clientNdfHash []byte) ([]byte, error) {
	ndfData := buildMockNDF()
	ndfJson, _ := json.Marshal(ndfData)
	return ndfJson, nil
}

func (s *MockPerm_CheckVersion_BadVersion) RegisterUser(registrationCode,
	key string) (hash []byte, err error) {
	return nil, nil
}

func (s *MockPerm_CheckVersion_BadVersion) GetCurrentClientVersion() (version string, err error) {
	return InvalidClientVersion, nil
}
