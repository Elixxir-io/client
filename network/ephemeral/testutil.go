///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package ephemeral

import (
	"gitlab.com/elixxir/client/network/gateway"
	"testing"
	"time"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/interfaces"
	"gitlab.com/elixxir/client/interfaces/message"
	"gitlab.com/elixxir/client/interfaces/params"
	"gitlab.com/elixxir/client/stoppable"
	"gitlab.com/elixxir/comms/network"
	"gitlab.com/elixxir/comms/testkeys"
	"gitlab.com/elixxir/crypto/e2e"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/comms/connect"
	"gitlab.com/xx_network/primitives/id"
	"gitlab.com/xx_network/primitives/id/ephemeral"
	"gitlab.com/xx_network/primitives/ndf"
	"gitlab.com/xx_network/primitives/utils"
)

// testNetworkManager is a test implementation of NetworkManager interface.
type testNetworkManager struct {
	instance *network.Instance
	msg      message.Send
}

func (t *testNetworkManager) SendE2E(m message.Send, _ params.E2E, _ *stoppable.Single) ([]id.Round,
	e2e.MessageID, time.Time, error) {
	rounds := []id.Round{
		id.Round(0),
		id.Round(1),
		id.Round(2),
	}

	t.msg = m

	return rounds, e2e.MessageID{}, time.Time{}, nil
}

func (t *testNetworkManager) SendUnsafe(m message.Send, _ params.Unsafe) ([]id.Round, error) {
	rounds := []id.Round{
		id.Round(0),
		id.Round(1),
		id.Round(2),
	}

	t.msg = m

	return rounds, nil
}

func (t *testNetworkManager) SendCMIX(format.Message, *id.ID, params.CMIX) (id.Round, ephemeral.Id, error) {
	return 0, ephemeral.Id{}, nil
}

func (t *testNetworkManager) SendManyCMIX(messages []message.TargetedCmixMessage, p params.CMIX) (id.Round, []ephemeral.Id, error) {
	return 0, []ephemeral.Id{}, nil
}

func (t *testNetworkManager) GetInstance() *network.Instance {
	return t.instance
}

type dummyEventMgr struct{}

func (d *dummyEventMgr) Report(p int, a, b, c string) {}
func (t *testNetworkManager) GetEventManager() interfaces.EventManager {
	return &dummyEventMgr{}
}

func (t *testNetworkManager) GetHealthTracker() interfaces.HealthTracker {
	return nil
}

func (t *testNetworkManager) Follow(_ interfaces.ClientErrorReport) (stoppable.Stoppable, error) {
	return nil, nil
}

func (t *testNetworkManager) CheckGarbledMessages() {}

func (t *testNetworkManager) InProgressRegistrations() int {
	return 0
}

func (t *testNetworkManager) GetSender() *gateway.Sender {
	return nil
}

func (t *testNetworkManager) GetAddressSize() uint8    { return 15 }
func (t *testNetworkManager) GetVerboseRounds() string { return "" }
func (t *testNetworkManager) RegisterAddressSizeNotification(string) (chan uint8, error) {
	return nil, nil
}

func (t *testNetworkManager) UnregisterAddressSizeNotification(string) {}
func (t *testNetworkManager) SetPoolFilter(gateway.Filter)             {}

func NewTestNetworkManager(i interface{}) interfaces.NetworkManager {
	switch i.(type) {
	case *testing.T, *testing.M, *testing.B:
		break
	default:
		jww.FATAL.Panicf("NewTestNetworkManager is restricted to testing only."+
			"Got %T", i)
	}

	commsManager := connect.NewManagerTesting(i)

	cert, err := utils.ReadFile(testkeys.GetNodeCertPath())
	if err != nil {
		jww.FATAL.Panicf("Failed to create new test Instance: %+v", err)
	}

	_, err = commsManager.AddHost(
		&id.Permissioning, "", cert, connect.GetDefaultHostParams())
	if err != nil {
		jww.FATAL.Panicf("Failed to add host: %+v", err)
	}
	instanceComms := &connect.ProtoComms{
		Manager: commsManager,
	}

	thisInstance, err := network.NewInstanceTesting(
		instanceComms, getNDF(), getNDF(), nil, nil, i)
	if err != nil {
		jww.FATAL.Panicf("Failed to create new test Instance: %+v", err)
	}

	thisManager := &testNetworkManager{instance: thisInstance}

	return thisManager
}

func getNDF() *ndf.NetworkDefinition {
	return &ndf.NetworkDefinition{
		E2E: ndf.Group{
			Prime: "E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B" +
				"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE" +
				"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F" +
				"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041" +
				"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45" +
				"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209" +
				"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29" +
				"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E" +
				"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2" +
				"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696" +
				"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E" +
				"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873" +
				"847AEF49F66E43873",
			Generator: "2",
		},
		CMIX: ndf.Group{
			Prime: "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48" +
				"C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F" +
				"FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
				"B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2" +
				"35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41" +
				"F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
				"92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15" +
				"3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B",
			Generator: "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
				"D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
				"6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
				"085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
				"AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
				"3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
				"BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
				"DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7",
		},
	}
}