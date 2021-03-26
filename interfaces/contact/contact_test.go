///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package contact

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/fact"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"gitlab.com/xx_network/primitives/id"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// Tests marshaling and unmarshalling of a common Contact.
func TestContact_Marshal_Unmarshal(t *testing.T) {
	expectedContact := Contact{
		ID:       id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
			{Fact: "6502530001US", T: fact.Phone},
		},
	}

	buff := expectedContact.Marshal()

	testContact, err := Unmarshal(buff)
	if err != nil {
		t.Errorf("Unmarshal() produced an error: %+v", err)
	}

	if !reflect.DeepEqual(expectedContact, testContact) {
		t.Errorf("Unmarshaled Contact does not match expected."+
			"\nexpected: %#v\nreceived: %#v", expectedContact, testContact)
	}
}

// Tests marshaling and unmarshalling of a Contact with nil fields.
func TestContact_Marshal_Unmarshal_Nil(t *testing.T) {
	expectedContact := Contact{}

	buff := expectedContact.Marshal()

	testContact, err := Unmarshal(buff)
	if err != nil {
		t.Errorf("Unmarshal() produced an error: %+v", err)
	}

	if !reflect.DeepEqual(expectedContact, testContact) {
		t.Errorf("Unmarshaled Contact does not match expected."+
			"\nexpected: %#v\nreceived: %#v", expectedContact, testContact)
	}
}

// Tests the size of marshaling and JSON marshaling of a Contact with a large
// amount of data.
func TestContact_Marshal_Size(t *testing.T) {
	expectedContact := Contact{
		ID:             id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey:       getCycInt(512),
		OwnershipProof: make([]byte, 1024),
		Facts: fact.FactList{
			{Fact: "myVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryLongUsername", T: fact.Username},
			{Fact: "myVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryLongEmail@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
		},
	}
	rand.Read(expectedContact.OwnershipProof)

	buff := expectedContact.Marshal()

	marshalBuff, err := json.Marshal(expectedContact)
	if err != nil {
		t.Errorf("Marshal() produced an error: %+v", err)
	}

	t.Logf("size of buff:        %d", len(buff))
	t.Logf("size of marshalBuff: %d", len(marshalBuff))
	t.Logf("ratio: %.2f%%", float32(len(buff))/float32(len(marshalBuff))*100)
	t.Logf("%s", marshalBuff)

	if len(marshalBuff) < len(buff) {
		t.Errorf("JSON Contact smaller than marshaled contact."+
			"\nJSON:    %d\nmarshal: %d", len(marshalBuff), len(buff))
	}
}

// Unit test of GetFingerprint.
func TestContact_GetFingerprint(t *testing.T) {
	c := Contact{
		ID:       id.NewIdFromString("Samwise", id.User, t),
		DhPubKey: getCycInt(512),
	}

	testFP := c.GetFingerprint()
	if len(testFP) != fingerprintLength {
		t.Errorf("GetFingerprint() returned fingerprint with unexpected length."+
			"\nexpected length: %d\nreceived length: %d",
			fingerprintLength, len(testFP))
	}

	// Generate expected fingerprint
	h := crypto.SHA256.New()
	h.Write(c.ID.Bytes())
	h.Write(c.DhPubKey.Bytes())
	expectedFP := base64.StdEncoding.EncodeToString(h.Sum(nil))[:fingerprintLength]

	if strings.Compare(expectedFP, testFP) != 0 {
		t.Errorf("GetFingerprint() returned expected fingerprint."+
			"\nexpected: %s\nreceived: %s", expectedFP, testFP)
	}

}

// Consistency test for changes in underlying dependencies.
func TestContact_GetFingerprint_Consistency(t *testing.T) {
	expected := []string{
		"rBUw1n4jtH4uEYq", "Z/Jm1OUwDaql5cd", "+vHLzY+yH96zAiy",
		"cZm5Iz78ViOIlnh", "9LqrcbFEIV4C4LX", "ll4eykGpMWYlxw+",
		"6YQshWJhdPL6ajx", "Y6gTPVEzow4IHOm", "6f/rT2vWxDC9tdt",
		"rwqbDT+PoeA6Iww", "YN4IFijP/GZ172O", "ScbHVQc2T9SXQ2m",
		"50mfbCXQ+LIqiZn", "cyRYdMKXByiFdtC", "7g6ujy7iIbJVl4F",
	}

	for i := range expected {
		c := Contact{
			ID:       id.NewIdFromUInt(uint64(i), id.User, t),
			DhPubKey: getGroup().NewInt(25),
		}

		fp := c.GetFingerprint()
		if expected[i] != fp {
			t.Errorf("GetFingerprint() did not output the expected fingerprint (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected[i], fp)
		}
	}
}

// Happy path.
func TestEqual(t *testing.T) {
	a := Contact{
		ID:             id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey:       getCycInt(512),
		OwnershipProof: make([]byte, 1024),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
		},
	}
	rand.Read(a.OwnershipProof)
	b := Contact{
		ID:             a.ID,
		DhPubKey:       a.DhPubKey,
		OwnershipProof: a.OwnershipProof,
		Facts:          a.Facts,
	}
	c := Contact{
		ID:             id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey:       getCycInt(512),
		OwnershipProof: make([]byte, 1024),
	}

	if !Equal(a, b) {
		t.Errorf("Equal reported two equal contacts as different."+
			"\na: %+v\nb: +%v", a, b)
	}

	if Equal(a, c) {
		t.Errorf("Equal reported two unequal contacts as the same."+
			"\na: %+v\nc: +%v", a, c)
	}
}

func getCycInt(size int) *cyclic.Int {
	var primeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E0" +
		"88A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F" +
		"14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDE" +
		"E386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48" +
		"361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907709" +
		"6966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603" +
		"9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D22" +
		"61898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458" +
		"DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619" +
		"DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE1" +
		"17577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A" +
		"92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150B" +
		"DA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B" +
		"2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127" +
		"D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFF" +
		"FFF"

	buff, err := csprng.GenerateInGroup([]byte(primeString), size, csprng.NewSystemRNG())
	if err != nil {
		panic(err)
	}

	grp := cyclic.NewGroup(large.NewIntFromString(primeString, 16),
		large.NewInt(2)).NewIntFromBytes(buff)

	return grp
}

func getGroup() *cyclic.Group {
	return cyclic.NewGroup(
		large.NewIntFromString("E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D4941"+
			"3394C049B7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688"+
			"B55B3DD2AEDF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861"+
			"575E745D31F8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC"+
			"718DD2A3E041023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FF"+
			"B1BC51DADDF453B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBC"+
			"A23EAC5ACE92096EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD"+
			"161C7738F32BF29A841698978825B4111B4BC3E1E198455095958333D776D8B2B"+
			"EEED3A1A1A221A6E37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C"+
			"4F50D7D7803D2D4F278DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F"+
			"1390B5D3FEACAF1696015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F"+
			"96789C38E89D796138E6319BE62E35D87B1048CA28BE389B575E994DCA7554715"+
			"84A09EC723742DC35873847AEF49F66E43873", 16),
		large.NewIntFromString("2", 16))
}

// Happy path.
func TestContact_MakeQR(t *testing.T) {
	expectedQrCode := "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"

	c := Contact{
		ID:       id.NewIdFromUInt(rand.Uint64(), id.User, t),
		DhPubKey: getCycInt(256),
		Facts: fact.FactList{
			{Fact: "myUsername", T: fact.Username},
			{Fact: "devinputvalidation@elixxir.io", T: fact.Email},
			{Fact: "6502530000US", T: fact.Phone},
			{Fact: "6502530001US", T: fact.Phone},
		},
	}
	qrCode, err := c.MakeQR()
	if err != nil {
		t.Errorf("MakeQR() returned an error: %+v", err)
	}

	expectedData, _ := base64.StdEncoding.DecodeString(expectedQrCode)
	if !bytes.Equal(qrCode, expectedData) {
		t.Errorf("Generated QR code data does not match expected."+
			"\nexpected: %+v\nreceived: %+v", expectedData, qrCode)
	}

}
