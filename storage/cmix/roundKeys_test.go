///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
	"gitlab.com/xx_network/crypto/csprng"
	"gitlab.com/xx_network/crypto/large"
	"math/rand"
	"reflect"
	"testing"
)

// tests that the encrypted paylaods and kmacs generated are consistent
func TestRoundKeys_Encrypt_Consistency(t *testing.T) {
	const numKeys = 5

	expectedPayload := []byte{238, 89, 139, 116, 56, 196, 216, 152, 225, 189,
		121, 167, 229, 248, 92, 126, 162, 229, 250, 212, 228, 97, 178, 47, 42,
		180, 141, 141, 146, 231, 15, 231, 53, 205, 36, 72, 83, 92, 92, 51, 97,
		145, 223, 41, 119, 80, 248, 61, 120, 175, 3, 219, 153, 76, 119, 160,
		153, 193, 161, 241, 67, 250, 35, 182, 140, 211, 244, 112, 82, 5, 153,
		91, 33, 15, 7, 61, 215, 133, 235, 214, 247, 93, 142, 131, 192, 203, 82,
		249, 225, 237, 17, 88, 245, 3, 146, 230, 204, 30, 29, 113, 152, 140, 94,
		22, 232, 100, 203, 35, 161, 143, 236, 131, 6, 122, 102, 77, 112, 218,
		33, 150, 25, 237, 108, 73, 167, 124, 172, 188, 196, 121, 247, 55, 62,
		188, 38, 157, 122, 24, 174, 235, 110, 1, 166, 65, 186, 233, 136, 172,
		180, 89, 64, 19, 46, 173, 45, 14, 118, 31, 56, 213, 105, 2, 105, 195,
		102, 144, 229, 70, 3, 62, 53, 148, 159, 108, 236, 146, 90, 207, 133,
		94, 138, 101, 183, 16, 35, 172, 0, 214, 78, 108, 13, 104, 55, 216, 43,
		168, 255, 100, 41, 86, 3, 168, 241, 136, 162, 1, 220, 151, 80, 98, 229,
		104, 100, 159, 137, 17, 24, 101, 213, 203, 27, 165, 214, 118, 204, 139,
		176, 53, 102, 240, 153, 245, 37, 146, 99, 207, 218, 36, 38, 216, 63,
		133, 197, 93, 61, 162, 64, 182, 197, 50, 126, 92, 3, 28, 172, 63, 28,
		223, 42, 169, 151, 62, 98, 84, 142, 63, 45, 75, 241, 43, 172, 32, 198,
		52, 106, 16, 182, 85, 206, 236, 59, 164, 58, 108, 168, 164, 209, 88,
		190, 213, 106, 182, 247, 242, 112, 63, 184, 246, 115, 210, 135, 152,
		78, 168, 43, 200, 154, 119, 239, 215, 156, 59, 65, 246, 58, 57, 43,
		95, 130, 179, 79, 94, 219, 164, 222, 139, 155, 12, 120, 202, 104, 87,
		105, 251, 32, 118, 22, 166, 134, 240, 193, 231, 99, 20, 54, 110, 10,
		31, 203, 67, 71, 124, 184, 251, 84, 243, 160, 108, 225, 163, 233, 238,
		39, 76, 205, 117, 13, 29, 234, 61, 140, 33, 135, 60, 192, 169, 80, 75,
		50, 49, 210, 117, 143, 175, 209, 237, 41, 228, 90, 34, 84, 195, 118,
		176, 169, 71, 214, 199, 128, 227, 248, 211, 131, 27, 38, 247, 68, 10,
		72, 226, 24, 78, 152, 242, 8, 181, 51, 22, 103, 90, 168, 115, 174, 56,
		80, 41, 64, 41, 104, 137, 206, 71, 23, 99, 30, 47, 77, 92, 40, 49, 3,
		79, 195, 31, 193, 38, 90, 226, 81, 244, 178, 101, 77, 10, 136, 45, 73,
		1, 183, 197, 176, 29, 15, 66, 211, 148, 33, 219, 97, 139, 211, 234,
		253, 68, 194, 215, 231, 81, 218, 142, 160, 252, 252, 212, 42, 146, 25,
		28, 227, 140, 81, 202, 212, 140, 63, 12, 82, 214, 222, 76, 13, 194,
		141, 75, 17, 37, 145, 27, 155, 162, 165, 234}

	expectedKmacs := [][]byte{
		{241, 132, 2, 131, 104, 92, 89, 120, 177, 8, 201,
			194, 41, 63, 99, 30, 82, 44, 125, 204, 55, 145, 29, 62, 228, 57,
			55, 208, 221, 195, 73, 50},
		{108, 243, 239, 28, 162, 109, 196, 127, 8, 41, 134, 241, 44, 112, 225,
			90, 138, 107, 6, 41, 123, 210, 194, 241, 176, 240, 35, 70, 196,
			149, 48, 77},
		{102, 155, 236, 6, 96, 155, 93, 100, 25, 38, 132, 2, 109, 216, 56, 157,
			60, 100, 99, 226, 123, 181, 99, 157, 115, 215, 104, 243, 48, 161,
			220, 184},
		{154, 237, 87, 227, 221, 68, 206, 8, 163, 133, 253, 96, 96, 220, 215,
			167, 62, 5, 47, 209, 95, 125, 13, 244, 211, 184, 77, 78, 226, 26,
			24, 239},
		{211, 180, 44, 51, 228, 147, 142, 94, 48, 99, 224, 101, 48, 43, 223, 23,
			231, 0, 11, 229, 126, 247, 202, 97, 149, 163, 107, 68, 120, 251, 158,
			33}}

	cmixGrp := cyclic.NewGroup(
		large.NewIntFromString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16),
		large.NewIntFromString("2", 16))

	prng := rand.New(rand.NewSource(42))

	keys := make([]*key, numKeys)

	for i := 0; i < numKeys; i++ {
		keyBytes, _ := csprng.GenerateInGroup(cmixGrp.GetPBytes(), cmixGrp.GetP().ByteLen(), prng)
		keys[i] = &key{
			k: cmixGrp.NewIntFromBytes(keyBytes),
		}
	}

	salt := make([]byte, 32)
	prng.Read(salt)

	msg := format.NewMessage(cmixGrp.GetP().ByteLen())
	contents := make([]byte, msg.ContentsSize())
	prng.Read(contents)
	msg.SetContents(contents)

	rk := RoundKeys{
		keys: keys,
		g:    cmixGrp,
	}

	encMsg, kmacs := rk.Encrypt(msg, salt)

	if !bytes.Equal(encMsg.Marshal(), expectedPayload) {
		t.Errorf("Encrypted messages do not match\n "+
			"expected: %v\n received: %v", expectedPayload, encMsg.Marshal())
	}

	if !reflect.DeepEqual(kmacs, expectedKmacs) {
		t.Errorf("kmacs do not match")
	}
}
