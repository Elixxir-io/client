package globals

import (
	"testing"
	"gitlab.com/privategrity/crypto/cyclic"
)

// Smoke test for MakeInitVect
func TestMakeInitVect(t *testing.T) {
	InitCrypto()
	tests := 100
	min := cyclic.NewInt(2)
	max := cyclic.NewIntFromString("7FFFFFFFFFFFFFFFFF", 16)
	for i := 0; i < tests; i++ {
		rand := MakeInitVect(cyclic.NewInt(0))
		if rand.Cmp(min) < 0 || rand.Cmp(max) >= 0 {
			t.Error("MakeInitVector is out of range.")
		}
	}
}