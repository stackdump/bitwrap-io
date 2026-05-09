package prover

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	tedhints "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// TestHintIDsNative — compare to WASM's HINT name=... id=... output.
// Mismatch ⇒ the cs's hint references won't resolve to the right
// implementation in WASM.
func TestHintIDsNative(t *testing.T) {
	for _, h := range tedhints.GetHints() {
		t.Log(fmt.Sprintf("HINT name=%s id=%d", solver.GetHintName(h), uint32(solver.GetHintID(h))))
	}
}
