package synth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("mint", generateMint)
}

// generateMint emits MintCircuit + its Define() method. Mirrors the
// hand-written MintCircuit in prover/circuits.go:136-159 so the two can be
// compared via parity fuzz tests.
//
// Constraint shape (for reference — keep this comment synced with reality):
//   - api.AssertIsEqual(Caller, Minter)              // from Action.Roles = ["minter"]
//   - newBalance := api.Add(BalanceTo, Amount)       // from output arc mint → balances[to]
//   - postLeaf := mimcHash(To, newBalance)
//   - api.AssertIsEqual(postLeaf, PostStateRoot)
//
// PreStateRoot is declared public but unused (matches hand-written version
// exactly — removing it would change the verifying key).
func generateMint(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	_ = imports // mimc helper now lives in prover/synth_runtime.go

	// Role check for minter — only emit if declared in schema metadata.
	if !slices.Contains(action.Roles, "minter") {
		return fmt.Errorf("mint synth: action %q must declare Roles=[minter] (got %v)", action.ID, action.Roles)
	}

	// Emit MiMC helper on first generator call per file. Since we only have
	// one generator for now, this is unconditional. Subsequent slices will
	// track "helper already emitted" state on the builder.
	if !strings.Contains(body.String(), "func synthMimcHash") {
		emitMimcHelper(body)
	}

	public := []string{"PreStateRoot", "PostStateRoot", "Caller", "To", "Amount"}
	private := []string{"Minter", "BalanceTo"}

	emitCircuitStruct(body, "MintCircuit",
		"MintCircuit is generated from schema action \"mint\". Parity target: MintCircuit in prover/circuits.go.",
		public, private)

	emitDefineHeader(body, "MintCircuit")
	emitComment(body, "Role check (Action.Roles contains \"minter\")")
	emitAssertEq(body, "c.Caller", "c.Minter")
	emitComment(body, "Output arc: balances[to] += amount")
	emitAdd(body, "newBalance", "c.BalanceTo", "c.Amount")
	emitMimcHashCall(body, "postLeaf", "c.To", "newBalance")
	emitAssertEq(body, "postLeaf", "c.PostStateRoot")
	emitDefineFooter(body)

	return nil
}
