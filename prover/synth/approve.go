package synth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("approve", generateApprove)
}

// generateApprove emits ApproveSynthCircuit matching ApproveCircuit in
// prover/circuits.go:201-223. The simplest role-gated transition: no
// Merkle proof, one equality constraint (`caller == owner`), one post-
// state hash (`postLeaf = mimcHash(Spender, Amount)`).
//
// Requires Action.Roles = ["owner"] in the schema so the synthesizer
// knows which role to bind.
func generateApprove(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	_ = imports // mimc helper lives in prover/synth_runtime.go
	if !slices.Contains(action.Roles, "owner") {
		return fmt.Errorf("approve synth: action %q must declare Roles=[owner] (got %v)", action.ID, action.Roles)
	}

	if !strings.Contains(body.String(), "func synthMimcHash") {
		emitMimcHelper(body)
	}

	public := []string{"PreStateRoot", "PostStateRoot", "Caller", "Spender", "Amount"}
	private := []string{"Owner"}

	emitCircuitStruct(body, "ApproveSynthCircuit",
		"ApproveSynthCircuit is generated from schema action \"approve\". Parity target: ApproveCircuit in prover/circuits.go.",
		public, private)

	emitDefineHeader(body, "ApproveSynthCircuit")
	emitComment(body, "Role check (Action.Roles contains \"owner\")")
	emitAssertEq(body, "c.Owner", "c.Caller")
	emitComment(body, "Output arc: allowances[spender] = amount")
	emitMimcHashCall(body, "postLeaf", "c.Spender", "c.Amount")
	emitAssertEq(body, "postLeaf", "c.PostStateRoot")
	emitDefineFooter(body)
	return nil
}
