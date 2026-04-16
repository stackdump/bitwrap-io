package synth

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("transfer", generateTransfer)
}

// generateTransfer emits TransferCircuit matching TransferCircuit in
// prover/circuits.go:20-65. The interesting new pattern vs Burn: the
// post-state is a pair-hash composition of two output-arc leaves
// (decremented From + incremented To) rather than a single leaf.
//
// Range check comes from Action.Guard "balances[from] >= amount" via the
// 2.3 guard compiler. The `to != address(0)` conjunct is correctly ignored
// (non-ZK, enforced on-chain).
func generateTransfer(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	_ = imports // mimc helper lives in prover/synth_runtime.go
	balances := stateByIDCI(schema, "balances")
	if balances == nil {
		return fmt.Errorf("transfer synth: schema missing 'balances' state")
	}
	depth := balances.MerkleDepth
	if depth == 0 {
		depth = 20
	}

	guardChecks, err := extractRangeChecks(action, 64)
	if err != nil {
		return fmt.Errorf("transfer synth: guard extract: %w", err)
	}

	if !strings.Contains(body.String(), "func synthMimcHash") {
		emitMimcHelper(body)
	}

	body.WriteString("// TransferCircuit is generated from schema action \"transfer\". Parity target: TransferCircuit in prover/circuits.go.\n")
	body.WriteString("type TransferCircuit struct {\n")
	emitStructField(body, "PreStateRoot", true)
	emitStructField(body, "PostStateRoot", true)
	emitStructField(body, "From", true)
	emitStructField(body, "To", true)
	emitStructField(body, "Amount", true)
	body.WriteString("\n")
	emitStructField(body, "BalanceFrom", false)
	emitStructField(body, "BalanceTo", false)
	body.WriteString("\n")
	emitMerklePathFields(body, "PathElements", "PathIndices", depth)
	body.WriteString("}\n\n")

	emitDefineHeader(body, "TransferCircuit")
	if len(guardChecks) > 0 {
		emitComment(body, fmt.Sprintf("Range checks from Action.Guard %q", action.Guard))
		for i, chk := range guardChecks {
			name := "diff"
			if i > 0 {
				name = fmt.Sprintf("diff%d", i)
			}
			chk.emit(body, name)
		}
	}
	body.WriteString("\n")

	emitComment(body, "Merkle membership: balances[from] = BalanceFrom at PreStateRoot")
	emitMimcHashCall(body, "leaf", "c.From", "c.BalanceFrom")
	emitMerkleMembership(body, depth, "leaf", "c.PreStateRoot", "PathElements", "PathIndices", "current")
	body.WriteString("\n")

	emitComment(body, "Post-state: composite hash of decremented from + incremented to leaves")
	emitSub(body, "newBalanceFrom", "c.BalanceFrom", "c.Amount")
	emitAdd(body, "newBalanceTo", "c.BalanceTo", "c.Amount")
	emitMimcHashCall(body, "postLeaf", "c.From", "newBalanceFrom")
	emitMimcHashCall(body, "postLeaf2", "c.To", "newBalanceTo")
	emitMimcHashCall(body, "computedPost", "postLeaf", "postLeaf2")
	emitAssertEq(body, "computedPost", "c.PostStateRoot")

	emitDefineFooter(body)
	return nil
}
