package synth

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("burn", generateBurn)
}

// generateBurn emits BurnSynthCircuit + its Define() method. Mirrors the
// hand-written BurnCircuit in prover/circuits.go:161-199.
//
// Constraint shape:
//   - diff = api.Sub(BalanceFrom, Amount); api.ToBinary(diff, 64)  (range check)
//   - Merkle membership: leaf = mimcHash(From, BalanceFrom) → root == PreStateRoot
//   - Post-state: postLeaf = mimcHash(From, BalanceFrom - Amount) == PostStateRoot
//
// Reads State.MerkleDepth on "balances" (default 20 if unset so existing
// schemas still work).
func generateBurn(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	imports["github.com/consensys/gnark/std/hash/mimc"] = true

	balances := schema.StateByID("balances")
	if balances == nil {
		return fmt.Errorf("burn synth: schema missing 'balances' state")
	}
	depth := balances.MerkleDepth
	if depth == 0 {
		depth = 20 // hand-written default
	}

	rangeBits := rangeCheckBits(action, "amount")
	if rangeBits == 0 {
		rangeBits = 64 // matches hand-written BurnCircuit.api.ToBinary(diff, 64)
	}

	if !strings.Contains(body.String(), "func synthMimcHash") {
		emitMimcHelper(body)
	}

	// Struct declaration — inline because we need both scalar fields and
	// fixed-size array fields in one struct, which emitCircuitStruct doesn't do.
	body.WriteString("// BurnSynthCircuit is generated from schema action \"burn\". Parity target: BurnCircuit in prover/circuits.go.\n")
	body.WriteString("type BurnSynthCircuit struct {\n")
	emitStructField(body, "PreStateRoot", true)
	emitStructField(body, "PostStateRoot", true)
	emitStructField(body, "From", true)
	emitStructField(body, "Amount", true)
	body.WriteString("\n")
	emitStructField(body, "BalanceFrom", false)
	body.WriteString("\n")
	emitMerklePathFields(body, "PathElements", "PathIndices", depth)
	body.WriteString("}\n\n")

	emitDefineHeader(body, "BurnSynthCircuit")
	emitComment(body, fmt.Sprintf("Range check: BalanceFrom - Amount fits in %d bits (non-negative)", rangeBits))
	emitSub(body, "diff", "c.BalanceFrom", "c.Amount")
	emitRangeCheck(body, "diff", rangeBits)
	body.WriteString("\n")
	emitComment(body, "Merkle membership: balances[from] = BalanceFrom at PreStateRoot")
	emitMimcHashCall(body, "leaf", "c.From", "c.BalanceFrom")
	emitMerkleMembership(body, depth, "leaf", "c.PreStateRoot", "PathElements", "PathIndices", "current")
	body.WriteString("\n")
	emitComment(body, "Post-state: balances[from] decremented")
	emitSub(body, "newBalance", "c.BalanceFrom", "c.Amount")
	emitMimcHashCall(body, "postLeaf", "c.From", "newBalance")
	emitAssertEq(body, "postLeaf", "c.PostStateRoot")
	emitDefineFooter(body)

	return nil
}

// rangeCheckBits looks through action.ZKOps for a range-check on the given
// field name and returns its BitSize, or 0 if not found.
func rangeCheckBits(action *metamodel.Action, fieldName string) int {
	for _, op := range action.ZKOps {
		if op.Kind != metamodel.ZKOpRangeCheck {
			continue
		}
		for _, in := range op.Inputs {
			if in == fieldName {
				return op.BitSize
			}
		}
	}
	return 0
}
