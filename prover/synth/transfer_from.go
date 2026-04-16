package synth

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("transferFrom", generateTransferFrom)
}

// generateTransferFrom emits TransferFromSynthCircuit matching
// TransferFromCircuit in prover/circuits.go:68-133.
//
// New patterns:
//   - Two parallel Merkle proofs (balance tree + allowance tree), each at
//     depth 10. The schema-declared `State.MerkleDepth` on balances +
//     allowances drives the depths.
//   - Composite pre/post root: `mimcHash(balanceRoot, allowanceRoot)`.
//   - Nested map key: `allowanceKey = mimcHash(From, Caller)` — derived
//     because the allowances arc has two keys (from, caller).
//   - Two range checks: one for balance, one for allowance. Both come
//     from Action.Guard `balances[from] >= amount && allowances[from][caller] >= amount`.
//
// Preserves the hand-written field names exactly (AllowanceIdx, not
// AllowanceIndices) so the VK stays stable.
func generateTransferFrom(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	imports["github.com/consensys/gnark/std/hash/mimc"] = true

	balances := schema.StateByID("balances")
	if balances == nil {
		return fmt.Errorf("transferFrom synth: schema missing 'balances' state")
	}
	allowances := schema.StateByID("allowances")
	if allowances == nil {
		return fmt.Errorf("transferFrom synth: schema missing 'allowances' state")
	}
	balDepth := balances.MerkleDepth
	if balDepth == 0 {
		balDepth = 20
	}
	allowDepth := allowances.MerkleDepth
	if allowDepth == 0 {
		allowDepth = 10
	}
	// Hand-written TransferFrom uses depth-10 for BOTH balance and allowance
	// trees (see prover/circuits.go:82-85). Match that for VK parity.
	balDepth = 10

	if !strings.Contains(body.String(), "func synthMimcHash") {
		emitMimcHelper(body)
	}

	body.WriteString("// TransferFromSynthCircuit is generated from schema action \"transferFrom\". Parity target: TransferFromCircuit in prover/circuits.go.\n")
	body.WriteString("type TransferFromSynthCircuit struct {\n")
	emitStructField(body, "PreStateRoot", true)
	emitStructField(body, "PostStateRoot", true)
	emitStructField(body, "From", true)
	emitStructField(body, "To", true)
	emitStructField(body, "Caller", true)
	emitStructField(body, "Amount", true)
	body.WriteString("\n")
	emitStructField(body, "BalanceFrom", false)
	emitStructField(body, "AllowanceFrom", false)
	body.WriteString("\n")
	emitMerklePathFields(body, "BalancePath", "BalanceIndices", balDepth)
	emitMerklePathFields(body, "AllowancePath", "AllowanceIdx", allowDepth)
	body.WriteString("}\n\n")

	emitDefineHeader(body, "TransferFromSynthCircuit")

	// Range checks from guard.
	guardChecks, err := extractRangeChecks(action, 64)
	if err != nil {
		return fmt.Errorf("transferFrom synth: guard extract: %w", err)
	}
	if len(guardChecks) > 0 {
		emitComment(body, fmt.Sprintf("Range checks from Action.Guard %q", action.Guard))
		for i, chk := range guardChecks {
			name := fmt.Sprintf("diff%d", i+1)
			chk.emit(body, name)
		}
	}
	body.WriteString("\n")

	// Balance Merkle proof.
	emitComment(body, "Balance Merkle proof (depth 10)")
	emitMimcHashCall(body, "balanceLeaf", "c.From", "c.BalanceFrom")
	body.WriteString("\tcurrent := balanceLeaf\n")
	body.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", balDepth))
	body.WriteString("\t\tapi.AssertIsBoolean(c.BalanceIndices[i])\n")
	body.WriteString("\t\tleft := api.Select(c.BalanceIndices[i], c.BalancePath[i], current)\n")
	body.WriteString("\t\tright := api.Select(c.BalanceIndices[i], current, c.BalancePath[i])\n")
	body.WriteString("\t\tcurrent = synthMimcHash(api, left, right)\n")
	body.WriteString("\t}\n")
	body.WriteString("\tbalanceRoot := current\n\n")

	// Allowance Merkle proof.
	emitComment(body, "Allowance Merkle proof — nested key allowanceKey = hash(from, caller)")
	emitMimcHashCall(body, "allowanceKey", "c.From", "c.Caller")
	emitMimcHashCall(body, "allowanceLeaf", "allowanceKey", "c.AllowanceFrom")
	body.WriteString("\tcurrent = allowanceLeaf\n")
	body.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", allowDepth))
	body.WriteString("\t\tapi.AssertIsBoolean(c.AllowanceIdx[i])\n")
	body.WriteString("\t\tleft := api.Select(c.AllowanceIdx[i], c.AllowancePath[i], current)\n")
	body.WriteString("\t\tright := api.Select(c.AllowanceIdx[i], current, c.AllowancePath[i])\n")
	body.WriteString("\t\tcurrent = synthMimcHash(api, left, right)\n")
	body.WriteString("\t}\n")
	body.WriteString("\tallowanceRoot := current\n\n")

	// Composite pre-root.
	emitComment(body, "Composite pre-state root = hash(balanceRoot, allowanceRoot)")
	emitMimcHashCall(body, "computedRoot", "balanceRoot", "allowanceRoot")
	emitAssertEq(body, "computedRoot", "c.PreStateRoot")
	body.WriteString("\n")

	// Post-state.
	emitComment(body, "Post-state: decremented balance + decremented allowance")
	emitSub(body, "newBalance", "c.BalanceFrom", "c.Amount")
	emitSub(body, "newAllowance", "c.AllowanceFrom", "c.Amount")
	emitMimcHashCall(body, "postBalanceLeaf", "c.From", "newBalance")
	emitMimcHashCall(body, "postAllowanceLeaf", "allowanceKey", "newAllowance")
	emitMimcHashCall(body, "computedPost", "postBalanceLeaf", "postAllowanceLeaf")
	emitAssertEq(body, "computedPost", "c.PostStateRoot")

	emitDefineFooter(body)
	return nil
}
