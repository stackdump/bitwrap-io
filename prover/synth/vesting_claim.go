package synth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("claim", generateVestingClaim)
}

// generateVestingClaim emits VestingClaimCircuit matching
// VestingClaimCircuit in prover/circuits.go:226-287.
//
// Constraint shape:
//   - Role check: `owner == caller` (from Action.Roles = ["owner"]).
//   - Range check from ZKOp (guard uses vestedAmount() which the guard
//     extractor can't compile, so a ZKOp carries BitSize explicitly).
//   - Two parallel Merkle proofs at depth 10 (schedule + owner trees).
//     Composite pre-root = hash(scheduleRoot, ownerRoot).
//   - Post-state: `postLeaf = mimcHash(TokenID, Claimed + ClaimAmount)`.
func generateVestingClaim(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	_ = imports // mimc helper lives in prover/synth_runtime.go

	if !slices.Contains(action.Roles, "owner") {
		return fmt.Errorf("vestingClaim synth: action %q must declare Roles=[owner]", action.ID)
	}

	schedules := schema.StateByID("schedules")
	owners := schema.StateByID("owners")
	if schedules == nil || owners == nil {
		return fmt.Errorf("vestingClaim synth: schema missing 'schedules' or 'owners' state")
	}
	scheduleDepth := schedules.MerkleDepth
	if scheduleDepth == 0 {
		scheduleDepth = 10
	}
	ownerDepth := owners.MerkleDepth
	if ownerDepth == 0 {
		ownerDepth = 10
	}

	rangeBits := rangeCheckBits(action, "claimAmount")
	if rangeBits == 0 {
		rangeBits = 64
	}

	body.WriteString("// VestingClaimCircuit is generated from schema action \"claim\". Parity target: VestingClaimCircuit in prover/circuits.go.\n")
	body.WriteString("type VestingClaimCircuit struct {\n")
	emitStructField(body, "PreStateRoot", true)
	emitStructField(body, "PostStateRoot", true)
	emitStructField(body, "TokenID", true)
	emitStructField(body, "Caller", true)
	emitStructField(body, "ClaimAmount", true)
	body.WriteString("\n")
	emitStructField(body, "VestedAmount", false)
	emitStructField(body, "Claimed", false)
	emitStructField(body, "Owner", false)
	body.WriteString("\n")
	emitMerklePathFields(body, "SchedulePath", "ScheduleIndices", scheduleDepth)
	emitMerklePathFields(body, "OwnerPath", "OwnerIndices", ownerDepth)
	body.WriteString("}\n\n")

	emitDefineHeader(body, "VestingClaimCircuit")
	emitComment(body, "Role check (Action.Roles contains \"owner\")")
	emitAssertEq(body, "c.Owner", "c.Caller")
	body.WriteString("\n")
	emitComment(body, fmt.Sprintf("Range check: available - claimAmount >= 0, %d bits", rangeBits))
	emitSub(body, "available", "c.VestedAmount", "c.Claimed")
	emitSub(body, "diff", "available", "c.ClaimAmount")
	emitRangeCheck(body, "diff", rangeBits)
	body.WriteString("\n")

	emitComment(body, "Schedule Merkle proof")
	emitMimcHashCall(body, "scheduleLeaf", "c.TokenID", "c.VestedAmount")
	body.WriteString("\tcurrent := scheduleLeaf\n")
	body.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", scheduleDepth))
	body.WriteString("\t\tapi.AssertIsBoolean(c.ScheduleIndices[i])\n")
	body.WriteString("\t\tleft := api.Select(c.ScheduleIndices[i], c.SchedulePath[i], current)\n")
	body.WriteString("\t\tright := api.Select(c.ScheduleIndices[i], current, c.SchedulePath[i])\n")
	body.WriteString("\t\tcurrent = synthMimcHash(api, left, right)\n")
	body.WriteString("\t}\n")
	body.WriteString("\tscheduleRoot := current\n\n")

	emitComment(body, "Owner Merkle proof")
	emitMimcHashCall(body, "ownerLeaf", "c.TokenID", "c.Owner")
	body.WriteString("\tcurrent = ownerLeaf\n")
	body.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", ownerDepth))
	body.WriteString("\t\tapi.AssertIsBoolean(c.OwnerIndices[i])\n")
	body.WriteString("\t\tleft := api.Select(c.OwnerIndices[i], c.OwnerPath[i], current)\n")
	body.WriteString("\t\tright := api.Select(c.OwnerIndices[i], current, c.OwnerPath[i])\n")
	body.WriteString("\t\tcurrent = synthMimcHash(api, left, right)\n")
	body.WriteString("\t}\n")
	body.WriteString("\townerRoot := current\n\n")

	emitComment(body, "Composite pre-state root")
	emitMimcHashCall(body, "computedRoot", "scheduleRoot", "ownerRoot")
	emitAssertEq(body, "computedRoot", "c.PreStateRoot")
	body.WriteString("\n")

	emitComment(body, "Post-state: claimed[tokenId] += claimAmount")
	emitAdd(body, "newClaimed", "c.Claimed", "c.ClaimAmount")
	emitMimcHashCall(body, "postLeaf", "c.TokenID", "newClaimed")
	emitAssertEq(body, "postLeaf", "c.PostStateRoot")

	emitDefineFooter(body)
	return nil
}
