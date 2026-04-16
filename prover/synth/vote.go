package synth

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

func init() {
	register("castVote", generateVoteCast)
}

// generateVoteCast emits VoteCastCircuit matching VoteCastCircuit in
// prover/circuits.go:296-343.
//
// Uses the ZKOp extension point for ZK primitives that aren't arc-derivable:
//   - NullifierBind(voterSecret, pollId → nullifier): asserts
//     Nullifier == mimcHash(VoterSecret, PollID).
//   - CommitmentBind(voterSecret, voteChoice → voteCommitment): asserts
//     VoteCommitment == mimcHash(VoterSecret, VoteChoice).
//   - RangeCheck(voteChoice, BitSize=8) + implicit MaxChoices bound.
//
// Also emits the Merkle membership proof on voterRegistry (leaf hashed
// from voterSecret + voterWeight). Note: the voterRegistry arc is
// implicit — the schema says "verified via ZK proof, not via on-chain
// arc" (erc/vote.go:34), so we read MerkleDepth from the state directly.
func generateVoteCast(body *strings.Builder, schema *metamodel.Schema, action *metamodel.Action, imports map[string]bool) error {
	_ = imports // mimc helper lives in prover/synth_runtime.go

	registry := stateByIDCI(schema, "voterRegistry")
	if registry == nil {
		return fmt.Errorf("voteCast synth: schema missing 'voterRegistry' state")
	}
	depth := registry.MerkleDepth
	if depth == 0 {
		depth = 20
	}

	// Locate ZKOps by kind so we know what obligations to emit.
	var nullifierOp, commitmentOp *metamodel.ZKOp
	var choiceBits int
	for i := range action.ZKOps {
		op := &action.ZKOps[i]
		switch op.Kind {
		case metamodel.ZKOpNullifierBind:
			nullifierOp = op
		case metamodel.ZKOpCommitmentBind:
			commitmentOp = op
		case metamodel.ZKOpRangeCheck:
			for _, in := range op.Inputs {
				if in == "voteChoice" {
					choiceBits = op.BitSize
				}
			}
		}
	}
	if nullifierOp == nil {
		return fmt.Errorf("voteCast synth: action must declare NullifierBind ZKOp")
	}
	if commitmentOp == nil {
		return fmt.Errorf("voteCast synth: action must declare CommitmentBind ZKOp")
	}
	if choiceBits == 0 {
		choiceBits = 8
	}

	body.WriteString("// VoteCastCircuit is generated from schema action \"castVote\". Parity target: VoteCastCircuit in prover/circuits.go.\n")
	body.WriteString("type VoteCastCircuit struct {\n")
	emitStructField(body, "PollID", true)
	emitStructField(body, "VoterRegistryRoot", true)
	emitStructField(body, "Nullifier", true)
	emitStructField(body, "VoteCommitment", true)
	emitStructField(body, "MaxChoices", true)
	body.WriteString("\n")
	emitStructField(body, "VoterSecret", false)
	emitStructField(body, "VoteChoice", false)
	emitStructField(body, "VoterWeight", false)
	body.WriteString("\n")
	emitMerklePathFields(body, "PathElements", "PathIndices", depth)
	body.WriteString("}\n\n")

	emitDefineHeader(body, "VoteCastCircuit")
	emitComment(body, "1. Merkle membership: leaf = mimcHash(voterSecret, voterWeight) → VoterRegistryRoot")
	emitMimcHashCall(body, "leaf", "c.VoterSecret", "c.VoterWeight")
	body.WriteString("\tcurrent := leaf\n")
	body.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", depth))
	body.WriteString("\t\tapi.AssertIsBoolean(c.PathIndices[i])\n")
	body.WriteString("\t\tleft := api.Select(c.PathIndices[i], c.PathElements[i], current)\n")
	body.WriteString("\t\tright := api.Select(c.PathIndices[i], current, c.PathElements[i])\n")
	body.WriteString("\t\tcurrent = synthMimcHash(api, left, right)\n")
	body.WriteString("\t}\n")
	emitAssertEq(body, "current", "c.VoterRegistryRoot")
	body.WriteString("\n")

	emitComment(body, fmt.Sprintf("2. NullifierBind ZKOp: %s == hash(%s)",
		capitalize(nullifierOp.Output), strings.Join(nullifierOp.Inputs, ", ")))
	emitMimcHashCall(body, "expectedNullifier",
		"c."+capitalize(nullifierOp.Inputs[0]),
		"c."+capitalize(nullifierOp.Inputs[1]))
	emitAssertEq(body, "c."+capitalize(nullifierOp.Output), "expectedNullifier")
	body.WriteString("\n")

	emitComment(body, fmt.Sprintf("3. Range check: VoteChoice fits in %d bits and < MaxChoices", choiceBits))
	emitRangeCheck(body, "c.VoteChoice", choiceBits)
	emitSub(body, "diff", "c.MaxChoices", "c.VoteChoice")
	emitSub(body, "diffMinusOne", "diff", "1")
	emitRangeCheck(body, "diffMinusOne", choiceBits)
	body.WriteString("\n")

	emitComment(body, fmt.Sprintf("4. CommitmentBind ZKOp: %s == hash(%s)",
		capitalize(commitmentOp.Output), strings.Join(commitmentOp.Inputs, ", ")))
	emitMimcHashCall(body, "expectedCommitment",
		"c."+capitalize(commitmentOp.Inputs[0]),
		"c."+capitalize(commitmentOp.Inputs[1]))
	emitAssertEq(body, "c."+capitalize(commitmentOp.Output), "expectedCommitment")

	emitDefineFooter(body)
	return nil
}
