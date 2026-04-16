package erc

import (
	"github.com/stackdump/bitwrap-io/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// Vote represents a ZK Poll voting template.
type Vote struct {
	BaseTemplate
}

// NewVote creates a new ZK Poll voting template.
func NewVote(name string) *Vote {
	schema := metamodel.NewSchema(name)
	schema.Version = "Vote:1.0.0"

	// States
	schema.AddState(metamodel.State{ID: "voterRegistry", Type: "map[uint256]uint256", Exported: true, MerkleDepth: 20})
	schema.AddState(metamodel.State{ID: "nullifiers", Type: "map[uint256]bool", Exported: true})
	schema.AddState(metamodel.State{ID: "tallies", Type: "map[uint256]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "pollConfig", Type: "uint256"})
	// registrySlots tracks how many registered voters have not yet cast a
	// vote. It's a TokenState so rt.Enabled("castVote") gates on it
	// automatically — each registerVoter produces a slot, each castVote
	// consumes one. Mirrors the voterRegistry semantics for the runtime
	// while leaving voterRegistry (DataState, Merkle-backed) as the
	// ZK-proof witness surface.
	schema.AddState(metamodel.State{ID: "registrySlots", Kind: metamodel.TokenState, Type: "int"})

	// Actions
	schema.AddAction(metamodel.Action{ID: "createPoll", Guard: "pollConfig == 0", EventID: "PollCreated"})
	schema.AddAction(metamodel.Action{ID: "registerVoter"})
	// castVote's ZK obligations aren't arc-expressible — the nullifier and
	// voteCommitment are keyed hash derivations the synthesizer must emit
	// as explicit constraints.
	schema.AddAction(metamodel.Action{
		ID:      "castVote",
		Guard:   "pollConfig == 1 && nullifiers[nullifier] == false",
		EventID: "VoteCast",
		ZKOps: []metamodel.ZKOp{
			{Kind: metamodel.ZKOpNullifierBind, Inputs: []string{"voterSecret", "pollId"}, Output: "nullifier"},
			{Kind: metamodel.ZKOpCommitmentBind, Inputs: []string{"voterSecret", "voteChoice"}, Output: "voteCommitment"},
			{Kind: metamodel.ZKOpRangeCheck, Inputs: []string{"voteChoice"}, BitSize: 8},
		},
	})
	schema.AddAction(metamodel.Action{ID: "closePoll", Guard: "pollConfig == 1", EventID: "PollClosed"})

	// Arcs
	// castVote -> tallies (increment vote count for chosen option)
	schema.AddArc(metamodel.Arc{Source: "castVote", Target: "tallies", Keys: []string{"choice"}, Value: "weight"})
	// castVote -> nullifiers (mark nullifier as used — weight=1 means "set to 1/true")
	schema.AddArc(metamodel.Arc{Source: "castVote", Target: "nullifiers", Keys: []string{"nullifier"}, Value: "weight"})
	// registrySlots token flow: registerVoter produces one, castVote consumes
	// one. rt.Enabled("castVote") returns false when slots are exhausted —
	// this is what the handler will check, replacing the phase-1 event-count
	// exhaustion gate.
	schema.AddArc(metamodel.Arc{Source: "registerVoter", Target: "registrySlots"})
	schema.AddArc(metamodel.Arc{Source: "registrySlots", Target: "castVote"})
	// Note: voterRegistry is verified via ZK proof (Merkle inclusion), not via on-chain arc

	// Events
	schema.AddEvent(metamodel.Event{
		ID:        "PollCreated",
		Signature: "PollCreated(uint256,uint256,uint256)",
		Topic:     "0x1c9c94bf784c3abe5ad5e8f368e489aad039ae0b4efcf53f28d01c8e1f8e0e4a",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256"},
			{Name: "seq", Type: "uint256"},
			{Name: "pollId", Type: "uint256", Indexed: true},
		},
	})
	schema.AddEvent(metamodel.Event{
		ID:        "VoteCast",
		Signature: "VoteCast(uint256,uint256,uint256,uint256)",
		Topic:     "0x3a4d2e8dd6e4076b2f2e9e3b6dbde64e1df44c23e6f5c4e8b19a76c38d4f1b2d",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256"},
			{Name: "seq", Type: "uint256"},
			{Name: "nullifier", Type: "uint256", Indexed: true},
			{Name: "choice", Type: "uint256"},
		},
	})
	schema.AddEvent(metamodel.Event{
		ID:        "PollClosed",
		Signature: "PollClosed(uint256,uint256,uint256)",
		Topic:     "0x5e2f8a95e5b3c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256"},
			{Name: "seq", Type: "uint256"},
			{Name: "pollId", Type: "uint256", Indexed: true},
		},
	})

	model := arc.FromSchema(schema)
	return &Vote{BaseTemplate: BaseTemplate{
		schema:   schema,
		model:    model,
		metadata: TokenMetadata{Name: name, Symbol: "VOTE", Standard: StandardVote},
		standard: StandardVote,
	}}
}
