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
	schema.AddState(metamodel.State{ID: "voterRegistry", Type: "map[uint256]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "nullifiers", Type: "map[uint256]bool", Exported: true})
	schema.AddState(metamodel.State{ID: "tallies", Type: "map[uint256]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "pollConfig", Type: "uint256"})

	// Actions
	schema.AddAction(metamodel.Action{ID: "createPoll", Guard: "pollConfig == 0", EventID: "PollCreated"})
	schema.AddAction(metamodel.Action{ID: "castVote", Guard: "pollConfig == 1 && nullifiers[nullifier] == false", EventID: "VoteCast"})
	schema.AddAction(metamodel.Action{ID: "closePoll", Guard: "pollConfig == 1", EventID: "PollClosed"})

	// Arcs
	// castVote -> tallies (each vote counts as 1)
	schema.AddArc(metamodel.Arc{Source: "castVote", Target: "tallies", Keys: []string{"choice"}, Value: "1"})
	// castVote -> nullifiers (mark nullifier as used to prevent double-voting)
	schema.AddArc(metamodel.Arc{Source: "castVote", Target: "nullifiers", Keys: []string{"nullifier"}, Value: "true"})
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
