package erc

import (
	"github.com/stackdump/bitwrap-io/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// ERC05725 represents a transferable vesting NFT template.
// This is the metamodel representation of ERC-5725.
//
// States:
//   - schedules: map of tokenId → vesting schedule
//   - owners: map of tokenId → owner address
//   - claimed: map of tokenId → amount claimed
//   - payoutToken: token being vested
//
// Actions:
//   - create: create new vesting NFT
//   - claim: claim vested tokens
//   - transfer: transfer vesting NFT to new owner
//   - burn: burn completed vesting NFT
type ERC05725 struct {
	BaseTemplate
}

// VestingSchedule represents the vesting parameters for a token.
type VestingSchedule struct {
	Start     uint64 // start timestamp
	Cliff     uint64 // cliff timestamp (no vesting before this)
	End       uint64 // end timestamp (fully vested)
	Total     uint64 // total tokens to vest
	Claimed   uint64 // tokens already claimed
	Revocable bool   // can be revoked by creator
	RevokedAt uint64 // timestamp when revoked (0 if not revoked)
}

// NewERC05725 creates a new transferable vesting NFT template.
func NewERC05725(name, symbol, payoutToken string) *ERC05725 {
	schema := metamodel.NewSchema(name)
	schema.Version = "ERC-05725:1.0.0"

	// States
	schema.AddState(metamodel.State{
		ID:   "payoutToken",
		Type: "address",
	})
	schema.AddState(metamodel.State{
		ID:          "schedules",
		Type:        "map[uint256]VestingSchedule",
		MerkleDepth: 10,
	})
	schema.AddState(metamodel.State{
		ID:          "owners",
		Type:        "map[uint256]address",
		MerkleDepth: 10,
	})
	schema.AddState(metamodel.State{
		ID:          "claimed",
		Type:        "map[uint256]uint256",
		MerkleDepth: 10,
	})
	schema.AddState(metamodel.State{
		ID:   "creators",
		Type: "map[uint256]address", // who created each vesting NFT
	})
	schema.AddState(metamodel.State{
		ID:   "totalLocked",
		Type: "uint256", // total tokens locked in vesting
	})
	schema.AddState(metamodel.State{
		ID:      "nextTokenId",
		Type:    "uint256",
		Initial: 1,
	})

	// Actions (with event linkage)
	schema.AddAction(metamodel.Action{
		ID:      "create",
		Guard:   "total > 0 && end > start && beneficiary != address(0)",
		EventID: "VestCreate",
	})
	schema.AddAction(metamodel.Action{
		ID:      "claim",
		Guard:   "vestedAmount(tokenId) > claimed[tokenId]",
		EventID: "VestClaim",
		Roles:   []string{"owner"},
		// Guard uses vestedAmount() which the extractor can't compile,
		// so the range check is declared explicitly as a ZKOp.
		ZKOps: []metamodel.ZKOp{
			{Kind: metamodel.ZKOpRangeCheck, Inputs: []string{"claimAmount"}, BitSize: 64},
		},
	})
	schema.AddAction(metamodel.Action{
		ID:      "transfer",
		Guard:   "owners[tokenId] == from && to != address(0)",
		EventID: "VestTransfer",
	})
	schema.AddAction(metamodel.Action{
		ID:      "revoke",
		Guard:   "creators[tokenId] == caller && schedules[tokenId].revocable && schedules[tokenId].revokedAt == 0",
		EventID: "VestRevoke",
	})
	schema.AddAction(metamodel.Action{
		ID:      "burn",
		Guard:   "owners[tokenId] == caller && claimed[tokenId] >= schedules[tokenId].total",
		EventID: "VestBurn",
	})

	// Arcs for create: schedules[tokenId] = schedule, owners[tokenId] = beneficiary, etc.
	schema.AddArc(metamodel.Arc{Source: "create", Target: "schedules", Keys: []string{"tokenId"}, Value: "schedule"})
	schema.AddArc(metamodel.Arc{Source: "create", Target: "owners", Keys: []string{"tokenId"}, Value: "beneficiary"})
	schema.AddArc(metamodel.Arc{Source: "create", Target: "creators", Keys: []string{"tokenId"}, Value: "caller"})
	schema.AddArc(metamodel.Arc{Source: "create", Target: "totalLocked", Value: "total"})
	schema.AddArc(metamodel.Arc{Source: "nextTokenId", Target: "create"})
	schema.AddArc(metamodel.Arc{Source: "create", Target: "nextTokenId"})

	// Arcs for claim: claimed[tokenId] += claimAmount, totalLocked -= claimAmount
	schema.AddArc(metamodel.Arc{Source: "schedules", Target: "claim", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "claimed", Target: "claim", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "claim", Target: "claimed", Keys: []string{"tokenId"}, Value: "claimAmount"})
	schema.AddArc(metamodel.Arc{Source: "totalLocked", Target: "claim", Value: "claimAmount"})

	// Arcs for transfer: owners[tokenId] = to
	schema.AddArc(metamodel.Arc{Source: "owners", Target: "transfer", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "transfer", Target: "owners", Keys: []string{"tokenId"}, Value: "to"})

	// Arcs for revoke: update schedule with revokedAt
	schema.AddArc(metamodel.Arc{Source: "schedules", Target: "revoke", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "revoke", Target: "schedules", Keys: []string{"tokenId"}, Value: "schedule"})
	schema.AddArc(metamodel.Arc{Source: "totalLocked", Target: "revoke", Value: "unvestedAmount"})

	// Arcs for burn: delete owners[tokenId], schedules[tokenId], etc.
	schema.AddArc(metamodel.Arc{Source: "owners", Target: "burn", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "schedules", Target: "burn", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "claimed", Target: "burn", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "creators", Target: "burn", Keys: []string{"tokenId"}})

	// Events for on-chain sync
	// Must match Solidity: event VestCreate(uint256 epoch, uint256 seq, address indexed caller, address beneficiary, uint256 tokenId, uint256 nftAmount, uint256 total)
	schema.AddEvent(metamodel.Event{
		ID:        "VestCreate",
		Signature: "VestCreate(uint256,uint256,address,address,uint256,uint256,uint256)",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256", Indexed: false},
			{Name: "seq", Type: "uint256", Indexed: false},
			{Name: "caller", Type: "address", Indexed: true},
			{Name: "beneficiary", Type: "address", Indexed: false},
			{Name: "tokenId", Type: "uint256", Indexed: false},
			{Name: "nftAmount", Type: "uint256", Indexed: false},
			{Name: "total", Type: "uint256", Indexed: false},
		},
	})
	// Must match Solidity: event VestClaim(uint256 epoch, uint256 seq, address indexed caller, uint256 tokenId, uint256 claimAmount)
	schema.AddEvent(metamodel.Event{
		ID:        "VestClaim",
		Signature: "VestClaim(uint256,uint256,address,uint256,uint256)",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256", Indexed: false},
			{Name: "seq", Type: "uint256", Indexed: false},
			{Name: "caller", Type: "address", Indexed: true},
			{Name: "tokenId", Type: "uint256", Indexed: false},
			{Name: "claimAmount", Type: "uint256", Indexed: false},
		},
	})
	schema.AddEvent(metamodel.Event{
		ID:        "VestTransfer",
		Signature: "VestTransfer(uint256,uint256,uint256,address,address)",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256", Indexed: false},
			{Name: "seq", Type: "uint256", Indexed: false},
			{Name: "tokenId", Type: "uint256", Indexed: true},
			{Name: "from", Type: "address", Indexed: true},
			{Name: "to", Type: "address", Indexed: true},
		},
	})
	schema.AddEvent(metamodel.Event{
		ID:        "VestRevoke",
		Signature: "VestRevoke(uint256,uint256,uint256,address,uint256,uint256)",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256", Indexed: false},
			{Name: "seq", Type: "uint256", Indexed: false},
			{Name: "tokenId", Type: "uint256", Indexed: true},
			{Name: "revoker", Type: "address", Indexed: true},
			{Name: "revokedAmount", Type: "uint256", Indexed: false},
			{Name: "revokedAt", Type: "uint256", Indexed: false},
		},
	})
	schema.AddEvent(metamodel.Event{
		ID:        "VestBurn",
		Signature: "VestBurn(uint256,uint256,uint256,address)",
		Parameters: []metamodel.EventParameter{
			{Name: "epoch", Type: "uint256", Indexed: false},
			{Name: "seq", Type: "uint256", Indexed: false},
			{Name: "tokenId", Type: "uint256", Indexed: true},
			{Name: "owner", Type: "address", Indexed: true},
		},
	})

	// Convert to Petri net model for backward compatibility
	model := arc.FromSchema(schema)

	return &ERC05725{
		BaseTemplate: BaseTemplate{
			schema: schema,
			model:  model,
			metadata: TokenMetadata{
				Name:     name,
				Symbol:   symbol,
				Standard: StandardERC05725,
			},
			standard: StandardERC05725,
		},
	}
}
