package erc

import (
	"github.com/stackdump/bitwrap-io/internal/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// ERC0721 represents a non-fungible token template (ERC-721).
type ERC0721 struct {
	BaseTemplate
}

// NewERC0721 creates a new non-fungible token template.
func NewERC0721(name, symbol string) *ERC0721 {
	schema := metamodel.NewSchema(name)
	schema.Version = "ERC-0721:1.0.0"

	schema.AddState(metamodel.State{ID: "owners", Type: "map[uint256]address", Exported: true})
	schema.AddState(metamodel.State{ID: "approved", Type: "map[uint256]address"})
	schema.AddState(metamodel.State{ID: "operators", Type: "map[address]map[address]bool"})
	schema.AddState(metamodel.State{ID: "balances", Type: "map[address]uint256"})

	schema.AddAction(metamodel.Action{ID: "transferFrom", Guard: "owners[tokenId] == from && (caller == from || approved[tokenId] == caller || operators[from][caller])", EventID: "Transfer"})
	schema.AddAction(metamodel.Action{ID: "approve", Guard: "owners[tokenId] == caller || operators[owners[tokenId]][caller]", EventID: "Approval"})
	schema.AddAction(metamodel.Action{ID: "setApprovalForAll", EventID: "ApprovalForAll"})
	schema.AddAction(metamodel.Action{ID: "mint", Guard: "owners[tokenId] == address(0)", EventID: "Mint"})
	schema.AddAction(metamodel.Action{ID: "burn", Guard: "owners[tokenId] == caller || approved[tokenId] == caller || operators[owners[tokenId]][caller]", EventID: "Burn"})

	schema.AddArc(metamodel.Arc{Source: "owners", Target: "transferFrom", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "transferFrom", Target: "owners", Keys: []string{"tokenId"}, Value: "to"})
	schema.AddArc(metamodel.Arc{Source: "approved", Target: "transferFrom", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "transferFrom", Keys: []string{"from"}})
	schema.AddArc(metamodel.Arc{Source: "transferFrom", Target: "balances", Keys: []string{"to"}})
	schema.AddArc(metamodel.Arc{Source: "approve", Target: "approved", Keys: []string{"tokenId"}, Value: "approved"})
	schema.AddArc(metamodel.Arc{Source: "setApprovalForAll", Target: "operators", Keys: []string{"owner", "operator"}, Value: "approved"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "owners", Keys: []string{"tokenId"}, Value: "to"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "balances", Keys: []string{"to"}})
	schema.AddArc(metamodel.Arc{Source: "owners", Target: "burn", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "burn", Keys: []string{"from"}})

	schema.AddEvent(metamodel.Event{ID: "Transfer", Signature: "Transfer(uint256,uint256,address,address,uint256)", Topic: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "from", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "tokenId", Type: "uint256", Indexed: true}}})
	schema.AddEvent(metamodel.Event{ID: "Approval", Signature: "Approval(uint256,uint256,address,address,uint256)", Topic: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "owner", Type: "address", Indexed: true}, {Name: "approved", Type: "address", Indexed: true}, {Name: "tokenId", Type: "uint256", Indexed: true}}})
	schema.AddEvent(metamodel.Event{ID: "ApprovalForAll", Signature: "ApprovalForAll(uint256,uint256,address,address,bool)", Topic: "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "owner", Type: "address", Indexed: true}, {Name: "operator", Type: "address", Indexed: true}, {Name: "approved", Type: "bool"}}})
	schema.AddEvent(metamodel.Event{ID: "Mint", Signature: "Mint(uint256,uint256,address,uint256)", Topic: "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "to", Type: "address", Indexed: true}, {Name: "tokenId", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Burn", Signature: "Burn(uint256,uint256,address,uint256)", Topic: "0xcc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "from", Type: "address", Indexed: true}, {Name: "tokenId", Type: "uint256"}}})

	model := arc.FromSchema(schema)
	return &ERC0721{BaseTemplate: BaseTemplate{schema: schema, model: model, metadata: TokenMetadata{Name: name, Symbol: symbol, Standard: StandardERC0721}, standard: StandardERC0721}}
}
