package erc

import (
	"github.com/bitwrap-io/bitwrap/internal/arc"
	"github.com/bitwrap-io/bitwrap/internal/metamodel"
)

// ERC020 represents a fungible token template (ERC-20).
type ERC020 struct {
	BaseTemplate
}

// NewERC020 creates a new fungible token template.
func NewERC020(name, symbol string, decimals uint8) *ERC020 {
	schema := metamodel.NewSchema(name)
	schema.Version = "ERC-020:1.0.0"

	schema.AddState(metamodel.State{ID: "totalSupply", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "balances", Type: "map[address]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "allowances", Type: "map[address]map[address]uint256", Exported: true})

	schema.AddAction(metamodel.Action{ID: "transfer", Guard: "balances[from] >= amount && to != address(0)", EventID: "Transfer"})
	schema.AddAction(metamodel.Action{ID: "approve", EventID: "Approve"})
	schema.AddAction(metamodel.Action{ID: "transferFrom", Guard: "balances[from] >= amount && allowances[from][caller] >= amount"})
	schema.AddAction(metamodel.Action{ID: "mint", Guard: "to != address(0)", EventID: "Mint"})
	schema.AddAction(metamodel.Action{ID: "burn", Guard: "balances[from] >= amount", EventID: "Burn"})

	schema.AddArc(metamodel.Arc{Source: "balances", Target: "transfer", Keys: []string{"from"}})
	schema.AddArc(metamodel.Arc{Source: "transfer", Target: "balances", Keys: []string{"to"}})
	schema.AddArc(metamodel.Arc{Source: "approve", Target: "allowances", Keys: []string{"owner", "spender"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "transferFrom", Keys: []string{"from"}})
	schema.AddArc(metamodel.Arc{Source: "allowances", Target: "transferFrom", Keys: []string{"from", "caller"}})
	schema.AddArc(metamodel.Arc{Source: "transferFrom", Target: "balances", Keys: []string{"to"}})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "balances", Keys: []string{"to"}})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "totalSupply"})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "burn", Keys: []string{"from"}})
	schema.AddArc(metamodel.Arc{Source: "totalSupply", Target: "burn"})

	schema.AddEvent(metamodel.Event{ID: "Transfer", Signature: "Transfer(uint256,uint256,address,address,uint256)", Topic: "0x2241a25efee990cbf41182c5b8b2a9e8ff1fcf955ae348d3978a44e371396c36", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "from", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "amount", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Mint", Signature: "Mint(uint256,uint256,address,uint256)", Topic: "0xd9ebada3362b7013882590dab065144bb426bd677acedeff7bfe565c01d104f8", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "to", Type: "address", Indexed: true}, {Name: "amount", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Burn", Signature: "Burn(uint256,uint256,address,uint256)", Topic: "0xf425743f03337ed26b75c5a7d67af831219519d5494ba86024fd56f8270a197f", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "from", Type: "address", Indexed: true}, {Name: "amount", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Approve", Signature: "Approve(uint256,uint256,address,address,uint256)", Topic: "0x8564182643cdabb02bdf8c75c713ba3ebc123121157e7998f0681b5d20de89aa", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "owner", Type: "address", Indexed: true}, {Name: "spender", Type: "address"}, {Name: "amount", Type: "uint256"}}})

	model := arc.FromSchema(schema)
	return &ERC020{BaseTemplate: BaseTemplate{schema: schema, model: model, metadata: TokenMetadata{Name: name, Symbol: symbol, Decimals: decimals, Standard: StandardERC020}, standard: StandardERC020}}
}
