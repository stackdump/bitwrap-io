package erc

import (
	"github.com/stackdump/bitwrap-io/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// ERC01155 represents a multi-token template (ERC-1155).
type ERC01155 struct {
	BaseTemplate
}

// NewERC01155 creates a new multi-token template.
func NewERC01155(name string) *ERC01155 {
	schema := metamodel.NewSchema(name)
	schema.Version = "ERC-01155:1.0.0"

	schema.AddState(metamodel.State{ID: "balances", Type: "map[uint256]map[address]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "operators", Type: "map[address]map[address]bool"})

	schema.AddAction(metamodel.Action{ID: "safeTransferFrom", Guard: "balances[id][from] >= amount && (caller == from || operators[from][caller])", EventID: "TransferSingle"})
	schema.AddAction(metamodel.Action{ID: "safeBatchTransferFrom", Guard: "caller == from || operators[from][caller]", EventID: "TransferBatch"})
	schema.AddAction(metamodel.Action{ID: "setApprovalForAll", EventID: "ApprovalForAll"})
	schema.AddAction(metamodel.Action{ID: "mint", EventID: "Mint"})
	schema.AddAction(metamodel.Action{ID: "mintBatch", EventID: "MintBatch"})
	schema.AddAction(metamodel.Action{ID: "burn", Guard: "balances[id][from] >= amount && (caller == from || operators[from][caller])", EventID: "Burn"})
	schema.AddAction(metamodel.Action{ID: "burnBatch", Guard: "caller == from || operators[from][caller]", EventID: "BurnBatch"})

	schema.AddArc(metamodel.Arc{Source: "balances", Target: "safeTransferFrom", Keys: []string{"id", "from"}})
	schema.AddArc(metamodel.Arc{Source: "safeTransferFrom", Target: "balances", Keys: []string{"id", "to"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "safeBatchTransferFrom", Keys: []string{"id", "from"}})
	schema.AddArc(metamodel.Arc{Source: "safeBatchTransferFrom", Target: "balances", Keys: []string{"id", "to"}})
	schema.AddArc(metamodel.Arc{Source: "setApprovalForAll", Target: "operators", Keys: []string{"owner", "operator"}, Value: "isApproved"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "balances", Keys: []string{"id", "to"}})
	schema.AddArc(metamodel.Arc{Source: "mintBatch", Target: "balances", Keys: []string{"id", "to"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "burn", Keys: []string{"id", "from"}})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "burnBatch", Keys: []string{"id", "from"}})

	schema.AddEvent(metamodel.Event{ID: "TransferSingle", Signature: "TransferSingle(uint256,uint256,address,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "from", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "id", Type: "uint256"}, {Name: "value", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "TransferBatch", Signature: "TransferBatch(uint256,uint256,address,address,address,uint256[],uint256[])", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "from", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "ids", Type: "uint256[]"}, {Name: "values", Type: "uint256[]"}}})
	schema.AddEvent(metamodel.Event{ID: "ApprovalForAll", Signature: "ApprovalForAll(uint256,uint256,address,address,bool)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "account", Type: "address", Indexed: true}, {Name: "operator", Type: "address", Indexed: true}, {Name: "approved", Type: "bool"}}})
	schema.AddEvent(metamodel.Event{ID: "Mint", Signature: "Mint(uint256,uint256,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "id", Type: "uint256"}, {Name: "value", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "MintBatch", Signature: "MintBatch(uint256,uint256,address,address,uint256[],uint256[])", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "to", Type: "address", Indexed: true}, {Name: "ids", Type: "uint256[]"}, {Name: "values", Type: "uint256[]"}}})
	schema.AddEvent(metamodel.Event{ID: "Burn", Signature: "Burn(uint256,uint256,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "from", Type: "address", Indexed: true}, {Name: "id", Type: "uint256"}, {Name: "value", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "BurnBatch", Signature: "BurnBatch(uint256,uint256,address,address,uint256[],uint256[])", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "operator", Type: "address", Indexed: true}, {Name: "from", Type: "address", Indexed: true}, {Name: "ids", Type: "uint256[]"}, {Name: "values", Type: "uint256[]"}}})

	model := arc.FromSchema(schema)
	return &ERC01155{BaseTemplate: BaseTemplate{schema: schema, model: model, metadata: TokenMetadata{Name: name, Standard: StandardERC01155}, standard: StandardERC01155}}
}
