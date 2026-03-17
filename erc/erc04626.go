package erc

import (
	"github.com/stackdump/bitwrap-io/internal/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// ERC04626 represents a tokenized vault template (ERC-4626).
type ERC04626 struct {
	BaseTemplate
}

// NewERC04626 creates a new tokenized vault template.
func NewERC04626(name, assetName string) *ERC04626 {
	schema := metamodel.NewSchema(name)
	schema.Version = "ERC-04626:1.0.0"

	schema.AddState(metamodel.State{ID: "asset", Type: "address"})
	schema.AddState(metamodel.State{ID: "totalAssets", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "totalShares", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "balances", Type: "map[address]uint256"})
	schema.AddState(metamodel.State{ID: "assetBalances", Type: "map[address]uint256"})

	schema.AddAction(metamodel.Action{ID: "deposit", Guard: "assets > 0 && receiver != address(0)", EventID: "Deposit"})
	schema.AddAction(metamodel.Action{ID: "mint", Guard: "shares > 0 && receiver != address(0)", EventID: "Mint"})
	schema.AddAction(metamodel.Action{ID: "withdraw", Guard: "assets > 0 && assets <= maxWithdraw(owner) && receiver != address(0)", EventID: "Withdraw"})
	schema.AddAction(metamodel.Action{ID: "redeem", Guard: "shares > 0 && shares <= maxRedeem(owner) && receiver != address(0)", EventID: "Redeem"})
	schema.AddAction(metamodel.Action{ID: "harvest", Guard: "yieldAmount > 0", EventID: "Harvest"})

	schema.AddArc(metamodel.Arc{Source: "assetBalances", Target: "deposit", Keys: []string{"caller"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "deposit", Target: "totalAssets", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "deposit", Target: "balances", Keys: []string{"receiver"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "deposit", Target: "totalShares", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "assetBalances", Target: "mint", Keys: []string{"caller"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "totalAssets", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "balances", Keys: []string{"receiver"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "mint", Target: "totalShares", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "withdraw", Keys: []string{"owner"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "totalShares", Target: "withdraw", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "totalAssets", Target: "withdraw", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "withdraw", Target: "assetBalances", Keys: []string{"receiver"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "balances", Target: "redeem", Keys: []string{"owner"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "totalShares", Target: "redeem", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "totalAssets", Target: "redeem", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "redeem", Target: "assetBalances", Keys: []string{"receiver"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "harvest", Target: "totalAssets", Value: "yieldAmount"})

	schema.AddEvent(metamodel.Event{ID: "Deposit", Signature: "Deposit(uint256,uint256,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "sender", Type: "address", Indexed: true}, {Name: "owner", Type: "address", Indexed: true}, {Name: "assets", Type: "uint256"}, {Name: "shares", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Mint", Signature: "Mint(uint256,uint256,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "sender", Type: "address", Indexed: true}, {Name: "owner", Type: "address", Indexed: true}, {Name: "assets", Type: "uint256"}, {Name: "shares", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Withdraw", Signature: "Withdraw(uint256,uint256,address,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "sender", Type: "address", Indexed: true}, {Name: "receiver", Type: "address", Indexed: true}, {Name: "owner", Type: "address", Indexed: true}, {Name: "assets", Type: "uint256"}, {Name: "shares", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Redeem", Signature: "Redeem(uint256,uint256,address,address,address,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "sender", Type: "address", Indexed: true}, {Name: "receiver", Type: "address", Indexed: true}, {Name: "owner", Type: "address", Indexed: true}, {Name: "assets", Type: "uint256"}, {Name: "shares", Type: "uint256"}}})
	schema.AddEvent(metamodel.Event{ID: "Harvest", Signature: "Harvest(uint256,uint256,uint256,uint256)", Parameters: []metamodel.EventParameter{{Name: "epoch", Type: "uint256"}, {Name: "seq", Type: "uint256"}, {Name: "yieldAmount", Type: "uint256"}, {Name: "totalAssets", Type: "uint256"}}})

	model := arc.FromSchema(schema)
	return &ERC04626{BaseTemplate: BaseTemplate{schema: schema, model: model, metadata: TokenMetadata{Name: name, Symbol: "v" + assetName, Standard: StandardERC04626}, standard: StandardERC04626}}
}
