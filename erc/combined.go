package erc

import (
	"github.com/stackdump/bitwrap-io/arc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// CombinedERC represents a unified token template with all ERC standards.
type CombinedERC struct {
	BaseTemplate
}

// NewCombinedERC creates a unified token template with all ERC standards.
func NewCombinedERC(name, symbol string, decimals uint8) *CombinedERC {
	schema := metamodel.NewSchema(name)
	schema.Version = "Combined:1.0.0"

	schema.AddState(metamodel.State{ID: "totalSupply", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "balances", Type: "map[address]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "allowances", Type: "map[address]map[address]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "operators", Type: "map[address]map[address]bool", Exported: true})

	schema.AddAction(metamodel.Action{ID: "transfer", Guard: "balances[from] >= amount && to != address(0)"})
	schema.AddAction(metamodel.Action{ID: "approve", Guard: "amount <= totalSupply"})
	schema.AddAction(metamodel.Action{ID: "transferFrom", Guard: "balances[from] >= amount && allowances[from][caller] >= amount"})
	schema.AddAction(metamodel.Action{ID: "mint", Guard: "to != address(0)"})
	schema.AddAction(metamodel.Action{ID: "burn", Guard: "balances[from] >= amount"})

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

	schema.AddState(metamodel.State{ID: "tokenBalances", Type: "map[uint256]map[address]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "tokenSupply", Type: "map[uint256]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "tokenApproved", Type: "map[uint256]address", Exported: true})

	schema.AddAction(metamodel.Action{ID: "tokenMint", Guard: "to != address(0)"})
	schema.AddAction(metamodel.Action{ID: "tokenBurn", Guard: "caller == from || operators[from][caller] || tokenApproved[id] == caller"})
	schema.AddAction(metamodel.Action{ID: "tokenTransfer", Guard: "caller == from || operators[from][caller] || tokenApproved[id] == caller"})
	schema.AddAction(metamodel.Action{ID: "tokenApprove"})
	schema.AddAction(metamodel.Action{ID: "setApprovalForAll"})
	schema.AddAction(metamodel.Action{ID: "tokenMintBatch", Guard: "to != address(0)"})
	schema.AddAction(metamodel.Action{ID: "tokenBurnBatch", Guard: "caller == from || operators[from][caller]"})
	schema.AddAction(metamodel.Action{ID: "tokenTransferBatch", Guard: "caller == from || operators[from][caller]"})

	schema.AddArc(metamodel.Arc{Source: "tokenMint", Target: "tokenBalances", Keys: []string{"id", "to"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenMint", Target: "tokenSupply", Keys: []string{"id"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenBalances", Target: "tokenBurn", Keys: []string{"id", "from"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenSupply", Target: "tokenBurn", Keys: []string{"id"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenBalances", Target: "tokenTransfer", Keys: []string{"id", "from"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenTransfer", Target: "tokenBalances", Keys: []string{"id", "to"}, Value: "amount"})
	schema.AddArc(metamodel.Arc{Source: "tokenApprove", Target: "tokenApproved", Keys: []string{"id"}, Value: "to"})
	schema.AddArc(metamodel.Arc{Source: "setApprovalForAll", Target: "operators", Keys: []string{"owner", "operator"}, Value: "approved"})

	schema.AddState(metamodel.State{ID: "vaultTotalAssets", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "vaultTotalShares", Type: "uint256"})
	schema.AddState(metamodel.State{ID: "vaultShares", Type: "map[address]uint256", Exported: true})

	schema.AddAction(metamodel.Action{ID: "vaultDeposit"})
	schema.AddAction(metamodel.Action{ID: "vaultMint"})
	schema.AddAction(metamodel.Action{ID: "vaultWithdraw"})
	schema.AddAction(metamodel.Action{ID: "vaultRedeem"})
	schema.AddAction(metamodel.Action{ID: "vaultHarvest"})

	schema.AddArc(metamodel.Arc{Source: "balances", Target: "vaultDeposit", Keys: []string{"caller"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultDeposit", Target: "vaultTotalAssets", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultDeposit", Target: "vaultTotalShares", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultDeposit", Target: "vaultShares", Keys: []string{"receiver"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultTotalAssets", Target: "vaultWithdraw", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultTotalShares", Target: "vaultWithdraw", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultShares", Target: "vaultWithdraw", Keys: []string{"owner"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultWithdraw", Target: "balances", Keys: []string{"receiver"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultTotalAssets", Target: "vaultRedeem", Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultTotalShares", Target: "vaultRedeem", Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultShares", Target: "vaultRedeem", Keys: []string{"owner"}, Value: "shares"})
	schema.AddArc(metamodel.Arc{Source: "vaultRedeem", Target: "balances", Keys: []string{"receiver"}, Value: "assets"})
	schema.AddArc(metamodel.Arc{Source: "vaultHarvest", Target: "vaultTotalAssets", Value: "yieldAmount"})

	schema.AddState(metamodel.State{ID: "vestSchedules", Type: "map[uint256]VestingSchedule", Exported: true})
	schema.AddState(metamodel.State{ID: "vestClaimed", Type: "map[uint256]uint256", Exported: true})
	schema.AddState(metamodel.State{ID: "vestCreators", Type: "map[uint256]address", Exported: true})
	schema.AddState(metamodel.State{ID: "vestTotalLocked", Type: "uint256"})

	schema.AddAction(metamodel.Action{ID: "vestCreate"})
	schema.AddAction(metamodel.Action{ID: "vestClaim"})
	schema.AddAction(metamodel.Action{ID: "vestRevoke"})
	schema.AddAction(metamodel.Action{ID: "vestBurn"})

	schema.AddArc(metamodel.Arc{Source: "balances", Target: "vestCreate", Keys: []string{"caller"}, Value: "total"})
	schema.AddArc(metamodel.Arc{Source: "vestCreate", Target: "vestSchedules", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "vestCreate", Target: "tokenBalances", Keys: []string{"tokenId", "beneficiary"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestCreate", Target: "tokenSupply", Keys: []string{"tokenId"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestCreate", Target: "vestCreators", Keys: []string{"tokenId"}, Value: "caller"})
	schema.AddArc(metamodel.Arc{Source: "vestCreate", Target: "vestTotalLocked", Value: "total"})
	schema.AddArc(metamodel.Arc{Source: "vestClaim", Target: "vestClaimed", Keys: []string{"tokenId"}, Value: "claimAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestTotalLocked", Target: "vestClaim", Value: "claimAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestClaim", Target: "balances", Keys: []string{"caller"}, Value: "claimAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestSchedules", Target: "vestRevoke", Keys: []string{"tokenId"}})
	schema.AddArc(metamodel.Arc{Source: "vestTotalLocked", Target: "vestRevoke", Value: "unvestedAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestRevoke", Target: "balances", Keys: []string{"caller"}, Value: "unvestedAmount"})
	schema.AddArc(metamodel.Arc{Source: "tokenBalances", Target: "vestRevoke", Keys: []string{"tokenId", "owner"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "tokenSupply", Target: "vestRevoke", Keys: []string{"tokenId"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "tokenBalances", Target: "vestBurn", Keys: []string{"tokenId", "owner"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "tokenSupply", Target: "vestBurn", Keys: []string{"tokenId"}, Value: "nftAmount"})
	schema.AddArc(metamodel.Arc{Source: "vestSchedules", Target: "vestBurn", Keys: []string{"tokenId"}})

	schema.AddConstraint(metamodel.Constraint{ID: "fungibleConservation", Expr: `sum("balances") + vaultTotalAssets + vestTotalLocked == totalSupply`})
	schema.AddConstraint(metamodel.Constraint{ID: "vaultSharesConservation", Expr: `sum("vaultShares") == vaultTotalShares`})
	schema.AddConstraint(metamodel.Constraint{ID: "tokenSupplyConservation", Expr: `forall id: sum("tokenBalances") == tokenSupply[id]`})

	model := arc.FromSchema(schema)
	return &CombinedERC{BaseTemplate: BaseTemplate{schema: schema, model: model, metadata: TokenMetadata{Name: name, Symbol: symbol, Decimals: decimals, Standard: "Combined"}, standard: "Combined"}}
}
