package dsl

import (
	"testing"
)

const erc20Source = `
schema ERC20 {
  version "1.0.0"
  domain "custody"
  asset "erc20"

  initial_state {
    ASSETS.AVAILABLE: {
      "0xAlice": 1000
      "0xBob": 500
      "0xCharlie": 250
    }
    ASSETS.TOTAL_SUPPLY: 1750
    INCOMES.MINT: 0
    EXPENSES.BURN: 0
  }

  register ASSETS.AVAILABLE map[address]uint256 observable
  register ASSETS.TOTAL_SUPPLY uint256 observable
  register INCOMES.MINT uint256 observable
  register EXPENSES.BURN uint256 observable

  event TransferBalanceChange {
    from: address indexed
    to: address indexed
    amount: uint256
  }

  event MintBalanceChange {
    to: address indexed
    amount: uint256
  }

  event BurnBalanceChange {
    from: address indexed
    amount: uint256
  }

  fn(transfer) {
    var from address
    var to address
    var amount amount

    require(ASSETS.AVAILABLE[from] >= amount && amount > 0)
    @event TransferBalanceChange

    ASSETS.AVAILABLE[from] -|amount|> transfer
    transfer -|amount|> ASSETS.AVAILABLE[to]
  }

  fn(mint) {
    var to address
    var amount amount

    require(amount > 0)
    @event MintBalanceChange

    mint -|amount|> ASSETS.AVAILABLE[to]
    mint -|amount|> ASSETS.TOTAL_SUPPLY
    mint -|amount|> INCOMES.MINT
  }

  fn(burn) {
    var from address
    var amount amount

    require(ASSETS.AVAILABLE[from] >= amount && amount > 0)
    @event BurnBalanceChange

    ASSETS.AVAILABLE[from] -|amount|> burn
    ASSETS.TOTAL_SUPPLY -|amount|> burn
    burn -|amount|> EXPENSES.BURN
  }
}
`

func TestLexer(t *testing.T) {
	lexer := NewLexer(erc20Source)
	tokens, err := lexer.Tokenize()
	if err != nil {
		t.Fatalf("Tokenize error: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("expected tokens, got none")
	}
	// First meaningful token should be "schema"
	if tokens[0].Type != TokenSchema {
		t.Errorf("expected first token to be schema, got %v", tokens[0])
	}
}

func TestParse(t *testing.T) {
	schema, err := Parse(erc20Source)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Name and version
	if schema.Name != "ERC20" {
		t.Errorf("expected name ERC20, got %s", schema.Name)
	}
	if schema.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", schema.Version)
	}
	if schema.Domain != "custody" {
		t.Errorf("expected domain custody, got %s", schema.Domain)
	}
	if schema.Asset != "erc20" {
		t.Errorf("expected asset erc20, got %s", schema.Asset)
	}

	// Registers
	if len(schema.Registers) != 4 {
		t.Fatalf("expected 4 registers, got %d", len(schema.Registers))
	}
	if schema.Registers[0].Name != "ASSETS.AVAILABLE" {
		t.Errorf("expected register ASSETS.AVAILABLE, got %s", schema.Registers[0].Name)
	}
	if schema.Registers[0].Type != "map[address]uint256" {
		t.Errorf("expected type map[address]uint256, got %s", schema.Registers[0].Type)
	}
	if !schema.Registers[0].Observable {
		t.Error("expected ASSETS.AVAILABLE to be observable")
	}

	// Events
	if len(schema.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(schema.Events))
	}
	if schema.Events[0].Name != "TransferBalanceChange" {
		t.Errorf("expected TransferBalanceChange, got %s", schema.Events[0].Name)
	}
	if len(schema.Events[0].Fields) != 3 {
		t.Errorf("expected 3 fields on TransferBalanceChange, got %d", len(schema.Events[0].Fields))
	}
	if !schema.Events[0].Fields[0].Indexed {
		t.Error("expected 'from' field to be indexed")
	}

	// Functions
	if len(schema.Functions) != 3 {
		t.Fatalf("expected 3 functions, got %d", len(schema.Functions))
	}

	// transfer function
	transfer := schema.Functions[0]
	if transfer.Name != "transfer" {
		t.Errorf("expected transfer, got %s", transfer.Name)
	}
	if len(transfer.Vars) != 3 {
		t.Errorf("expected 3 vars in transfer, got %d", len(transfer.Vars))
	}
	if transfer.Require == "" {
		t.Error("expected non-empty require expression for transfer")
	}
	if transfer.EventRef != "TransferBalanceChange" {
		t.Errorf("expected event TransferBalanceChange, got %s", transfer.EventRef)
	}
	if len(transfer.Arcs) != 2 {
		t.Fatalf("expected 2 arcs in transfer, got %d", len(transfer.Arcs))
	}

	// First arc: ASSETS.AVAILABLE[from] -|amount|> transfer (input)
	arc0 := transfer.Arcs[0]
	if arc0.Source != "ASSETS.AVAILABLE" || arc0.SourceIndex != "from" {
		t.Errorf("arc0 source: expected ASSETS.AVAILABLE[from], got %s[%s]", arc0.Source, arc0.SourceIndex)
	}
	if arc0.Target != "transfer" {
		t.Errorf("arc0 target: expected transfer, got %s", arc0.Target)
	}
	if arc0.Weight != "amount" {
		t.Errorf("arc0 weight: expected amount, got %s", arc0.Weight)
	}

	// Second arc: transfer -|amount|> ASSETS.AVAILABLE[to] (output)
	arc1 := transfer.Arcs[1]
	if arc1.Source != "transfer" {
		t.Errorf("arc1 source: expected transfer, got %s", arc1.Source)
	}
	if arc1.Target != "ASSETS.AVAILABLE" || arc1.TargetIndex != "to" {
		t.Errorf("arc1 target: expected ASSETS.AVAILABLE[to], got %s[%s]", arc1.Target, arc1.TargetIndex)
	}

	// mint function has 3 output arcs, 0 input arcs
	mint := schema.Functions[1]
	if mint.Name != "mint" {
		t.Errorf("expected mint, got %s", mint.Name)
	}
	if len(mint.Arcs) != 3 {
		t.Fatalf("expected 3 arcs in mint, got %d", len(mint.Arcs))
	}

	// burn function has 2 input arcs, 1 output arc
	burn := schema.Functions[2]
	if burn.Name != "burn" {
		t.Errorf("expected burn, got %s", burn.Name)
	}
	if len(burn.Arcs) != 3 {
		t.Fatalf("expected 3 arcs in burn, got %d", len(burn.Arcs))
	}

	// Initial state
	if len(schema.InitialState) != 4 {
		t.Fatalf("expected 4 initial values, got %d", len(schema.InitialState))
	}
	if !schema.InitialState[0].IsMap {
		t.Error("expected ASSETS.AVAILABLE initial to be a map")
	}
	if schema.InitialState[0].MapValue["0xAlice"] != 1000 {
		t.Errorf("expected 0xAlice=1000, got %d", schema.InitialState[0].MapValue["0xAlice"])
	}
	if schema.InitialState[1].Scalar != 1750 {
		t.Errorf("expected ASSETS.TOTAL_SUPPLY=1750, got %d", schema.InitialState[1].Scalar)
	}
}

func TestBuild(t *testing.T) {
	ast, err := Parse(erc20Source)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	schema, err := Build(ast)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}

	// Schema basics
	if schema.Name != "ERC20" {
		t.Errorf("expected name ERC20, got %s", schema.Name)
	}
	if schema.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", schema.Version)
	}

	// States (from registers)
	if len(schema.States) != 4 {
		t.Fatalf("expected 4 states, got %d", len(schema.States))
	}
	avail := schema.StateByID("ASSETS.AVAILABLE")
	if avail == nil {
		t.Fatal("expected state ASSETS.AVAILABLE")
	}
	if !avail.IsData() {
		t.Error("expected ASSETS.AVAILABLE to be data state")
	}
	if !avail.Exported {
		t.Error("expected ASSETS.AVAILABLE to be exported")
	}
	if avail.Type != "map[address]uint256" {
		t.Errorf("expected type map[address]uint256, got %s", avail.Type)
	}
	// Check initial value
	initMap, ok := avail.Initial.(map[string]any)
	if !ok {
		t.Fatalf("expected initial to be map[string]any, got %T", avail.Initial)
	}
	if initMap["0xAlice"] != 1000 {
		t.Errorf("expected 0xAlice=1000, got %v", initMap["0xAlice"])
	}

	supply := schema.StateByID("ASSETS.TOTAL_SUPPLY")
	if supply == nil {
		t.Fatal("expected state ASSETS.TOTAL_SUPPLY")
	}
	if !supply.IsToken() {
		t.Error("expected ASSETS.TOTAL_SUPPLY to be token state")
	}
	if supply.Initial != 1750 {
		t.Errorf("expected initial 1750, got %v", supply.Initial)
	}

	// Actions (from functions)
	if len(schema.Actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(schema.Actions))
	}
	transferAction := schema.ActionByID("transfer")
	if transferAction == nil {
		t.Fatal("expected action transfer")
	}
	if transferAction.Guard == "" {
		t.Error("expected non-empty guard for transfer")
	}
	if transferAction.EventID != "TransferBalanceChange" {
		t.Errorf("expected event TransferBalanceChange, got %s", transferAction.EventID)
	}

	// Arcs
	// transfer: 2 arcs, mint: 3 arcs, burn: 3 arcs = 8 total
	if len(schema.Arcs) != 8 {
		t.Fatalf("expected 8 arcs, got %d", len(schema.Arcs))
	}

	// Check transfer input arcs
	inputArcs := schema.InputArcs("transfer")
	if len(inputArcs) != 1 {
		t.Fatalf("expected 1 input arc for transfer, got %d", len(inputArcs))
	}
	if inputArcs[0].Source != "ASSETS.AVAILABLE" {
		t.Errorf("expected input from ASSETS.AVAILABLE, got %s", inputArcs[0].Source)
	}
	if len(inputArcs[0].Keys) != 1 || inputArcs[0].Keys[0] != "from" {
		t.Errorf("expected keys [from], got %v", inputArcs[0].Keys)
	}

	// Check transfer output arcs
	outputArcs := schema.OutputArcs("transfer")
	if len(outputArcs) != 1 {
		t.Fatalf("expected 1 output arc for transfer, got %d", len(outputArcs))
	}
	if outputArcs[0].Target != "ASSETS.AVAILABLE" {
		t.Errorf("expected output to ASSETS.AVAILABLE, got %s", outputArcs[0].Target)
	}
	if len(outputArcs[0].Keys) != 1 || outputArcs[0].Keys[0] != "to" {
		t.Errorf("expected keys [to], got %v", outputArcs[0].Keys)
	}

	// Check mint output arcs (3 outputs, no inputs)
	mintInputs := schema.InputArcs("mint")
	if len(mintInputs) != 0 {
		t.Errorf("expected 0 input arcs for mint, got %d", len(mintInputs))
	}
	mintOutputs := schema.OutputArcs("mint")
	if len(mintOutputs) != 3 {
		t.Fatalf("expected 3 output arcs for mint, got %d", len(mintOutputs))
	}

	// Check that ASSETS.TOTAL_SUPPLY output from mint has no keys (scalar)
	for _, a := range mintOutputs {
		if a.Target == "ASSETS.TOTAL_SUPPLY" {
			if len(a.Keys) != 0 {
				t.Errorf("expected no keys for TOTAL_SUPPLY arc, got %v", a.Keys)
			}
		}
	}

	// Events
	if len(schema.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(schema.Events))
	}
	te := schema.EventByID("TransferBalanceChange")
	if te == nil {
		t.Fatal("expected event TransferBalanceChange")
	}
	if len(te.Parameters) != 3 {
		t.Errorf("expected 3 parameters, got %d", len(te.Parameters))
	}
	if !te.Parameters[0].Indexed {
		t.Error("expected first parameter to be indexed")
	}

	// Verify event-action linkage
	linkedAction := schema.ActionForEvent("TransferBalanceChange")
	if linkedAction == nil {
		t.Fatal("expected action linked to TransferBalanceChange")
	}
	if linkedAction.ID != "transfer" {
		t.Errorf("expected transfer action linked, got %s", linkedAction.ID)
	}

	// Check burn arcs: 2 inputs, 1 output
	burnInputs := schema.InputArcs("burn")
	if len(burnInputs) != 2 {
		t.Fatalf("expected 2 input arcs for burn, got %d", len(burnInputs))
	}
	burnOutputs := schema.OutputArcs("burn")
	if len(burnOutputs) != 1 {
		t.Fatalf("expected 1 output arc for burn, got %d", len(burnOutputs))
	}
}

func TestParseError(t *testing.T) {
	_, err := Parse(`schema {`)
	if err == nil {
		t.Error("expected parse error for missing name")
	}
}

func TestLexerComment(t *testing.T) {
	src := `schema Test {
  // this is a comment
  version "1.0.0"
}
`
	schema, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if schema.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", schema.Version)
	}
}
