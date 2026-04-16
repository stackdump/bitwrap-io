package dsl

import (
	"strings"
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
	if arc0.Source != "ASSETS.AVAILABLE" || len(arc0.SourceIndices) != 1 || arc0.SourceIndices[0] != "from" {
		t.Errorf("arc0 source: expected ASSETS.AVAILABLE[from], got %s%v", arc0.Source, arc0.SourceIndices)
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
	if arc1.Target != "ASSETS.AVAILABLE" || len(arc1.TargetIndices) != 1 || arc1.TargetIndices[0] != "to" {
		t.Errorf("arc1 target: expected ASSETS.AVAILABLE[to], got %s%v", arc1.Target, arc1.TargetIndices)
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

// TestParseRequiresRole — `fn(name) requires <role> { ... }` produces
// Function.Roles. Lowering to Action.Roles is covered by TestBuildRolesLowered.
func TestParseRequiresRole(t *testing.T) {
	src := `schema T {
  version "1.0"
  register B uint256
  fn(mint) requires minter {
    var amount amount
    mint -|amount|> B
  }
  fn(admin) requires owner, minter {
    var amount amount
    admin -|amount|> B
  }
  fn(burn) {
    var amount amount
    B -|amount|> burn
  }
}`
	schema, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	byName := map[string][]string{}
	for _, fn := range schema.Functions {
		byName[fn.Name] = fn.Roles
	}
	if got := byName["mint"]; len(got) != 1 || got[0] != "minter" {
		t.Errorf("mint roles: got %v, want [minter]", got)
	}
	if got := byName["admin"]; len(got) != 2 || got[0] != "owner" || got[1] != "minter" {
		t.Errorf("admin roles: got %v, want [owner minter]", got)
	}
	if got := byName["burn"]; len(got) != 0 {
		t.Errorf("burn should have no roles, got %v", got)
	}
}

// TestBuildRolesLowered — Function.Roles flows into Action.Roles so the
// synthesizer sees the metadata it needs.
func TestBuildRolesLowered(t *testing.T) {
	src := `schema T {
  version "1.0"
  register B uint256
  fn(mint) requires minter {
    var amount amount
    mint -|amount|> B
  }
}`
	ast, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	schema, err := Build(ast)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	a := schema.ActionByID("mint")
	if a == nil {
		t.Fatal("mint action missing")
	}
	if len(a.Roles) != 1 || a.Roles[0] != "minter" {
		t.Errorf("mint Action.Roles: got %v, want [minter]", a.Roles)
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

const nestedMapSource = `
schema ERC20WithApprove {
  version "1.0.0"

  register BALANCES map[address]uint256 observable
  register ALLOWANCES map[address]map[address]uint256 observable

  fn(approve) {
    var owner address
    var spender address
    var amount amount

    ALLOWANCES[owner][spender] -|amount|> approve
    approve -|amount|> ALLOWANCES[owner][spender]
  }

  fn(transferFrom) {
    var from address
    var to address
    var amount amount

    require(BALANCES[from] >= amount && ALLOWANCES[from][to] >= amount)

    BALANCES[from] -|amount|> transferFrom
    ALLOWANCES[from][to] -|amount|> transferFrom
    transferFrom -|amount|> BALANCES[to]
  }
}
`

func TestNestedMapArcs(t *testing.T) {
	ast, err := Parse(nestedMapSource)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Check nested map register type
	if ast.Registers[1].Type != "map[address]map[address]uint256" {
		t.Errorf("expected map[address]map[address]uint256, got %s", ast.Registers[1].Type)
	}

	// Check approve arcs have two indices
	approve := ast.Functions[0]
	if approve.Name != "approve" {
		t.Fatalf("expected approve, got %s", approve.Name)
	}
	if len(approve.Arcs) != 2 {
		t.Fatalf("expected 2 arcs, got %d", len(approve.Arcs))
	}

	// Input arc: ALLOWANCES[owner][spender] -|amount|> approve
	arc0 := approve.Arcs[0]
	if arc0.Source != "ALLOWANCES" {
		t.Errorf("arc0 source: expected ALLOWANCES, got %s", arc0.Source)
	}
	if len(arc0.SourceIndices) != 2 || arc0.SourceIndices[0] != "owner" || arc0.SourceIndices[1] != "spender" {
		t.Errorf("arc0 source indices: expected [owner spender], got %v", arc0.SourceIndices)
	}

	// Output arc: approve -|amount|> ALLOWANCES[owner][spender]
	arc1 := approve.Arcs[1]
	if arc1.Target != "ALLOWANCES" {
		t.Errorf("arc1 target: expected ALLOWANCES, got %s", arc1.Target)
	}
	if len(arc1.TargetIndices) != 2 || arc1.TargetIndices[0] != "owner" || arc1.TargetIndices[1] != "spender" {
		t.Errorf("arc1 target indices: expected [owner spender], got %v", arc1.TargetIndices)
	}

	// Build and verify schema arcs get multi-key
	schema, err := Build(ast)
	if err != nil {
		t.Fatalf("Build error: %v", err)
	}

	approveArcs := schema.InputArcs("approve")
	if len(approveArcs) != 1 {
		t.Fatalf("expected 1 input arc for approve, got %d", len(approveArcs))
	}
	if len(approveArcs[0].Keys) != 2 || approveArcs[0].Keys[0] != "owner" || approveArcs[0].Keys[1] != "spender" {
		t.Errorf("approve input arc keys: expected [owner spender], got %v", approveArcs[0].Keys)
	}

	outputArcs := schema.OutputArcs("approve")
	if len(outputArcs) != 1 {
		t.Fatalf("expected 1 output arc for approve, got %d", len(outputArcs))
	}
	if len(outputArcs[0].Keys) != 2 {
		t.Errorf("approve output arc keys: expected 2, got %d", len(outputArcs[0].Keys))
	}

	// transferFrom has a 2-key input arc for ALLOWANCES
	tfArcs := schema.InputArcs("transferFrom")
	foundNested := false
	for _, a := range tfArcs {
		if a.Source == "ALLOWANCES" && len(a.Keys) == 2 {
			foundNested = true
			if a.Keys[0] != "from" || a.Keys[1] != "to" {
				t.Errorf("transferFrom ALLOWANCES arc keys: expected [from to], got %v", a.Keys)
			}
		}
	}
	if !foundNested {
		t.Error("expected a 2-key ALLOWANCES arc in transferFrom inputs")
	}
}

func TestMapCommaShorthand(t *testing.T) {
	src := `
schema Test {
  version "1.0.0"
  register ALLOWANCES map[address,address]uint256 observable
  register TRIPLE map[uint256,address,uint256]bool
}
`
	ast, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// map[address,address]uint256 → map[address]map[address]uint256
	if ast.Registers[0].Type != "map[address]map[address]uint256" {
		t.Errorf("expected map[address]map[address]uint256, got %s", ast.Registers[0].Type)
	}

	// map[uint256,address,uint256]bool → map[uint256]map[address]map[uint256]bool
	if ast.Registers[1].Type != "map[uint256]map[address]map[uint256]bool" {
		t.Errorf("expected map[uint256]map[address]map[uint256]bool, got %s", ast.Registers[1].Type)
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring of expected error
	}{
		{
			name: "duplicate register",
			src:  `schema Foo { version "1.0" register X uint256 register X uint256 }`,
			want: `duplicate name "X"`,
		},
		{
			name: "reserved schema name",
			src:  `schema Test { version "1.0" }`,
			want: `schema name "Test" conflicts with forge-std class`,
		},
		{
			name: "reserved function name",
			src:  `schema Foo { version "1.0" register X uint256 fn(msg) { X -|1|> msg } }`,
			want: `function name "msg" conflicts with Solidity built-in`,
		},
		{
			name: "scalar indexed",
			src:  `schema Foo { version "1.0" register X uint256 fn(f) { var k address X[k] -|1|> f } }`,
			want: "register X is uint256 (scalar), cannot index",
		},
		{
			name: "unknown register in arc",
			src:  `schema Foo { version "1.0" fn(f) { var x amount NOPE -|x|> f } }`,
			want: `unknown register "NOPE"`,
		},
		{
			name: "unknown identifier in guard",
			src:  `schema Foo { version "1.0" register X uint256 fn(f) { var amount amount require(NOPE >= amount) f -|amount|> X } }`,
			want: `guard references unknown identifier "NOPE"`,
		},
		{
			name: "undeclared event",
			src:  `schema Foo { version "1.0" register X uint256 fn(f) { var amount amount @event Nope f -|amount|> X } }`,
			want: `undeclared event "Nope"`,
		},
		{
			name: "unknown type",
			src:  `schema Foo { version "1.0" register X maps[address]uint256 }`,
			want: `unknown type "maps"`,
		},
		{
			name: "map key depth mismatch",
			src:  `schema Foo { version "1.0" register X map[address,address]uint256 fn(f) { var k address X[k] -|1|> f } }`,
			want: "needs 2 index key(s)",
		},
		{
			name: "undeclared arc weight",
			src:  `schema Foo { version "1.0" register X uint256 fn(f) { f -|typo|> X } }`,
			want: `arc weight "typo" is not a declared variable`,
		},
		{
			name: "hash comment",
			src: `# comment
schema Foo { version "1.0"
  register X uint256  # inline comment
  fn(inc) { var amount amount inc -|amount|> X }
}`,
			want: "", // no error
		},
		{
			name: "valid schema passes",
			src: `schema Foo { version "1.0"
				register X map[address]uint256 observable
				event E { to: address indexed amount: uint256 }
				fn(inc) { var to address var amount amount @event E inc -|amount|> X[to] }
			}`,
			want: "", // no error
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ast, err := Parse(tc.src)
			if err != nil {
				if tc.want != "" && strings.Contains(err.Error(), tc.want) {
					return // parse error matches expected
				}
				t.Fatalf("unexpected parse error: %v", err)
			}
			_, err = Build(ast)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got: %v", tc.want, err)
			}
		})
	}
}
