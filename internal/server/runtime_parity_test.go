package server

import (
	"testing"

	"github.com/stackdump/bitwrap-io/dsl"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// TestRuntimeSolidityParity verifies the Go runtime produces the same state
// as the generated Solidity contracts would for the same inputs.
func TestRuntimeSolidityParity(t *testing.T) {
	t.Run("ERC20_transfer", func(t *testing.T) {
		src := `
schema ERC20 {
  version "1.0.0"
  register BALANCES map[address]uint256 observable
  register TOTAL_SUPPLY uint256

  fn(mint) {
    var to address
    var amount amount
    mint -|amount|> BALANCES[to]
    mint -|amount|> TOTAL_SUPPLY
  }

  fn(transfer) {
    var from address
    var to address
    var amount amount
    require(BALANCES[from] >= amount)
    BALANCES[from] -|amount|> transfer
    transfer -|amount|> BALANCES[to]
  }

  fn(burn) {
    var from address
    var amount amount
    require(BALANCES[from] >= amount)
    BALANCES[from] -|amount|> burn
    TOTAL_SUPPLY -|amount|> burn
  }
}
`
		ast, err := dsl.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		schema, err := dsl.Build(ast)
		if err != nil {
			t.Fatal(err)
		}

		rt := metamodel.NewRuntime(schema)
		rt.CheckConstraints = false

		// Mint 1000 to Alice
		err = rt.ExecuteWithBindings("mint", metamodel.Bindings{"to": "Alice", "amount": int64(1000)})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}

		// Verify: BALANCES[Alice]=1000, TOTAL_SUPPLY=1000
		balances := rt.DataMap("BALANCES")
		if mapVal(balances, "Alice") != 1000 {
			t.Errorf("after mint: BALANCES[Alice]=%v, want 1000", balances["Alice"])
		}
		if rt.Tokens("TOTAL_SUPPLY") != 1000 {
			t.Errorf("after mint: TOTAL_SUPPLY=%d, want 1000", rt.Tokens("TOTAL_SUPPLY"))
		}

		// Transfer 300 from Alice to Bob
		err = rt.ExecuteWithBindings("transfer", metamodel.Bindings{
			"from": "Alice", "to": "Bob", "amount": int64(300),
		})
		if err != nil {
			t.Fatalf("transfer: %v", err)
		}

		balances = rt.DataMap("BALANCES")
		if mapVal(balances, "Alice") != 700 {
			t.Errorf("after transfer: BALANCES[Alice]=%v, want 700", balances["Alice"])
		}
		if mapVal(balances, "Bob") != 300 {
			t.Errorf("after transfer: BALANCES[Bob]=%v, want 300", balances["Bob"])
		}
		// TOTAL_SUPPLY unchanged by transfer
		if rt.Tokens("TOTAL_SUPPLY") != 1000 {
			t.Errorf("after transfer: TOTAL_SUPPLY=%d, want 1000", rt.Tokens("TOTAL_SUPPLY"))
		}

		// Burn 100 from Alice
		err = rt.ExecuteWithBindings("burn", metamodel.Bindings{
			"from": "Alice", "amount": int64(100),
		})
		if err != nil {
			t.Fatalf("burn: %v", err)
		}

		balances = rt.DataMap("BALANCES")
		if mapVal(balances, "Alice") != 600 {
			t.Errorf("after burn: BALANCES[Alice]=%v, want 600", balances["Alice"])
		}
		if rt.Tokens("TOTAL_SUPPLY") != 900 {
			t.Errorf("after burn: TOTAL_SUPPLY=%d, want 900", rt.Tokens("TOTAL_SUPPLY"))
		}
	})

	t.Run("counter", func(t *testing.T) {
		src := `
schema Counter {
  version "1.0.0"
  register COUNT uint256

  fn(increment) {
    var amount amount
    increment -|amount|> COUNT
  }

  fn(decrement) {
    var amount amount
    require(COUNT >= amount)
    COUNT -|amount|> decrement
  }
}
`
		ast, err := dsl.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		schema, err := dsl.Build(ast)
		if err != nil {
			t.Fatal(err)
		}

		rt := metamodel.NewRuntime(schema)
		rt.CheckConstraints = false

		// Increment by 5
		err = rt.ExecuteWithBindings("increment", metamodel.Bindings{"amount": int64(5)})
		if err != nil {
			t.Fatalf("increment: %v", err)
		}
		if rt.Tokens("COUNT") != 5 {
			t.Errorf("after increment(5): COUNT=%d, want 5", rt.Tokens("COUNT"))
		}

		// Decrement by 2
		err = rt.ExecuteWithBindings("decrement", metamodel.Bindings{"amount": int64(2)})
		if err != nil {
			t.Fatalf("decrement: %v", err)
		}
		if rt.Tokens("COUNT") != 3 {
			t.Errorf("after decrement(2): COUNT=%d, want 3", rt.Tokens("COUNT"))
		}
	})
}

func mapVal(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}
