package server

import (
	"os"
	"os/exec"
	"path/filepath"
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

	t.Run("allowances", func(t *testing.T) {
		src := `
schema ERC20Approve {
  version "1.0.0"
  register BALANCES map[address]uint256
  register ALLOWANCES map[address]map[address]uint256

  fn(mint) {
    var to address
    var amount amount
    mint -|amount|> BALANCES[to]
  }

  fn(approve) {
    var owner address
    var spender address
    var amount amount
    approve -|amount|> ALLOWANCES[owner][spender]
  }

  fn(transferFrom) {
    var from address
    var spender address
    var to address
    var amount amount
    BALANCES[from] -|amount|> transferFrom
    ALLOWANCES[from][spender] -|amount|> transferFrom
    transferFrom -|amount|> BALANCES[to]
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

		// Alice approves Bob for 500
		err = rt.ExecuteWithBindings("approve", metamodel.Bindings{"owner": "Alice", "spender": "Bob", "amount": int64(500)})
		if err != nil {
			t.Fatalf("approve: %v", err)
		}
		allowances := rt.DataMap("ALLOWANCES")
		nested, ok := allowances["Alice"].(map[string]any)
		if !ok {
			t.Fatal("ALLOWANCES[Alice] is not a map")
		}
		if mapVal(nested, "Bob") != 500 {
			t.Errorf("after approve: ALLOWANCES[Alice][Bob]=%v, want 500", nested["Bob"])
		}

		// Bob transfers 200 from Alice to Charlie
		err = rt.ExecuteWithBindings("transferFrom", metamodel.Bindings{
			"from": "Alice", "spender": "Bob", "to": "Charlie", "amount": int64(200),
		})
		if err != nil {
			t.Fatalf("transferFrom: %v", err)
		}

		balances := rt.DataMap("BALANCES")
		if mapVal(balances, "Alice") != 800 {
			t.Errorf("after transferFrom: BALANCES[Alice]=%v, want 800", balances["Alice"])
		}
		if mapVal(balances, "Charlie") != 200 {
			t.Errorf("after transferFrom: BALANCES[Charlie]=%v, want 200", balances["Charlie"])
		}
		allowances = rt.DataMap("ALLOWANCES")
		nested = allowances["Alice"].(map[string]any)
		if mapVal(nested, "Bob") != 300 {
			t.Errorf("after transferFrom: ALLOWANCES[Alice][Bob]=%v, want 300", nested["Bob"])
		}
	})

	// Verify JS parity by running the JS test
	t.Run("js_parity", func(t *testing.T) {
		cmd := exec.Command("node", "--experimental-vm-modules", "public/parity_test.mjs")
		cmd.Dir = findProjectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("JS parity test failed:\n%s\n%v", out, err)
		}
		t.Logf("%s", out)
	})
}

func findProjectRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test binary's working directory to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root")
		}
		dir = parent
	}
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
