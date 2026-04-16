package synth

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
	"github.com/stackdump/bitwrap-io/internal/metamodel/guard"
)

// extractRangeChecks parses an action's guard expression and extracts all
// `<state>[<key>(.<key>)*] >= <binding>` clauses — the only ZK-relevant
// guard pattern in the current hand-written circuits. Non-ZK clauses
// (zero-address checks, role equality, etc.) are silently ignored because
// they're enforced on-chain, not in the ZK proof.
//
// Returns a slice of emitted gnark constraint groups (each group is a
// `diff := Sub(...); ToBinary(diff, bits)` pair). The caller writes them
// into the Define() body at the appropriate place.
//
// This is the narrow first-slice of the guard compiler; slice 2.4 expands
// it to cover TransferFrom's multi-proof composition and equality checks.
func extractRangeChecks(action *metamodel.Action, bits int) ([]rangeCheckEmit, error) {
	if action.Guard == "" {
		return nil, nil
	}
	p := guard.NewParser(action.Guard)
	ast, err := p.Parse()
	if err != nil {
		return nil, fmt.Errorf("guard parse: %w", err)
	}

	var out []rangeCheckEmit
	walkAnd(ast, func(clause guard.Node) {
		bin, ok := clause.(*guard.BinaryOp)
		if !ok {
			return
		}
		if bin.Op != ">=" && bin.Op != "<=" {
			return
		}
		left, right := bin.Left, bin.Right
		if bin.Op == "<=" {
			left, right = right, left // normalize to >=
		}
		// Expect LHS = IndexExpr chain on a state identifier, RHS = identifier.
		leftField := indexExprFieldName(left)
		if leftField == "" {
			return
		}
		rightID, ok := right.(*guard.Identifier)
		if !ok {
			return
		}
		out = append(out, rangeCheckEmit{
			left:  leftField,
			right: capitalize(rightID.Name),
			bits:  bits,
		})
	})
	return out, nil
}

type rangeCheckEmit struct {
	left, right string // struct field names (e.g. "BalanceFrom", "Amount")
	bits        int
}

func (r rangeCheckEmit) emit(b *strings.Builder, tmpVarName string) {
	emitSub(b, tmpVarName, "c."+r.left, "c."+r.right)
	emitRangeCheck(b, tmpVarName, r.bits)
}

// walkAnd applies fn to each top-level conjunct of an expression. `a && b`
// visits a and b; anything else visits itself.
func walkAnd(node guard.Node, fn func(guard.Node)) {
	if bin, ok := node.(*guard.BinaryOp); ok && bin.Op == "&&" {
		walkAnd(bin.Left, fn)
		walkAnd(bin.Right, fn)
		return
	}
	fn(node)
}

// indexExprFieldName converts an AST node representing `state[key]` or
// `state[key1][key2]` into the camelCase struct field name the hand-written
// circuits use — `balances[from]` → `BalanceFrom`,
// `allowances[from][caller]` → `AllowanceFrom`. Returns "" if the node
// shape isn't recognized.
func indexExprFieldName(node guard.Node) string {
	idx, ok := node.(*guard.IndexExpr)
	if !ok {
		return ""
	}
	var keys []string
	cur := guard.Node(idx)
	for {
		e, ok := cur.(*guard.IndexExpr)
		if !ok {
			break
		}
		keyID, ok := e.Index.(*guard.Identifier)
		if !ok {
			return ""
		}
		keys = append([]string{keyID.Name}, keys...)
		cur = e.Object
	}
	baseID, ok := cur.(*guard.Identifier)
	if !ok {
		return ""
	}
	// Convert "balances" → "Balance" (drop trailing 's' if collection-plural);
	// prepend each key's capitalization. Keep the exact hand-written
	// convention by only chopping known plurals.
	base := depluralize(baseID.Name)
	name := capitalize(base)
	for _, k := range keys {
		name += capitalize(k)
	}
	return name
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// depluralize handles the two collection names the ERC templates use today:
// "balances" → "balance", "allowances" → "allowance". Other names fall
// through unchanged. Keeping this conservative so we don't mangle arbitrary
// state IDs; slice 2.4 may need to extend it.
func depluralize(s string) string {
	switch s {
	case "balances":
		return "balance"
	case "allowances":
		return "allowance"
	case "schedules":
		return "schedule"
	case "owners":
		return "owner"
	case "tallies":
		return "tally"
	}
	return s
}
