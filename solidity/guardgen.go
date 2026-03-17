// Package solidity provides AST-based guard expression to Solidity translation.
package solidity

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel/guard"
)

// GuardTranslator converts parsed guard ASTs to Solidity code.
type GuardTranslator struct {
	Parameters map[string]string
}

// NewGuardTranslator creates a new translator.
func NewGuardTranslator() *GuardTranslator {
	return &GuardTranslator{Parameters: make(map[string]string)}
}

// TranslateGuard parses a guard expression and returns Solidity require statements.
func (t *GuardTranslator) TranslateGuard(expr string) ([]string, error) {
	if expr == "" {
		return nil, nil
	}
	compiled, err := guard.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse guard: %w", err)
	}
	ast := compiled.AST()
	if ast == nil {
		return nil, nil
	}
	clauses := t.splitAnd(ast)
	var requires []string
	for _, clause := range clauses {
		solExpr := t.translateNode(clause)
		errMsg := t.genErrMsg(clause)
		requires = append(requires, fmt.Sprintf("require(%s, \"%s\");", solExpr, errMsg))
	}
	return requires, nil
}

func (t *GuardTranslator) splitAnd(node guard.Node) []guard.Node {
	if binOp, ok := node.(*guard.BinaryOp); ok && binOp.Op == "&&" {
		left := t.splitAnd(binOp.Left)
		right := t.splitAnd(binOp.Right)
		return append(left, right...)
	}
	return []guard.Node{node}
}

func (t *GuardTranslator) translateNode(node guard.Node) string {
	switch n := node.(type) {
	case *guard.BinaryOp:
		return fmt.Sprintf("%s %s %s", t.translateNode(n.Left), n.Op, t.translateNode(n.Right))
	case *guard.UnaryOp:
		return fmt.Sprintf("%s%s", n.Op, t.translateNode(n.Operand))
	case *guard.IndexExpr:
		return fmt.Sprintf("%s[%s]", t.translateNode(n.Object), t.translateNode(n.Index))
	case *guard.FieldExpr:
		return fmt.Sprintf("%s.%s", t.translateNode(n.Object), n.Field)
	case *guard.CallExpr:
		args := make([]string, len(n.Args))
		for i, arg := range n.Args {
			args[i] = t.translateNode(arg)
		}
		return fmt.Sprintf("%s(%s)", n.Func, strings.Join(args, ", "))
	case *guard.Identifier:
		if n.Name == "caller" {
			return "msg.sender"
		}
		t.Parameters[n.Name] = inferParamType(n.Name)
		return n.Name
	case *guard.NumberLit:
		return fmt.Sprintf("%d", n.Value)
	case *guard.StringLit:
		return fmt.Sprintf("\"%s\"", n.Value)
	case *guard.BoolLit:
		if n.Value {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("/* unknown node: %T */", node)
	}
}

func (t *GuardTranslator) genErrMsg(node guard.Node) string {
	switch n := node.(type) {
	case *guard.BinaryOp:
		if n.Op == ">=" {
			rootName := t.getRootIdentifier(n.Left)
			if rootName == "balances" {
				return "insufficient balance"
			}
			if rootName == "allowances" {
				return "insufficient allowance"
			}
			if strings.Contains(rootName, "Balances") {
				return "insufficient balance"
			}
		}
		if n.Op == "!=" {
			if call, ok := n.Right.(*guard.CallExpr); ok {
				if call.Func == "address" && len(call.Args) > 0 {
					if num, ok := call.Args[0].(*guard.NumberLit); ok && num.Value == 0 {
						return "zero address"
					}
				}
			}
		}
		if n.Op == "==" || n.Op == "||" {
			left := t.translateNode(n.Left)
			if strings.Contains(left, "caller") || strings.Contains(left, "msg.sender") ||
				strings.Contains(left, "operators") || strings.Contains(left, "Approved") {
				return "not authorized"
			}
		}
		expr := t.translateNode(node)
		if len(expr) > 40 {
			return "precondition failed"
		}
		return expr
	default:
		return "precondition failed"
	}
}

// ExtractParameters returns all parameters discovered from a guard expression.
func (t *GuardTranslator) ExtractParameters(expr string) (map[string]string, error) {
	if expr == "" {
		return nil, nil
	}
	compiled, err := guard.Compile(expr)
	if err != nil {
		return nil, err
	}
	t.Parameters = make(map[string]string)
	t.walkNode(compiled.AST())
	delete(t.Parameters, "caller")
	return t.Parameters, nil
}

func (t *GuardTranslator) walkNode(node guard.Node) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *guard.BinaryOp:
		t.walkNode(n.Left)
		t.walkNode(n.Right)
	case *guard.UnaryOp:
		t.walkNode(n.Operand)
	case *guard.IndexExpr:
		t.walkNode(n.Object)
		t.walkNode(n.Index)
	case *guard.FieldExpr:
		t.walkNode(n.Object)
	case *guard.CallExpr:
		for _, arg := range n.Args {
			t.walkNode(arg)
		}
	case *guard.Identifier:
		if isLikelyParameter(n.Name) {
			t.Parameters[n.Name] = inferParamType(n.Name)
		}
	}
}

func (t *GuardTranslator) getRootIdentifier(node guard.Node) string {
	switch n := node.(type) {
	case *guard.Identifier:
		return n.Name
	case *guard.IndexExpr:
		return t.getRootIdentifier(n.Object)
	case *guard.FieldExpr:
		return t.getRootIdentifier(n.Object)
	default:
		return ""
	}
}

func isLikelyParameter(name string) bool {
	stateNames := map[string]bool{
		"balances": true, "allowances": true, "operators": true,
		"tokenBalances": true, "tokenSupply": true, "tokenApproved": true,
		"vaultTotalAssets": true, "vaultTotalShares": true, "vaultShares": true,
		"vestSchedules": true, "vestClaimed": true, "vestCreators": true,
		"vestTotalLocked": true, "totalSupply": true,
	}
	return !stateNames[name]
}
