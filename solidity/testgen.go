package solidity

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// GenerateTests produces Foundry tests for a metamodel schema.
func GenerateTests(schema *metamodel.Schema) string {
	g := &testGenerator{schema: schema}
	return g.generate()
}

type testGenerator struct {
	schema *metamodel.Schema
}

func (g *testGenerator) generate() string {
	var b strings.Builder

	contractName := toContractName(g.schema.Name)

	b.WriteString("// SPDX-License-Identifier: MIT\n")
	b.WriteString("pragma solidity ^0.8.20;\n\n")
	b.WriteString("import \"forge-std/Test.sol\";\n")
	b.WriteString(fmt.Sprintf("import \"../src/%s.sol\";\n\n", contractName))

	b.WriteString(fmt.Sprintf("contract %sTest is Test {\n", contractName))
	b.WriteString(fmt.Sprintf("    %s public token;\n\n", contractName))

	b.WriteString("    address alice = address(0x1);\n")
	b.WriteString("    address bob = address(0x2);\n")
	b.WriteString("    address charlie = address(0x3);\n\n")

	b.WriteString("    function setUp() public {\n")
	b.WriteString(fmt.Sprintf("        token = new %s();\n", contractName))
	b.WriteString("    }\n\n")

	for _, action := range g.schema.Actions {
		b.WriteString(g.generateActionTest(action))
	}

	b.WriteString(g.generateRevertTests())
	b.WriteString(g.generateViewTests())

	b.WriteString("}\n")

	if len(g.schema.Constraints) > 0 {
		b.WriteString("\n")
		b.WriteString(g.generateInvariantTests(contractName))
	}

	return b.String()
}

func (g *testGenerator) generateActionTest(action metamodel.Action) string {
	var b strings.Builder

	funcName := action.ID
	params := g.inferTestParams(action)

	b.WriteString(fmt.Sprintf("    function test_%s() public {\n", funcName))

	// Setup: if action is privileged, prank as owner
	if isPrivilegedAction(funcName) {
		b.WriteString("        // Privileged action — called as contract owner\n")
	} else {
		b.WriteString("        vm.prank(alice);\n")
	}

	// If we need to mint first for transfer/burn/approve actions, add setup
	if funcName == "transfer" || funcName == "burn" || funcName == "approve" || funcName == "transferFrom" {
		b.WriteString("        // Setup: mint tokens first\n")
		if g.hasAction("mint") {
			b.WriteString("        token.mint(alice, 1000);\n")
			b.WriteString("        vm.prank(alice);\n")
		}
	}

	b.WriteString(fmt.Sprintf("        token.%s(%s);\n", funcName, params))
	b.WriteString("    }\n\n")

	return b.String()
}

func (g *testGenerator) generateRevertTests() string {
	var b strings.Builder

	for _, action := range g.schema.Actions {
		if action.Guard == "" {
			continue
		}

		funcName := action.ID
		b.WriteString(fmt.Sprintf("    function test_%s_reverts_on_invalid_guard() public {\n", funcName))
		b.WriteString("        vm.expectRevert();\n")

		if isPrivilegedAction(funcName) {
			b.WriteString("        // Non-owner call should revert\n")
			b.WriteString("        vm.prank(alice);\n")
		} else {
			b.WriteString("        vm.prank(charlie);\n")
		}

		// Call with zero/empty args to trigger guard failure
		params := g.inferZeroParams(action)
		b.WriteString(fmt.Sprintf("        token.%s(%s);\n", funcName, params))
		b.WriteString("    }\n\n")
	}

	return b.String()
}

func (g *testGenerator) generateViewTests() string {
	var b strings.Builder

	hasExported := false
	for _, state := range g.schema.States {
		if state.Exported {
			hasExported = true
			break
		}
	}

	if !hasExported {
		return ""
	}

	b.WriteString("    function test_view_functions() public view {\n")
	for _, state := range g.schema.States {
		if !state.Exported {
			continue
		}
		if strings.HasPrefix(state.Type, "map[") {
			// Map types need a key argument
			b.WriteString(fmt.Sprintf("        token.%s(alice);\n", state.ID))
		} else {
			b.WriteString(fmt.Sprintf("        token.%s();\n", state.ID))
		}
	}
	b.WriteString("    }\n\n")

	return b.String()
}

func (g *testGenerator) generateInvariantTests(contractName string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("contract %sInvariantTest is Test {\n", contractName))
	b.WriteString(fmt.Sprintf("    %s public token;\n\n", contractName))

	b.WriteString("    function setUp() public {\n")
	b.WriteString(fmt.Sprintf("        token = new %s();\n", contractName))
	b.WriteString("        targetContract(address(token));\n")
	b.WriteString("    }\n\n")

	for _, c := range g.schema.Constraints {
		b.WriteString(g.generateInvariantFunction(c))
	}

	b.WriteString("}\n")

	return b.String()
}

func (g *testGenerator) generateInvariantFunction(c metamodel.Constraint) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("    /// @dev Invariant: %s\n", c.Expr))
	b.WriteString(fmt.Sprintf("    function invariant_%s() public view {\n", c.ID))
	b.WriteString(fmt.Sprintf("        // TODO: implement check for: %s\n", c.Expr))
	b.WriteString("    }\n\n")

	return b.String()
}

func (g *testGenerator) inferTestParams(action metamodel.Action) string {
	params := collectArcParams(g.schema, action.ID)

	var parts []string
	for _, name := range sortedParams(params) {
		switch params[name] {
		case "address":
			if name == "to" || name == "beneficiary" || name == "receiver" {
				parts = append(parts, "bob")
			} else if name == "spender" || name == "operator" {
				parts = append(parts, "charlie")
			} else {
				parts = append(parts, "alice")
			}
		case "uint256":
			parts = append(parts, "100")
		case "bool":
			parts = append(parts, "true")
		default:
			parts = append(parts, "0")
		}
	}

	// Add guard-extracted params
	if action.Guard != "" {
		guardParams := extractGuardParams(action.Guard)
		for name := range guardParams {
			if _, exists := params[name]; !exists {
				parts = append(parts, "alice")
			}
		}
	}

	return strings.Join(parts, ", ")
}

func (g *testGenerator) inferZeroParams(action metamodel.Action) string {
	params := collectArcParams(g.schema, action.ID)

	var parts []string
	for _, name := range sortedParams(params) {
		switch params[name] {
		case "address":
			parts = append(parts, "address(0)")
		case "uint256":
			parts = append(parts, "0")
		case "bool":
			parts = append(parts, "false")
		default:
			parts = append(parts, "0")
		}
	}

	return strings.Join(parts, ", ")
}

func (g *testGenerator) hasAction(id string) bool {
	for _, a := range g.schema.Actions {
		if a.ID == id {
			return true
		}
	}
	return false
}

// collectArcParams gathers parameter names and types from arcs.
func collectArcParams(schema *metamodel.Schema, actionID string) map[string]string {
	params := make(map[string]string)

	for _, arc := range schema.InputArcs(actionID) {
		for _, key := range arc.Keys {
			params[key] = inferParamType(key)
		}
		if arc.Value != "" {
			params[arc.Value] = "uint256"
		}
	}

	for _, arc := range schema.OutputArcs(actionID) {
		for _, key := range arc.Keys {
			params[key] = inferParamType(key)
		}
		if arc.Value != "" {
			params[arc.Value] = "uint256"
		}
	}

	return params
}

// sortedParams returns param names in a stable order.
func sortedParams(params map[string]string) []string {
	order := []string{"caller", "from", "to", "owner", "spender", "operator", "receiver", "beneficiary", "id", "tokenId", "amount", "assets", "shares", "total", "claimAmount"}
	var result []string
	seen := make(map[string]bool)

	for _, name := range order {
		if _, ok := params[name]; ok {
			result = append(result, name)
			seen[name] = true
		}
	}
	for name := range params {
		if !seen[name] {
			result = append(result, name)
		}
	}
	return result
}

