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

	if strings.HasPrefix(g.schema.Version, "Vote:") {
		b.WriteString("\n    function setUp() public {\n")
		b.WriteString("        // Deploy a mock verifier that always returns true\n")
		b.WriteString("        address mockVerifier = address(new MockVerifier());\n")
		b.WriteString(fmt.Sprintf("        token = new %s(0, 10, mockVerifier);\n", contractName))
		b.WriteString("    }\n\n")
	} else {
		b.WriteString("    function setUp() public {\n")
		b.WriteString(fmt.Sprintf("        token = new %s();\n", contractName))
		b.WriteString("    }\n\n")
	}

	for _, action := range g.schema.Actions {
		b.WriteString(g.generateActionTest(action))
	}

	b.WriteString(g.generateRevertTests())
	b.WriteString(g.generateViewTests())

	b.WriteString("}\n")

	// Vote-specific: add MockVerifier helper contract
	if strings.HasPrefix(g.schema.Version, "Vote:") {
		b.WriteString("\n/// @dev Mock verifier that always returns true (for testing only)\n")
		b.WriteString("contract MockVerifier {\n")
		b.WriteString("    function verifyProof(\n")
		b.WriteString("        uint256[2] calldata,\n")
		b.WriteString("        uint256[2][2] calldata,\n")
		b.WriteString("        uint256[2] calldata,\n")
		b.WriteString("        uint256[5] calldata\n")
		b.WriteString("    ) external pure returns (bool) {\n")
		b.WriteString("        return true;\n")
		b.WriteString("    }\n")
		b.WriteString("}\n")
	}

	if len(g.schema.Constraints) > 0 {
		b.WriteString("\n")
		b.WriteString(g.generateInvariantTests(contractName))
	}

	return b.String()
}

func (g *testGenerator) generateActionTest(action metamodel.Action) string {
	var b strings.Builder

	funcName := action.ID

	// Vote-specific: castVote has ZK proof signature
	if strings.HasPrefix(g.schema.Version, "Vote:") && funcName == "castVote" {
		b.WriteString("    function test_castVote() public {\n")
		b.WriteString("        // Setup: create poll first\n")
		b.WriteString("        token.createPoll();\n")
		b.WriteString("        // Cast vote with mock proof — choice is hidden in voteCommitment\n")
		b.WriteString("        uint256[2] memory pA = [uint256(0), uint256(0)];\n")
		b.WriteString("        uint256[2][2] memory pB = [[uint256(0), uint256(0)], [uint256(0), uint256(0)]];\n")
		b.WriteString("        uint256[2] memory pC = [uint256(0), uint256(0)];\n")
		b.WriteString("        uint256 nullifier = 42;\n")
		b.WriteString("        uint256 voteCommitment = 0xdeadbeef; // blinded hash of (secret, choice)\n")
		b.WriteString("        vm.prank(alice);\n")
		b.WriteString("        token.castVote(pA, pB, pC, nullifier, voteCommitment, 0);\n")
		b.WriteString("        // Verify nullifier is used and commitment stored\n")
		b.WriteString("        assertTrue(token.isNullifierUsed(42));\n")
		b.WriteString("        assertEq(token.voteCommitments(42), voteCommitment);\n")
		b.WriteString("    }\n\n")
		return b.String()
	}

	params := g.inferTestParams(action)
	b.WriteString(fmt.Sprintf("    function test_%s() public {\n", funcName))

	// Vote-specific: closePoll needs poll to be active first
	if strings.HasPrefix(g.schema.Version, "Vote:") && funcName == "closePoll" {
		b.WriteString("        // Setup: create poll first (as owner)\n")
		b.WriteString("        token.createPoll();\n")
	}

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

		// Vote-specific: castVote revert test uses ZK proof signature
		if strings.HasPrefix(g.schema.Version, "Vote:") && funcName == "castVote" {
			b.WriteString("    function test_castVote_reverts_on_double_vote() public {\n")
			b.WriteString("        token.createPoll();\n")
			b.WriteString("        uint256[2] memory pA;\n")
			b.WriteString("        uint256[2][2] memory pB;\n")
			b.WriteString("        uint256[2] memory pC;\n")
			b.WriteString("        // First vote succeeds\n")
			b.WriteString("        token.castVote(pA, pB, pC, 42, 0xabc, 0);\n")
			b.WriteString("        // Second vote with same nullifier reverts\n")
			b.WriteString("        vm.expectRevert(\"already voted\");\n")
			b.WriteString("        token.castVote(pA, pB, pC, 42, 0xdef, 0);\n")
			b.WriteString("    }\n\n")

			b.WriteString("    function test_castVote_reverts_when_poll_inactive() public {\n")
			b.WriteString("        // Poll not started — pollConfig == 0\n")
			b.WriteString("        uint256[2] memory pA;\n")
			b.WriteString("        uint256[2][2] memory pB;\n")
			b.WriteString("        uint256[2] memory pC;\n")
			b.WriteString("        vm.expectRevert(\"poll not active\");\n")
			b.WriteString("        token.castVote(pA, pB, pC, 42, 0xabc, 0);\n")
			b.WriteString("    }\n\n")
			continue
		}

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
			// Map types need a key argument — determine key type
			keyArg := "alice" // default: address key
			if strings.HasPrefix(state.Type, "map[uint256]") {
				keyArg = "1"
			}
			b.WriteString(fmt.Sprintf("        token.%s(%s);\n", state.ID, keyArg))
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
	if strings.HasPrefix(g.schema.Version, "Vote:") {
		b.WriteString(fmt.Sprintf("        token = new %s(0, 10, address(new MockVerifier()));\n", contractName))
	} else {
		b.WriteString(fmt.Sprintf("        token = new %s();\n", contractName))
	}
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

	// Translate constraint expression to Solidity assertion
	solExpr := translateConstraintExpr(c.Expr, g.schema)
	if solExpr != "" {
		b.WriteString(fmt.Sprintf("        assertTrue(%s, \"%s\");\n", solExpr, c.ID))
	} else {
		b.WriteString(fmt.Sprintf("        // Complex constraint — verify manually: %s\n", c.Expr))
	}

	b.WriteString("    }\n\n")

	return b.String()
}

// translateConstraintExpr converts a metamodel constraint expression to Solidity.
// Handles common patterns like "sum(X) == Y", "sum(X) + Y == Z", "forall id: ...".
func translateConstraintExpr(expr string, schema *metamodel.Schema) string {
	expr = strings.TrimSpace(expr)

	// "forall" constraints are too complex for direct translation
	if strings.HasPrefix(expr, "forall") {
		return ""
	}

	// Replace sum("field") with a helper call pattern
	// sum("balances") → sumBalances()
	result := expr
	for _, state := range schema.States {
		sumPattern := fmt.Sprintf(`sum("%s")`, state.ID)
		if strings.Contains(result, sumPattern) {
			// For map types, sum requires iteration — can't inline in Solidity view
			// Use a placeholder that the developer implements
			return ""
		}
	}

	// Simple equality expressions: "X == Y" where X and Y are state vars
	// Convert to Solidity: token.X() == token.Y()
	if strings.Contains(result, "==") {
		parts := strings.SplitN(result, "==", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		return fmt.Sprintf("token.%s() == token.%s()", left, right)
	}

	return ""
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

	// Add guard-extracted params (excluding state variables and literals)
	if action.Guard != "" {
		guardParams := extractGuardParams(action.Guard)
		for _, state := range g.schema.States {
			delete(guardParams, state.ID)
		}
		delete(guardParams, "caller")
		for name := range guardParams {
			if _, exists := params[name]; !exists && !isLiteralValue(name) {
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
		if arc.Value != "" && !isLiteralValue(arc.Value) {
			params[arc.Value] = "uint256"
		}
	}

	for _, arc := range schema.OutputArcs(actionID) {
		for _, key := range arc.Keys {
			params[key] = inferParamType(key)
		}
		if arc.Value != "" && !isLiteralValue(arc.Value) {
			params[arc.Value] = "uint256"
		}
	}

	// Remove state variable names — these are contract storage, not function params
	for _, state := range schema.States {
		delete(params, state.ID)
	}
	delete(params, "caller")

	return params
}

// sortedParams returns param names in a stable order.
func sortedParams(params map[string]string) []string {
	order := []string{"caller", "from", "to", "owner", "spender", "operator", "receiver", "beneficiary", "id", "tokenId", "nullifier", "choice", "pollId", "commitment", "weight", "amount", "assets", "shares", "total", "claimAmount"}
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

