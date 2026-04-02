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

	// Vault deposit/mint/withdraw/redeem need external asset balances that can't be
	// seeded from within the contract. Test that the guard reverts on zero-value call.
	if g.isVaultAction(funcName) {
		zeroParams := g.inferZeroParams(action)
		b.WriteString("        // Vault action requires external asset setup — test guard revert\n")
		b.WriteString("        vm.expectRevert();\n")
		b.WriteString(fmt.Sprintf("        token.%s(%s);\n", funcName, zeroParams))
		b.WriteString("    }\n\n")
		return b.String()
	}

	// If action consumes tokens, mint first (as owner)
	if g.needsMintSetup(funcName) && g.hasAction("mint") {
		b.WriteString("        // Setup: mint tokens first (as owner)\n")
		b.WriteString(fmt.Sprintf("        %s\n", g.mintSetupCall()))
		// For transferFrom, also need approve setup
		if funcName == "transferFrom" && g.hasAction("approve") {
			b.WriteString("        // Setup: approve alice's tokens for spending\n")
			b.WriteString("        vm.prank(alice);\n")
			b.WriteString(fmt.Sprintf("        %s\n", g.approveSetupCall()))
		}
	}

	// Prank as non-owner for non-privileged actions
	if !isPrivilegedAction(funcName) {
		b.WriteString("        vm.prank(alice);\n")
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
			// Map types need key arguments — determine from type nesting
			keyArgs := inferMapKeyArgs(state.Type)
			b.WriteString(fmt.Sprintf("        token.%s(%s);\n", state.ID, strings.Join(keyArgs, ", ")))
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
	params := g.collectFunctionParams(action)

	var parts []string
	for _, name := range sortedParams(params) {
		parts = append(parts, g.testValueForParam(name, params[name]))
	}

	return strings.Join(parts, ", ")
}

// testValueForParam returns an appropriate test value for a given parameter name and type.
func (g *testGenerator) testValueForParam(name, typ string) string {
	switch typ {
	case "address":
		if name == "to" || name == "beneficiary" || name == "receiver" {
			return "bob"
		} else if name == "spender" || name == "operator" {
			return "charlie"
		}
		return "alice"
	case "uint256":
		return "100"
	case "bool":
		return "true"
	default:
		return "0"
	}
}

// collectFunctionParams collects all parameters matching the codegen function signature.
// This ensures testgen generates calls with the correct argument count and types.
func (g *testGenerator) collectFunctionParams(action metamodel.Action) map[string]string {
	params := make(map[string]string)

	for _, arc := range g.schema.InputArcs(action.ID) {
		for _, key := range arc.Keys {
			params[key] = inferParamType(key)
		}
		if arc.Value != "" && !isLiteralValue(arc.Value) {
			params[arc.Value] = inferParamType(arc.Value)
		}
	}

	for _, arc := range g.schema.OutputArcs(action.ID) {
		for _, key := range arc.Keys {
			params[key] = inferParamType(key)
		}
		if arc.Value != "" && !isLiteralValue(arc.Value) {
			params[arc.Value] = inferParamType(arc.Value)
		}
	}

	// Add guard-extracted params with proper types
	if action.Guard != "" {
		guardParams := extractGuardParams(action.Guard)
		for name, typ := range guardParams {
			if _, exists := params[name]; !exists {
				params[name] = typ
			}
		}
	}

	delete(params, "caller")
	for _, state := range g.schema.States {
		delete(params, state.ID)
	}

	// Build output target set for read-arc detection (same as codegen).
	// Input arcs where the same state+keys also appears as output are reads, not consumes.
	outputTargets := make(map[string]bool)
	for _, arc := range g.schema.OutputArcs(action.ID) {
		key := arc.Target + "|" + strings.Join(arc.Keys, ",")
		outputTargets[key] = true
	}

	// Add default "amount" for arcs with empty Value on MAP states.
	// Skip read arcs (input+output to same state) and scalar states (use literal 1).
	needsAmount := false
	for _, arc := range g.schema.InputArcs(action.ID) {
		if arc.Value == "" {
			inputKey := arc.Source + "|" + strings.Join(arc.Keys, ",")
			if outputTargets[inputKey] {
				continue // read arc — codegen skips the decrement, no "amount" needed
			}
			state := g.schema.StateByID(arc.Source)
			if state != nil && isMapType(state.Type) && g.isNumericState(state) {
				needsAmount = true
			}
		}
	}
	for _, arc := range g.schema.OutputArcs(action.ID) {
		if arc.Value == "" {
			state := g.schema.StateByID(arc.Target)
			if state != nil && isMapType(state.Type) && g.isNumericState(state) {
				needsAmount = true
			}
		}
	}
	if needsAmount {
		params["amount"] = "uint256"
	}

	// Add VestingSchedule struct fields for struct output arcs
	for _, arc := range g.schema.OutputArcs(action.ID) {
		state := g.schema.StateByID(arc.Target)
		if state != nil && strings.Contains(state.Type, "VestingSchedule") && arc.Value == "schedule" {
			for _, f := range []string{"start", "cliff", "end", "total", "revocable"} {
				params[f] = inferParamType(f)
			}
		}
	}

	return params
}

func (g *testGenerator) inferZeroParams(action metamodel.Action) string {
	params := g.collectFunctionParams(action)

	var parts []string
	for _, name := range sortedParams(params) {
		switch params[name] {
		case "address":
			parts = append(parts, "address(0)")
		case "uint256":
			// Use 1 for amounts so guards like "balances[from] >= amount" actually fail
			// (0 >= 0 would pass, but 0 >= 1 fails)
			if name == "amount" || name == "assets" || name == "shares" || name == "total" || name == "claimAmount" {
				parts = append(parts, "1")
			} else {
				parts = append(parts, "0")
			}
		case "bool":
			parts = append(parts, "false")
		default:
			parts = append(parts, "0")
		}
	}

	return strings.Join(parts, ", ")
}

// isNumericState returns true if the state stores uint256 values (not address, bool, or structs).
func (g *testGenerator) isNumericState(state *metamodel.State) bool {
	if strings.Contains(state.Type, "VestingSchedule") {
		return false
	}
	if isMapType(state.Type) {
		vt := getMapValueType(state.Type)
		return vt != "address" && vt != "bool" && vt != ""
	}
	return state.Type == "uint256" || state.Type == ""
}

// needsMintSetup returns true for actions that consume tokens and need minting first.
func (g *testGenerator) needsMintSetup(funcName string) bool {
	switch funcName {
	case "transfer", "burn", "approve", "transferFrom",
		"safeTransferFrom", "safeBatchTransferFrom", "burnBatch":
		return true
	}
	return false
}

// isVaultAction returns true for vault actions that need external asset setup.
func (g *testGenerator) isVaultAction(funcName string) bool {
	if !strings.HasPrefix(g.schema.Version, "ERC-04626:") {
		return false
	}
	switch funcName {
	case "deposit", "mint", "withdraw", "redeem":
		return true
	}
	return false
}

// mintSetupCall returns the Solidity call to mint tokens for test setup.
// Uses tokenId=100 to match the default test param, so approve(100, ...) works.
func (g *testGenerator) mintSetupCall() string {
	for _, action := range g.schema.Actions {
		if action.ID != "mint" {
			continue
		}
		params := g.collectFunctionParams(action)
		var parts []string
		for _, name := range sortedParams(params) {
			switch name {
			case "to", "beneficiary", "receiver":
				parts = append(parts, "alice")
			case "tokenId", "id":
				parts = append(parts, "100") // matches default test param
			case "amount", "total", "nftAmount":
				parts = append(parts, "1000")
			case "shares", "assets":
				parts = append(parts, "1000")
			default:
				parts = append(parts, g.testValueForParam(name, params[name]))
			}
		}
		return fmt.Sprintf("token.mint(%s);", strings.Join(parts, ", "))
	}
	return "token.mint(alice, 1000);"
}

// approveSetupCall returns the Solidity call to approve tokens for transferFrom setup.
func (g *testGenerator) approveSetupCall() string {
	for _, action := range g.schema.Actions {
		if action.ID != "approve" {
			continue
		}
		params := g.collectFunctionParams(action)
		var parts []string
		for _, name := range sortedParams(params) {
			switch name {
			case "owner", "from":
				parts = append(parts, "alice")
			case "spender", "operator", "to":
				parts = append(parts, "charlie")
			case "amount":
				parts = append(parts, "1000")
			case "tokenId", "id":
				parts = append(parts, "1")
			case "isApproved", "approved":
				parts = append(parts, "true")
			default:
				parts = append(parts, g.testValueForParam(name, params[name]))
			}
		}
		return fmt.Sprintf("token.approve(%s);", strings.Join(parts, ", "))
	}
	return "token.approve(alice, charlie, 1000);"
}

func (g *testGenerator) hasAction(id string) bool {
	for _, a := range g.schema.Actions {
		if a.ID == id {
			return true
		}
	}
	return false
}

// inferMapKeyArgs returns test argument values for a Solidity mapping's key types.
// e.g., "map[address]uint256" → ["alice"], "map[address]map[address]uint256" → ["alice", "bob"],
// "map[uint256]map[address]uint256" → ["1", "alice"]
func inferMapKeyArgs(mapType string) []string {
	var args []string
	remaining := mapType
	for strings.HasPrefix(remaining, "map[") {
		// Extract key type between [ and ]
		close := strings.Index(remaining, "]")
		if close == -1 {
			break
		}
		keyType := remaining[4:close]
		switch keyType {
		case "address":
			if len(args) == 0 {
				args = append(args, "alice")
			} else {
				args = append(args, "bob")
			}
		case "uint256":
			args = append(args, "1")
		default:
			args = append(args, "0")
		}
		remaining = remaining[close+1:]
	}
	return args
}

// sortedParams returns param names in a stable order.
func sortedParams(params map[string]string) []string {
	order := []string{"caller", "from", "to", "owner", "spender", "operator", "receiver", "beneficiary", "id", "tokenId", "nullifier", "choice", "pollId", "commitment", "weight", "amount", "assets", "shares", "approved", "isApproved", "total", "claimAmount", "nftAmount", "unvestedAmount", "yieldAmount", "start", "cliff", "end", "revocable"}
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

