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

	b.WriteString(g.generateFuzzTests())
	b.WriteString(g.generateViewTests())
	b.WriteString(g.generateEpochTests())

	b.WriteString("}\n\n")

	if len(g.schema.Constraints) > 0 {
		b.WriteString(g.generateInvariantTests(contractName))
	}

	return b.String()
}

func (g *testGenerator) generateActionTest(action metamodel.Action) string {
	return ""
}

func (g *testGenerator) generateFuzzTests() string {
	return ""
}

func (g *testGenerator) generateViewTests() string {
	return ""
}

func (g *testGenerator) generateEpochTests() string {
	return ""
}

func (g *testGenerator) getFunctionParams(_ metamodel.Action) []string {
	return nil
}

func (g *testGenerator) generateArcOperations(_ string) ([]string, []string) {
	return nil, nil
}

func (g *testGenerator) getFunctionParamsByName(_ string) []string {
	return nil
}

func (g *testGenerator) buildTestArgs(_ []string, _ string, _ string) string {
	return ""
}

func (g *testGenerator) buildApproveArgs(_ []string) string {
	return ""
}

func (g *testGenerator) buildTransferFromArgs(_ []string) string {
	return ""
}

func (g *testGenerator) buildVaultDepositArgs(_ []string) string {
	return ""
}

func (g *testGenerator) buildVestCreateArgs(_ []string) string {
	return ""
}

func (g *testGenerator) buildVestCreateArgsRevocable(_ []string) string {
	return ""
}

func (g *testGenerator) buildVestClaimArgs(_ []string, _ string) string {
	return ""
}

func (g *testGenerator) buildVestRevokeArgs(_ []string) string {
	return ""
}

func (g *testGenerator) buildTokenBurnArgs(_ []string) string {
	return ""
}

func (g *testGenerator) generateInvariantTests(_ string) string {
	return ""
}

func (g *testGenerator) generateHandlerFunctions(_ *strings.Builder) {
}

func (g *testGenerator) generateInvariantFunction(_ metamodel.Constraint) string {
	return ""
}

func buildTestAccessor(stateID string, keys []string) string {
	if len(keys) == 0 {
		return stateID
	}
	accessor := stateID
	for _, key := range keys {
		accessor += fmt.Sprintf("[%s]", key)
	}
	return accessor
}

func isTestMapType(t string) bool {
	return strings.HasPrefix(t, "map[")
}

func getTestMapValueType(mapType string) string {
	idx := strings.Index(mapType, "]")
	if idx == -1 {
		return ""
	}
	inner := mapType[idx+1:]
	if strings.HasPrefix(inner, "map[") {
		return getTestMapValueType(inner)
	}
	return inner
}

func extractBodyParamsFromCode(_, _ []string) map[string]bool {
	return make(map[string]bool)
}
