package solidity

import (
	"fmt"
	"strings"
)

// GenesisAction represents a single action to execute at genesis.
type GenesisAction struct {
	Action   string         `json:"action"`
	Bindings map[string]any `json:"bindings"`
}

// GenesisConfig holds the configuration for genesis block initialization.
type GenesisConfig struct {
	Actions     []GenesisAction `json:"actions"`
	TotalEpochs int             `json:"totalEpochs,omitempty"`
}

// GenerateGenesis produces a Foundry script that executes genesis actions.
func GenerateGenesis(contractName string, config GenesisConfig, addresses map[string]string) string {
	g := &genesisGenerator{contractName: contractName, config: config, addresses: addresses}
	return g.generate()
}

// DefaultAddresses returns standard anvil test addresses.
func DefaultAddresses() map[string]string {
	return map[string]string{
		"treasury": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"alice":    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"bob":      "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		"charlie":  "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
		"diana":    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
		"eve":      "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
		"frank":    "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
	}
}

// DefaultPrivateKeys returns anvil private keys.
func DefaultPrivateKeys() map[string]string {
	return map[string]string{
		"treasury": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"alice":    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
		"bob":      "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
		"charlie":  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
		"diana":    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
		"eve":      "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
		"frank":    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
	}
}

type genesisGenerator struct {
	contractName string
	config       GenesisConfig
	addresses    map[string]string
}

func (g *genesisGenerator) generate() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("// Genesis script for %s\n", g.contractName))
	return b.String()
}
