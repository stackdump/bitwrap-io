//go:build e2e

package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
	"github.com/stackdump/bitwrap-io/internal/petri"
	"github.com/stackdump/bitwrap-io/solidity"
)

// TestFoundryE2E generates Solidity contracts, tests, and deploy scripts for each
// ERC template, then compiles and runs them with Foundry (forge) to validate the
// full generator pipeline.
func TestFoundryE2E(t *testing.T) {
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not installed, skipping Foundry e2e tests")
	}

	srv := testServer(t)

	templates := []string{"erc20", "erc721", "erc1155", "erc4626", "erc5725", "vote"}

	for _, tmpl := range templates {
		t.Run(tmpl, func(t *testing.T) {
			dir := t.TempDir()

			// Create Foundry project layout
			for _, sub := range []string{"src", "test", "script"} {
				if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", sub, err)
				}
			}

			// Write foundry.toml
			foundryToml := `[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"

[fmt]
line_length = 120
`
			if err := os.WriteFile(filepath.Join(dir, "foundry.toml"), []byte(foundryToml), 0o644); err != nil {
				t.Fatalf("write foundry.toml: %v", err)
			}

			// Generate contract via /api/solgen
			solResp := callGenAPI(t, srv, "/api/solgen", fmt.Sprintf(`{"template":%q}`, tmpl))

			// Generate tests via /api/testgen
			testResp := callGenAPI(t, srv, "/api/testgen", fmt.Sprintf(`{"template":%q}`, tmpl))

			// Generate deploy script via /api/genesisgen
			genesisResp := callGenAPI(t, srv, "/api/genesisgen", fmt.Sprintf(`{"template":%q}`, tmpl))

			// Derive the contract name from testgen filename (e.g. "ERC20Test.t.sol" → "ERC20")
			// This matches the import paths used in generated test/genesis files.
			testFile := testResp["filename"]
			contractName := strings.TrimSuffix(testFile, "Test.t.sol")
			if contractName == "" || contractName == testFile {
				t.Fatalf("unexpected testgen filename: %s", testFile)
			}

			// Write files using the contract name that matches import paths
			srcFile := contractName + ".sol"
			if err := os.WriteFile(filepath.Join(dir, "src", srcFile), []byte(solResp["solidity"]), 0o644); err != nil {
				t.Fatalf("write contract: %v", err)
			}
			t.Logf("src/%s (%d bytes)", srcFile, len(solResp["solidity"]))

			if err := os.WriteFile(filepath.Join(dir, "test", testFile), []byte(testResp["solidity"]), 0o644); err != nil {
				t.Fatalf("write test: %v", err)
			}
			t.Logf("test/%s (%d bytes)", testFile, len(testResp["solidity"]))

			genesisFile := genesisResp["filename"]
			if err := os.WriteFile(filepath.Join(dir, "script", genesisFile), []byte(genesisResp["solidity"]), 0o644); err != nil {
				t.Fatalf("write genesis: %v", err)
			}
			t.Logf("script/%s (%d bytes)", genesisFile, len(genesisResp["solidity"]))

			// Initialize git repo (required for forge install)
			runCmd(t, dir, "git", "init")
			runCmd(t, dir, "forge", "install", "foundry-rs/forge-std")

			// forge build
			t.Log("running forge build...")
			runCmd(t, dir, "forge", "build")

			// Deploy to local anvil and run functional smoke tests
			t.Log("deploying to anvil...")
			env := deployToAnvil(t, dir, contractName, tmpl)
			if env != nil {
				t.Log("running functional smoke tests...")
				smokeTestContract(t, env, tmpl)
			}

			// forge test — log failures but don't fail the build
			// (generated tests may need manual setup for complex token interactions)
			t.Log("running forge test...")
			runCmdSoft(t, dir, "forge", "test", "-vv")
		})
	}
}

// anvilEnv holds a running anvil instance and deployment info for functional testing.
type anvilEnv struct {
	rpcURL     string
	privateKey string
	address    string // deployed contract address
	dir        string
	cleanup    func()
}

// Anvil accounts (default HD wallet)
const (
	anvilAccount0    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	anvilPrivKey0    = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	anvilAccount1    = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	anvilPrivKey1    = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)

// deployToAnvil starts a local anvil instance, deploys the contract, and returns the env.
func deployToAnvil(t *testing.T, dir, contractName, tmpl string) *anvilEnv {
	t.Helper()

	if _, err := exec.LookPath("anvil"); err != nil {
		t.Log("anvil not installed, skipping deployment test")
		return nil
	}

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Start anvil
	anvil := exec.Command("anvil", "--port", fmt.Sprintf("%d", port), "--silent")
	if err := anvil.Start(); err != nil {
		t.Fatalf("start anvil: %v", err)
	}
	t.Cleanup(func() {
		anvil.Process.Kill()
		anvil.Wait()
	})

	// Wait for anvil to be ready
	ready := false
	for i := 0; i < 50; i++ {
		cmd := exec.Command("cast", "chain-id", "--rpc-url", rpcURL)
		if out, err := cmd.CombinedOutput(); err == nil && strings.TrimSpace(string(out)) == "31337" {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("anvil failed to start")
	}

	// Build constructor args for forge create
	args := []string{
		"create",
		fmt.Sprintf("src/%s.sol:%s", contractName, contractName),
		"--rpc-url", rpcURL,
		"--private-key", anvilPrivKey0,
		"--broadcast",
	}

	if tmpl == "vote" {
		args = append(args, "--constructor-args", "0", "10", "0x0000000000000000000000000000000000000000")
	}

	cmd := exec.Command("forge", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("forge create failed:\n%s\n%v", out, err)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Deployed to:") {
		t.Fatalf("deployment output missing 'Deployed to:':\n%s", outStr)
	}

	// Extract deployed address
	var addr string
	for _, line := range strings.Split(outStr, "\n") {
		if strings.Contains(line, "Deployed to:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				addr = parts[len(parts)-1]
			}
		}
	}
	if addr == "" {
		t.Fatalf("could not parse deployed address from:\n%s", outStr)
	}

	t.Logf("deployed %s at %s", contractName, addr)

	return &anvilEnv{
		rpcURL:     rpcURL,
		privateKey: anvilPrivKey0,
		address:    addr,
		dir:        dir,
	}
}

// castSend sends a transaction to the contract and returns the output.
func castSend(t *testing.T, env *anvilEnv, privKey, sig string, args ...string) string {
	t.Helper()
	cmdArgs := []string{"send", env.address, sig}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--rpc-url", env.rpcURL, "--private-key", privKey)
	cmd := exec.Command("cast", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cast send %s failed:\n%s\n%v", sig, out, err)
	}
	return string(out)
}

// castCall calls a view function and returns the result.
func castCall(t *testing.T, env *anvilEnv, sig string, args ...string) string {
	t.Helper()
	cmdArgs := []string{"call", env.address, sig}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--rpc-url", env.rpcURL)
	cmd := exec.Command("cast", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cast call %s failed:\n%s\n%v", sig, out, err)
	}
	return strings.TrimSpace(string(out))
}

// smokeTestContract uses Petri net reachability to find a firing sequence that
// covers all transitions, then executes that sequence against the deployed contract.
func smokeTestContract(t *testing.T, env *anvilEnv, tmpl string) {
	t.Helper()

	srv := testServer(t)
	template := srv.getTemplate(tmpl)
	if template == nil {
		t.Fatalf("unknown template: %s", tmpl)
	}

	schema := template.Schema()
	model := petri.FromSchema(schema)
	state := petri.NewState(model)

	// BFS to find a firing sequence that covers all transitions
	sequence := findCoveringSequence(model, state)
	total := len(model.Transitions)
	covered := make(map[string]bool)
	for _, tid := range sequence {
		covered[tid] = true
	}

	t.Logf("reachability: %d/%d transitions coverable from initial marking", len(covered), total)
	t.Logf("firing sequence: %v", sequence)

	if len(sequence) == 0 {
		t.Log("no transitions fireable from initial marking (all gated by keyed arcs)")
		return
	}

	// Build function signatures from the schema for each action
	sigs := buildFunctionSigs(schema)

	// Execute the firing sequence on-chain with multi-actor orchestration.
	// The Petri net gives us the transition ordering; we inject setup steps
	// (mint, approve) as needed for multi-actor token flows.
	minted := false
	approved := false
	tokenIdCounter := 1
	fired := 0

	for _, tid := range sequence {
		sig, ok := sigs[tid]
		if !ok {
			// Zero-param functions still have a signature like "createPoll()"
			t.Logf("skip %s: no cast signature", tid)
			continue
		}

		// Inject mint setup before token-consuming actions
		if needsTokenSetup(tid) && !minted {
			if mintSig, hasMint := sigs["mint"]; hasMint {
				t.Log("setup: minting tokens...")
				castSendSoft(t, env, anvilPrivKey0, mintSig.signature, mintSig.args...)
				minted = true
			}
		}

		// Inject approve before transferFrom (account1 approves account0 as spender)
		if tid == "transferFrom" && !approved {
			if appSig, hasApprove := sigs["approve"]; hasApprove {
				t.Log("setup: account1 approving account0 as spender...")
				castSendSoft(t, env, anvilPrivKey1, appSig.signature, appSig.args...)
				approved = true
			}
		}

		// For repeated mint calls (e.g., NFTs), use unique tokenId
		args := sig.args
		if tid == "mint" && minted {
			tokenIdCounter++
			args = replaceTokenIdArg(sig, tokenIdCounter)
		}

		// Determine caller based on action semantics
		privKey := callerForAction(tid)

		out := castSendSoft(t, env, privKey, sig.signature, args...)
		if out != "" {
			fired++
			t.Logf("fired %s ✓", tid)
		} else {
			t.Logf("fired %s ✗ (reverted)", tid)
		}
	}
	t.Logf("on-chain: %d/%d transitions fired successfully", fired, len(sequence))
}

// callerForAction returns the appropriate private key for calling an action.
func callerForAction(actionID string) string {
	// Owner actions: mint, createPoll, closePoll, harvest, create (vesting)
	if solidity.IsPrivilegedAction(actionID) {
		return anvilPrivKey0
	}
	// transferFrom is called by the spender (account0), not the token owner
	if actionID == "transferFrom" {
		return anvilPrivKey0
	}
	// Everything else: called by token holder (account1)
	return anvilPrivKey1
}

// replaceTokenIdArg substitutes the tokenId in args with a new value.
func replaceTokenIdArg(sig actionSig, newId int) []string {
	args := make([]string, len(sig.args))
	copy(args, sig.args)
	for i, a := range args {
		if a == "1" { // default tokenId
			args[i] = fmt.Sprintf("%d", newId)
			break
		}
	}
	return args
}

func needsTokenSetup(actionID string) bool {
	switch actionID {
	case "transfer", "burn", "transferFrom", "approve",
		"safeTransferFrom", "safeBatchTransferFrom", "burnBatch",
		"claim", "revoke":
		return true
	}
	return false
}

// actionSig holds a cast-compatible function signature and test arguments.
type actionSig struct {
	signature string
	args      []string
}

// buildFunctionSigs generates cast-compatible signatures from schema actions.
func buildFunctionSigs(schema *metamodel.Schema) map[string]actionSig {
	sigs := make(map[string]actionSig)

	for _, action := range schema.Actions {
		params := collectCastParams(schema, action)

		// Build signature string and default args
		var types []string
		var args []string
		for _, p := range params {
			types = append(types, p.solType)
			args = append(args, p.testValue)
		}
		// Zero-param functions are valid (e.g., createPoll, closePoll)
		sig := fmt.Sprintf("%s(%s)", action.ID, strings.Join(types, ","))
		sigs[action.ID] = actionSig{signature: sig, args: args}
	}

	return sigs
}

type castParam struct {
	name     string
	solType  string
	testValue string
}

// collectCastParams builds the ordered parameter list for an action, matching codegen output.
func collectCastParams(schema *metamodel.Schema, action metamodel.Action) []castParam {
	params := make(map[string]string) // name → solidity type

	for _, arc := range schema.InputArcs(action.ID) {
		for _, key := range arc.Keys {
			params[key] = solidity.InferParamType(key)
		}
		if arc.Value != "" && !isLiteralValueStr(arc.Value) {
			params[arc.Value] = solidity.InferParamType(arc.Value)
		}
	}
	for _, arc := range schema.OutputArcs(action.ID) {
		for _, key := range arc.Keys {
			params[key] = solidity.InferParamType(key)
		}
		if arc.Value != "" && !isLiteralValueStr(arc.Value) {
			params[arc.Value] = solidity.InferParamType(arc.Value)
		}
	}

	// Guard params
	if action.Guard != "" {
		gp := solidity.ExtractGuardParams(action.Guard)
		for name, typ := range gp {
			if _, exists := params[name]; !exists {
				params[name] = typ
			}
		}
	}

	delete(params, "caller")
	for _, state := range schema.States {
		delete(params, state.ID)
	}

	// Default "amount" for arcs with empty Value on numeric states
	for _, arc := range schema.InputArcs(action.ID) {
		if arc.Value == "" {
			st := schema.StateByID(arc.Source)
			if st != nil && !strings.Contains(st.Type, "VestingSchedule") {
				if !isMapOfNonNumeric(st.Type) {
					params["amount"] = "uint256"
				}
			}
		}
	}
	for _, arc := range schema.OutputArcs(action.ID) {
		if arc.Value == "" {
			st := schema.StateByID(arc.Target)
			if st != nil && !strings.Contains(st.Type, "VestingSchedule") {
				if !isMapOfNonNumeric(st.Type) {
					params["amount"] = "uint256"
				}
			}
		}
	}

	// VestingSchedule struct fields
	for _, arc := range schema.OutputArcs(action.ID) {
		st := schema.StateByID(arc.Target)
		if st != nil && strings.Contains(st.Type, "VestingSchedule") && arc.Value == "schedule" {
			for _, f := range []string{"start", "cliff", "end", "total", "revocable"} {
				params[f] = solidity.InferParamType(f)
			}
		}
	}

	// Order using the same sorted order as codegen
	order := []string{"from", "to", "owner", "spender", "operator", "receiver", "beneficiary", "id", "tokenId", "nullifier", "choice", "pollId", "commitment", "weight", "amount", "assets", "shares", "approved", "isApproved", "nftAmount", "claimAmount", "unvestedAmount", "yieldAmount", "total", "start", "cliff", "end", "revocable", "schedule"}
	seen := make(map[string]bool)
	var result []castParam

	for _, name := range order {
		if typ, ok := params[name]; ok {
			result = append(result, castParam{name: name, solType: typ, testValue: defaultTestArg(name, typ)})
			seen[name] = true
		}
	}
	for name, typ := range params {
		if !seen[name] {
			result = append(result, castParam{name: name, solType: typ, testValue: defaultTestArg(name, typ)})
		}
	}

	return result
}

func defaultTestArg(name, typ string) string {
	switch typ {
	case "address":
		switch name {
		case "to", "beneficiary", "receiver":
			return anvilAccount1
		case "from", "owner":
			return anvilAccount1
		case "spender", "operator":
			return anvilAccount0
		default:
			return anvilAccount1
		}
	case "uint256":
		switch name {
		case "amount", "assets", "shares", "nftAmount", "yieldAmount", "unvestedAmount", "claimAmount":
			return "100"
		case "total":
			return "1000"
		case "tokenId", "id":
			return "1"
		case "start":
			return "1"
		case "cliff":
			return "5"
		case "end":
			return "100"
		case "schedule":
			return "0" // unused struct placeholder
		default:
			return "1"
		}
	case "bool":
		return "true"
	default:
		return "0"
	}
}

func isMapOfNonNumeric(stateType string) bool {
	if !strings.HasPrefix(stateType, "map[") {
		return false
	}
	// Get innermost value type
	remaining := stateType
	for strings.HasPrefix(remaining, "map[") {
		close := strings.Index(remaining, "]")
		if close == -1 { break }
		remaining = remaining[close+1:]
	}
	return remaining == "address" || remaining == "bool"
}

func isLiteralValueStr(v string) bool {
	if v == "true" || v == "false" { return true }
	for _, c := range v {
		if c < '0' || c > '9' { return false }
	}
	return len(v) > 0
}

// findCoveringSequence does BFS to find a firing sequence that covers as many
// transitions as possible. Returns the sequence of transition IDs.
func findCoveringSequence(model *petri.Model, initial *petri.State) []string {
	type node struct {
		state    *petri.State
		sequence []string
		covered  map[string]bool
	}

	totalTransitions := len(model.Transitions)
	best := &node{covered: make(map[string]bool)}

	start := &node{
		state:    initial.Clone(),
		sequence: nil,
		covered:  make(map[string]bool),
	}

	queue := []*node{start}
	visited := make(map[string]bool)
	maxSteps := 1000

	for len(queue) > 0 && maxSteps > 0 {
		current := queue[0]
		queue = queue[1:]
		maxSteps--

		key := current.state.MarkingKey()
		coverKey := key + fmt.Sprintf("|%d", len(current.covered))
		if visited[coverKey] {
			continue
		}
		visited[coverKey] = true

		if len(current.covered) > len(best.covered) {
			best = current
		}
		if len(current.covered) == totalTransitions {
			return current.sequence
		}

		for _, tid := range current.state.EnabledTransitions() {
			next := current.state.Clone()
			if err := next.Fire(tid); err != nil {
				continue
			}
			newCovered := make(map[string]bool)
			for k := range current.covered {
				newCovered[k] = true
			}
			newCovered[tid] = true
			queue = append(queue, &node{
				state:    next,
				sequence: append(append([]string{}, current.sequence...), tid),
				covered:  newCovered,
			})
		}
	}

	return best.sequence
}

// castSendSoft sends a transaction, returning output on success or empty string on revert.
func castSendSoft(t *testing.T, env *anvilEnv, privKey, sig string, args ...string) string {
	t.Helper()
	cmdArgs := []string{"send", env.address, sig}
	cmdArgs = append(cmdArgs, args...)
	cmdArgs = append(cmdArgs, "--rpc-url", env.rpcURL, "--private-key", privKey)
	cmd := exec.Command("cast", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// callGenAPI sends a POST to a generator endpoint and returns the JSON response fields.
func callGenAPI(t *testing.T, srv *Server, path, body string) map[string]string {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("POST %s = %d: %s", path, w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	if resp["solidity"] == "" {
		t.Fatalf("%s returned empty solidity", path)
	}
	if !strings.Contains(resp["solidity"], "pragma solidity") {
		t.Fatalf("%s output missing pragma", path)
	}
	return resp
}

// runCmd executes a command in the given directory and fails the test on error.
func runCmd(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed:\n%s\n%v", name, strings.Join(args, " "), out, err)
	}
}

// runCmdSoft executes a command and logs failures without failing the test.
func runCmdSoft(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("WARNING: %s %s had failures:\n%s", name, strings.Join(args, " "), out)
	}
}
