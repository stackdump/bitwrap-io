package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackdump/bitwrap-io/dsl"
	"github.com/stackdump/bitwrap-io/internal/server"
	"github.com/stackdump/bitwrap-io/public"
	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/solidity"
)

func main() {
	port := flag.Int("port", 8088, "Port to listen on")
	dataDir := flag.String("data", "./data", "Data directory for storage")
	noProver := flag.Bool("no-prover", false, "Disable ZK prover (faster startup)")
	noSolgen := flag.Bool("no-solgen", false, "Disable Solidity generation endpoints")
	keyDir := flag.String("key-dir", "", "Directory for persistent circuit keys (enables fast restarts)")
	devMode := flag.Bool("dev", false, "Enable dev mode (built-in test wallet, /api/dev/* endpoints)")
	compile := flag.String("compile", "", "Compile a .btw file and output JSON schema to stdout")
	validate := flag.String("validate", "", "Validate a .btw file: compile → generate Solidity → forge build → forge test → deploy")
	output := flag.String("output", "", "Save generated Foundry project to this directory (use with -validate)")
	flag.Parse()

	if *compile != "" {
		src, err := os.ReadFile(*compile)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", *compile, err)
		}
		ast, err := dsl.Parse(string(src))
		if err != nil {
			log.Fatalf("Parse error: %v", err)
		}
		schema, err := dsl.Build(ast)
		if err != nil {
			log.Fatalf("Build error: %v", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(schema); err != nil {
			log.Fatalf("JSON encode error: %v", err)
		}
		return
	}

	if *validate != "" {
		os.Exit(runValidate(*validate, *output))
	}

	storage := store.NewFSStore(*dataDir)

	publicFS, err := public.FS()
	if err != nil {
		log.Fatalf("Failed to get public filesystem: %v", err)
	}

	srv := server.New(storage, publicFS, server.Options{
		EnableProver:   !*noProver,
		EnableSolidity: !*noSolgen,
		KeyDir:         *keyDir,
		DevMode:        *devMode,
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("bitwrap listening on %s", addr)
	log.Printf("Data directory: %s", *dataDir)
	if *noProver {
		log.Printf("ZK prover: disabled")
	}
	if *noSolgen {
		log.Printf("Solidity generation: disabled")
	}
	if *devMode {
		log.Printf("Dev mode: enabled (add ?dev-wallet to poll URL for built-in wallet)")
	}
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// runValidate compiles a .btw file through the full pipeline:
// parse → build schema → generate Solidity + tests → forge build → forge test → deploy to anvil
func runValidate(path, outputDir string) int {
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL read %s: %v\n", path, err)
		return 1
	}

	// Step 1: Parse DSL
	fmt.Printf("  parse    %s\n", path)
	ast, err := dsl.Parse(string(src))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL parse: %v\n", err)
		return 1
	}

	// Step 2: Build metamodel schema
	schema, err := dsl.Build(ast)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL build: %v\n", err)
		return 1
	}
	fmt.Printf("  schema   %s (%d states, %d actions, %d arcs)\n",
		ast.Name, len(schema.States), len(schema.Actions), len(schema.Arcs))

	// Step 3: Generate Solidity
	contractName := solidity.ContractName(schema.Name)
	contractCode := solidity.Generate(schema)
	testCode := solidity.GenerateTests(schema)
	genesisCode := solidity.GenerateGenesis(schema.Name, solidity.GenesisConfig{}, solidity.DefaultAddresses())
	fmt.Printf("  solidity %s.sol (%d bytes), tests (%d bytes), genesis (%d bytes)\n",
		contractName, len(contractCode), len(testCode), len(genesisCode))

	// Step 4: Check for forge
	if _, err := exec.LookPath("forge"); err != nil {
		fmt.Printf("  skip     forge not installed\n")
		fmt.Printf("PASS (parse + generate)\n")
		return 0
	}

	// Step 5: Set up Foundry project directory
	var dir string
	if outputDir != "" {
		dir = outputDir
		os.MkdirAll(dir, 0o755)
	} else {
		dir, err = os.MkdirTemp("", "bitwrap-validate-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL tmpdir: %v\n", err)
			return 1
		}
		defer os.RemoveAll(dir)
	}

	for _, sub := range []string{"src", "test", "script"} {
		os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}

	foundryToml := "[profile.default]\nsrc = \"src\"\nout = \"out\"\nlibs = [\"lib\"]\nsolc_version = \"0.8.20\"\n"
	os.WriteFile(filepath.Join(dir, "foundry.toml"), []byte(foundryToml), 0o644)
	os.WriteFile(filepath.Join(dir, "src", contractName+".sol"), []byte(contractCode), 0o644)
	os.WriteFile(filepath.Join(dir, "test", contractName+"Test.t.sol"), []byte(testCode), 0o644)
	os.WriteFile(filepath.Join(dir, "script", contractName+"Genesis.s.sol"), []byte(genesisCode), 0o644)

	// Step 6: Install forge-std
	if !runStep(dir, "deps", "git", "init") {
		return 1
	}
	if !runStep(dir, "deps", "forge", "install", "foundry-rs/forge-std") {
		return 1
	}

	// Step 7: Compile
	if !runStep(dir, "compile", "forge", "build") {
		return 1
	}

	// Step 8: Test — show individual results
	fmt.Printf("  test     ")
	cmd := exec.Command("forge", "test", "-vv")
	cmd.Dir = dir
	out, testErr := cmd.CombinedOutput()
	outStr := string(out)

	// Count pass/fail from forge output
	passed, failed := 0, 0
	for _, line := range strings.Split(outStr, "\n") {
		if strings.Contains(line, "[PASS]") {
			passed++
		} else if strings.Contains(line, "[FAIL") {
			failed++
		}
	}
	if testErr != nil {
		fmt.Printf("%d passed, %d failed\n", passed, failed)
		// Show failing test names
		for _, line := range strings.Split(outStr, "\n") {
			if strings.Contains(line, "[FAIL") {
				fmt.Printf("           %s\n", strings.TrimSpace(line))
			}
		}
		fmt.Fprintf(os.Stderr, "FAIL forge test\n")
		return 1
	}
	fmt.Printf("%d passed\n", passed)

	// Step 9: Deploy to anvil
	if _, err := exec.LookPath("anvil"); err != nil {
		fmt.Printf("  skip     anvil not installed\n")
		fmt.Printf("PASS\n")
		return 0
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL find free port: %v\n", err)
		return 1
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	rpcURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	anvil := exec.Command("anvil", "--port", fmt.Sprintf("%d", port), "--silent")
	if err := anvil.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL start anvil: %v\n", err)
		return 1
	}
	defer func() { anvil.Process.Kill(); anvil.Wait() }()

	for i := 0; i < 50; i++ {
		c := exec.Command("cast", "chain-id", "--rpc-url", rpcURL)
		if o, e := c.CombinedOutput(); e == nil && strings.TrimSpace(string(o)) == "31337" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	privKey := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	createArgs := []string{"create", fmt.Sprintf("src/%s.sol:%s", contractName, contractName),
		"--rpc-url", rpcURL, "--private-key", privKey, "--broadcast"}

	deployCmd := exec.Command("forge", createArgs...)
	deployCmd.Dir = dir
	deployOut, deployErr := deployCmd.CombinedOutput()
	deployStr := string(deployOut)
	if deployErr != nil || !strings.Contains(deployStr, "Deployed to:") {
		fmt.Fprintf(os.Stderr, "FAIL deploy\n%s\n", deployStr)
		return 1
	}

	for _, line := range strings.Split(deployStr, "\n") {
		if strings.Contains(line, "Deployed to:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				fmt.Printf("  deploy   %s\n", parts[len(parts)-1])
			}
		}
	}

	if outputDir != "" {
		fmt.Printf("  output   %s/\n", outputDir)
	}
	fmt.Printf("PASS\n")
	return 0
}

func runStep(dir, label, name string, args ...string) bool {
	fmt.Printf("  %-8s ", label)
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("FAIL\n")
		fmt.Fprintf(os.Stderr, "%s\n", out)
		return false
	}
	fmt.Printf("ok\n")
	return true
}
