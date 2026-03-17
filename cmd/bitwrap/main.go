package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/stackdump/bitwrap-io/dsl"
	"github.com/stackdump/bitwrap-io/internal/server"
	"github.com/stackdump/bitwrap-io/internal/static"
	"github.com/stackdump/bitwrap-io/internal/store"
)

func main() {
	port := flag.Int("port", 8088, "Port to listen on")
	dataDir := flag.String("data", "./data", "Data directory for storage")
	noProver := flag.Bool("no-prover", false, "Disable ZK prover (faster startup)")
	solgen := flag.Bool("solgen", false, "Enable Solidity generation endpoints")
	compile := flag.String("compile", "", "Compile a .btw file and output JSON schema to stdout")
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

	storage := store.NewFSStore(*dataDir)

	publicFS, err := static.Public()
	if err != nil {
		log.Fatalf("Failed to get public filesystem: %v", err)
	}

	srv := server.New(storage, publicFS, server.Options{
		EnableProver:   !*noProver,
		EnableSolidity: *solgen,
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("bitwrap listening on %s", addr)
	log.Printf("Data directory: %s", *dataDir)
	if *noProver {
		log.Printf("ZK prover: disabled")
	}
	if *solgen {
		log.Printf("Solidity generation: enabled")
	}
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
