package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/bitwrap-io/bitwrap/internal/server"
	"github.com/bitwrap-io/bitwrap/internal/static"
	"github.com/bitwrap-io/bitwrap/internal/store"
)

func main() {
	port := flag.Int("port", 8088, "Port to listen on")
	dataDir := flag.String("data", "./data", "Data directory for storage")
	noProver := flag.Bool("no-prover", false, "Disable ZK prover (faster startup)")
	solgen := flag.Bool("solgen", false, "Enable Solidity generation endpoints")
	flag.Parse()

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
