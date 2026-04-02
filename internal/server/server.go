package server

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stackdump/bitwrap-io/dsl"
	"github.com/stackdump/bitwrap-io/erc"
	"github.com/stackdump/bitwrap-io/internal/seal"
	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/internal/svg"
	"github.com/stackdump/bitwrap-io/prover"
	"github.com/stackdump/bitwrap-io/solidity"
)

// Options configures the server.
type Options struct {
	EnableProver   bool
	EnableSolidity bool
	KeyDir         string // directory for persistent circuit keys (empty = no persistence)
}

// Server is the bitwrap HTTP server.
type Server struct {
	store          *store.FSStore
	publicFS       fs.FS
	opts           Options
	proverSvc      *prover.Service
	keyStore       *prover.KeyStore
	pollRateLimiter *RateLimiter
}

// New creates a new server.
func New(s *store.FSStore, publicFS fs.FS, opts Options) *Server {
	srv := &Server{store: s, publicFS: publicFS, opts: opts, pollRateLimiter: NewRateLimiter(5, time.Hour)}
	if opts.EnableProver {
		log.Printf("Initializing ZK prover (compiling circuits)...")
		start := time.Now()
		svc, ks, err := prover.NewArcnetService(opts.KeyDir)
		if err != nil {
			log.Printf("WARNING: ZK prover initialization failed: %v", err)
		} else {
			srv.proverSvc = svc
			srv.keyStore = ks
			log.Printf("ZK prover ready (%d circuits compiled in %v)", len(svc.Prover().ListCircuits()), time.Since(start))
		}
	}
	return srv
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)

	// CORS
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch {
	// API routes
	case r.URL.Path == "/api/save" && r.Method == http.MethodPost:
		s.handleSave(w, r)
	case r.URL.Path == "/api/svg" && r.Method == http.MethodPost:
		s.handlePostSVG(w, r)
	case r.URL.Path == "/api/templates":
		s.handleTemplates(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/templates/"):
		s.handleTemplate(w, r)
	case r.URL.Path == "/api/solgen" && r.Method == http.MethodPost:
		if !s.opts.EnableSolidity {
			http.Error(w, "Solidity generation is disabled (start with -solgen flag)", http.StatusServiceUnavailable)
			return
		}
		s.handleSolGen(w, r)
	case r.URL.Path == "/api/testgen" && r.Method == http.MethodPost:
		if !s.opts.EnableSolidity {
			http.Error(w, "Solidity generation is disabled (start with -solgen flag)", http.StatusServiceUnavailable)
			return
		}
		s.handleTestGen(w, r)
	case r.URL.Path == "/api/genesisgen" && r.Method == http.MethodPost:
		if !s.opts.EnableSolidity {
			http.Error(w, "Solidity generation is disabled (start with -solgen flag)", http.StatusServiceUnavailable)
			return
		}
		s.handleGenesisGen(w, r)
	case r.URL.Path == "/api/prove" && r.Method == http.MethodPost:
		s.handleProve(w, r)
	case r.URL.Path == "/api/circuits":
		s.handleCircuits(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/bundle/"):
		if !s.opts.EnableSolidity {
			http.Error(w, "Solidity generation is disabled", http.StatusServiceUnavailable)
			return
		}
		s.handleBundle(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/vk/"):
		s.handleVK(w, r)
	case r.URL.Path == "/api/compile" && r.Method == http.MethodPost:
		s.handleCompile(w, r)

	// Poll routes
	case r.URL.Path == "/api/polls" && r.Method == http.MethodPost:
		s.handleCreatePoll(w, r)
	case r.URL.Path == "/api/polls" && r.Method == http.MethodGet:
		s.handleListPolls(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/vote") && r.Method == http.MethodPost:
		s.handleCastVote(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/close") && r.Method == http.MethodPost:
		s.handleClosePoll(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/reveal") && r.Method == http.MethodPost:
		s.handleRevealVote(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/results"):
		s.handlePollResults(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/nullifiers"):
		s.handlePollNullifiers(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/register") && r.Method == http.MethodPost:
		s.handleRegisterVoter(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/") && strings.HasSuffix(r.URL.Path, "/registry"):
		s.handleGetRegistry(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/polls/"):
		s.handleGetPoll(w, r)

	// Object routes
	case strings.HasPrefix(r.URL.Path, "/o/"):
		s.handleGetObject(w, r)

	// SVG image routes
	case strings.HasPrefix(r.URL.Path, "/img/") && strings.HasSuffix(r.URL.Path, ".svg"):
		s.handleGetSVG(w, r)

	// Static files
	default:
		s.handleStatic(w, r)
	}
}

// handleStatic serves embedded static files.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.publicFS == nil {
		http.NotFound(w, r)
		return
	}

	path := r.URL.Path
	if path == "/" {
		path = "/index.html"
	}
	if path == "/editor" {
		path = "/editor.html"
	}
	if path == "/remix" {
		path = "/remix-plugin.html"
	}
	if path == "/poll" {
		path = "/poll.html"
	}

	// Serve the file
	name := strings.TrimPrefix(path, "/")
	data, err := fs.ReadFile(s.publicFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".json"):
		w.Header().Set("Content-Type", "application/json")
	}

	w.Write(data)
}

// handleSave saves a JSON-LD document and returns its CID.
func (s *Server) handleSave(w http.ResponseWriter, r *http.Request) {
	var doc map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&doc); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Validate JSON-LD
	if _, ok := doc["@context"]; !ok {
		http.Error(w, "Missing @context field", http.StatusBadRequest)
		return
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		http.Error(w, "Failed to serialize", http.StatusInternalServerError)
		return
	}

	cid, canonical, err := seal.SealJSONLD(raw)
	if err != nil {
		log.Printf("Sealing failed: %v", err)
		http.Error(w, fmt.Sprintf("Sealing failed: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.store.SaveObject(cid, raw, canonical); err != nil {
		log.Printf("Save failed: %v", err)
		http.Error(w, "Failed to save", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"cid": cid})
}

// handleGetObject returns a stored JSON-LD document by CID.
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request) {
	cid := strings.TrimPrefix(r.URL.Path, "/o/")
	cid = strings.Split(cid, "/")[0]
	if cid == "" {
		http.Error(w, "CID required", http.StatusBadRequest)
		return
	}

	data, err := s.store.ReadObject(cid)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ld+json")
	w.Write(data)
}

// handleGetSVG generates SVG from a stored model.
func (s *Server) handleGetSVG(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/img/")
	cid := strings.TrimSuffix(path, ".svg")
	if cid == "" {
		http.Error(w, "CID required", http.StatusBadRequest)
		return
	}

	data, err := s.store.ReadObject(cid)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	layout := r.URL.Query().Get("layout")
	svgContent, err := svg.GenerateSVGWithLayout(data, layout)
	if err != nil {
		log.Printf("SVG generation failed: %v", err)
		http.Error(w, "Failed to generate SVG", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Write([]byte(svgContent))
}

// handlePostSVG generates SVG from posted JSON-LD.
func (s *Server) handlePostSVG(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	layout := r.URL.Query().Get("layout")
	svgContent, err := svg.GenerateSVGWithLayout(data, layout)
	if err != nil {
		http.Error(w, "Failed to generate SVG", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(svgContent))
}

// Template represents an ERC template for the API.
type Template struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Standard    string `json:"standard"`
	Description string `json:"description"`
}

var templates = []Template{
	{ID: "erc20", Name: "ERC-20 Fungible Token", Standard: "ERC-20", Description: "Fungible token with transfer, approve, mint, burn"},
	{ID: "erc721", Name: "ERC-721 Non-Fungible Token", Standard: "ERC-721", Description: "Non-fungible token with ownership and transfers"},
	{ID: "erc1155", Name: "ERC-1155 Multi Token", Standard: "ERC-1155", Description: "Multi-token standard supporting both fungible and non-fungible"},
	{ID: "erc4626", Name: "ERC-4626 Tokenized Vault", Standard: "ERC-4626", Description: "Tokenized vault with deposit, withdraw, and yield"},
	{ID: "erc5725", Name: "ERC-5725 Transferable Vesting NFT", Standard: "ERC-5725", Description: "Transferable vesting NFT with create, claim, transfer, revoke, burn"},
	{ID: "vote", Name: "ZK Poll", Standard: "Vote", Description: "Private voting with ZK proofs — anonymous ballots, verifiable tallies"},
}

// handleTemplates lists available ERC templates.
func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"templates": templates})
}

// solgenRequest is the request body for /api/solgen.
type solgenRequest struct {
	Template string `json:"template"`
}

// solgenResponse is the response body for /api/solgen.
type solgenResponse struct {
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Solidity string `json:"solidity"`
}

// handleSolGen generates Solidity code from an ERC template.
func (s *Server) handleSolGen(w http.ResponseWriter, r *http.Request) {
	var req solgenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Template == "" {
		http.Error(w, "template field required", http.StatusBadRequest)
		return
	}

	tmpl := s.getTemplate(req.Template)
	if tmpl == nil {
		http.Error(w, fmt.Sprintf("Unknown template: %s", req.Template), http.StatusBadRequest)
		return
	}

	code := solidity.Generate(tmpl.Schema())

	filenames := map[string]string{
		"erc20":  "BitwrapERC20.sol",
		"erc721": "BitwrapERC721.sol",
		"erc1155": "BitwrapERC1155.sol",
		"erc4626": "BitwrapERC4626.sol",
		"erc5725": "BitwrapERC5725.sol",
		"vote":   "BitwrapZKPoll.sol",
	}

	resp := solgenResponse{
		Name:     tmpl.Metadata().Name,
		Filename: filenames[req.Template],
		Solidity: code,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTestGen generates Foundry tests from an ERC template.
func (s *Server) handleTestGen(w http.ResponseWriter, r *http.Request) {
	var req solgenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Template == "" {
		http.Error(w, "template field required", http.StatusBadRequest)
		return
	}

	tmpl := s.getTemplate(req.Template)
	if tmpl == nil {
		http.Error(w, fmt.Sprintf("Unknown template: %s", req.Template), http.StatusBadRequest)
		return
	}

	code := solidity.GenerateTests(tmpl.Schema())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"name":     tmpl.Metadata().Name,
		"filename": tmpl.Schema().Name + "Test.t.sol",
		"solidity": code,
	})
}

// handleGenesisGen generates a Foundry genesis deployment script from an ERC template.
func (s *Server) handleGenesisGen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Template string                 `json:"template"`
		Actions  []solidity.GenesisAction `json:"actions"`
		Epochs   int                    `json:"epochs"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Template == "" {
		http.Error(w, "template field required", http.StatusBadRequest)
		return
	}

	tmpl := s.getTemplate(req.Template)
	if tmpl == nil {
		http.Error(w, fmt.Sprintf("Unknown template: %s", req.Template), http.StatusBadRequest)
		return
	}

	config := solidity.GenesisConfig{
		Actions:     req.Actions,
		TotalEpochs: req.Epochs,
	}
	schema := tmpl.Schema()
	if strings.HasPrefix(schema.Version, "Vote:") {
		config.ConstructorArgs = "0 /* voterRegistryRoot */, 10 /* maxChoices */, address(0) /* verifier — deploy Verifier.sol first */"
	}
	schemaName := schema.Name
	code := solidity.GenerateGenesis(schemaName, config, solidity.DefaultAddresses())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"name":     tmpl.Metadata().Name,
		"filename": schemaName + "Genesis.s.sol",
		"solidity": code,
	})
}

// handleTemplate returns a specific template as a full Petri net JSON-LD model.
func (s *Server) handleTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/")
	if id == "" {
		http.Error(w, "Template ID required", http.StatusBadRequest)
		return
	}

	tmpl := s.getTemplate(id)
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	// Convert schema to JSON-LD Petri net representation
	schema := tmpl.Schema()
	model := map[string]interface{}{
		"@context":    "https://pflow.xyz/schema",
		"@type":       "PetriNet",
		"name":        schema.Name,
		"version":     schema.Version,
		"states":      schema.States,
		"actions":     schema.Actions,
		"arcs":        schema.Arcs,
		"events":      schema.Events,
		"constraints": schema.Constraints,
	}

	w.Header().Set("Content-Type", "application/ld+json")
	json.NewEncoder(w).Encode(model)
}

// getTemplate returns an ERC template by ID.
func (s *Server) getTemplate(id string) erc.Template {
	switch id {
	case "erc20":
		return erc.NewERC020("ERC20", "TKN", 18)
	case "erc721":
		return erc.NewERC0721("ERC721", "NFT")
	case "erc1155":
		return erc.NewERC01155("ERC1155")
	case "erc4626":
		return erc.NewERC04626("ERC4626", "VLT")
	case "erc5725":
		return erc.NewERC05725("ERC5725", "VEST", "0x0000000000000000000000000000000000000000")
	case "vote":
		return erc.NewVote("ZKPoll")
	default:
		return nil
	}
}

// handleProve generates a ZK proof from a model and witness.
func (s *Server) handleProve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Circuit string            `json:"circuit"`
		Witness map[string]string `json:"witness"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Circuit == "" {
		http.Error(w, "circuit field required", http.StatusBadRequest)
		return
	}

	if len(req.Witness) == 0 {
		http.Error(w, "witness field required (map of field name to value)", http.StatusBadRequest)
		return
	}

	// If prover is not initialized, return error
	if s.proverSvc == nil {
		// Validate circuit name against known list for a helpful error
		knownCircuits := []string{"transfer", "transferFrom", "mint", "burn", "approve", "vestClaim", "voteCast"}
		found := false
		for _, c := range knownCircuits {
			if c == req.Circuit {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, fmt.Sprintf("Unknown circuit: %s. Available: %v", req.Circuit, knownCircuits), http.StatusBadRequest)
			return
		}
		http.Error(w, "ZK prover is disabled (server started with -no-prover)", http.StatusServiceUnavailable)
		return
	}

	// Validate circuit exists in the compiled prover
	p := s.proverSvc.Prover()
	if _, ok := p.GetCircuit(req.Circuit); !ok {
		http.Error(w, fmt.Sprintf("Unknown circuit: %s. Available: %v", req.Circuit, p.ListCircuits()), http.StatusBadRequest)
		return
	}

	// Create circuit assignment from witness
	factory := &prover.ArcnetWitnessFactory{}
	assignment, err := factory.CreateAssignment(req.Circuit, req.Witness)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   fmt.Sprintf("witness error: %v", err),
			"circuit": req.Circuit,
		})
		return
	}

	// Generate Groth16 proof
	start := time.Now()
	proof, err := p.Prove(req.Circuit, assignment)
	elapsed := time.Since(start)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":        fmt.Sprintf("proof generation failed: %v", err),
			"circuit":      req.Circuit,
			"proof_time_ms": elapsed.Milliseconds(),
		})
		return
	}

	log.Printf("Proof generated: circuit=%s constraints=%d elapsed=%v", req.Circuit, proof.Constraints, elapsed)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"proof":        proof,
		"circuit":      req.Circuit,
		"proof_time_ms": elapsed.Milliseconds(),
	})
}

// circuitDescriptions provides human-readable descriptions for known circuits.
var circuitDescriptions = map[string]struct {
	description  string
	publicInputs []string
}{
	"transfer":     {"ERC-20 transfer: proves balance >= amount", []string{"preStateRoot", "postStateRoot", "from", "to", "amount"}},
	"transferFrom": {"ERC-20 delegated transfer: proves balance >= amount && allowance >= amount", []string{"preStateRoot", "postStateRoot", "from", "to", "caller", "amount"}},
	"mint":         {"ERC-20 mint: proves caller == minter", []string{"preStateRoot", "postStateRoot", "caller", "to", "amount"}},
	"burn":         {"ERC-20 burn: proves balance >= amount", []string{"preStateRoot", "postStateRoot", "from", "amount"}},
	"approve":      {"ERC-20 approve: proves owner == caller", []string{"preStateRoot", "postStateRoot", "caller", "spender", "amount"}},
	"vestClaim":    {"Vesting claim: proves ownership and available amount", []string{"preStateRoot", "postStateRoot", "tokenID", "caller", "claimAmount"}},
	"voteCast":     {"ZK vote: proves voter eligibility and valid choice without revealing identity or choice", []string{"pollId", "voterRegistryRoot", "nullifier", "voteCommitment", "maxChoices"}},
}

// handleCircuits lists available ZK circuits.
func (s *Server) handleCircuits(w http.ResponseWriter, r *http.Request) {
	var circuits []map[string]interface{}

	if s.proverSvc != nil {
		// Use live circuit data from the prover
		for _, name := range s.proverSvc.Prover().ListCircuits() {
			entry := map[string]interface{}{"name": name, "status": "compiled"}
			if cc, ok := s.proverSvc.Prover().GetCircuit(name); ok {
				entry["constraints"] = cc.Constraints
				entry["public_vars"] = cc.PublicVars
				entry["private_vars"] = cc.PrivateVars
			}
			if desc, ok := circuitDescriptions[name]; ok {
				entry["description"] = desc.description
				entry["public_inputs"] = desc.publicInputs
			}
			circuits = append(circuits, entry)
		}
	} else {
		// Fallback to static descriptions
		for name, desc := range circuitDescriptions {
			circuits = append(circuits, map[string]interface{}{
				"name":          name,
				"description":   desc.description,
				"public_inputs": desc.publicInputs,
				"status":        "disabled",
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"circuits": circuits})
}

// handleVK serves verifying key data for a circuit.
// GET /api/vk/{circuit} — raw verifying key bytes
// GET /api/vk/{circuit}/solidity — Solidity verifier contract
func (s *Server) handleVK(w http.ResponseWriter, r *http.Request) {
	if s.keyStore == nil {
		http.Error(w, "Key store not enabled (start with -key-dir flag)", http.StatusServiceUnavailable)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/vk/")
	parts := strings.SplitN(path, "/", 2)
	circuit := parts[0]

	if !s.keyStore.Has(circuit) {
		http.Error(w, fmt.Sprintf("circuit %q not found", circuit), http.StatusNotFound)
		return
	}

	// GET /api/vk/{circuit}/solidity
	if len(parts) == 2 && parts[1] == "solidity" {
		sol, err := s.keyStore.ExportSolidityVerifier(circuit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=Verifier_%s.sol", circuit))
		w.Write(sol)
		return
	}

	// GET /api/vk/{circuit} — raw binary key
	vkBytes, err := s.keyStore.ExportVerifyingKey(circuit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.vk", circuit))
	w.Write(vkBytes)
}

// handleCompile compiles a .btw DSL source to metamodel schema JSON.
func (s *Server) handleCompile(w http.ResponseWriter, r *http.Request) {
	src, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	ast, err := dsl.Parse(string(src))
	if err != nil {
		http.Error(w, fmt.Sprintf("Parse error: %v", err), http.StatusBadRequest)
		return
	}

	schema, err := dsl.Build(ast)
	if err != nil {
		http.Error(w, fmt.Sprintf("Build error: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(schema)
}

// handleBundle generates a ZIP file containing a complete Foundry project.
func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	templateID := strings.TrimPrefix(r.URL.Path, "/api/bundle/")
	if templateID == "" {
		http.Error(w, "Template ID required", http.StatusBadRequest)
		return
	}

	tmpl := s.getTemplate(templateID)
	if tmpl == nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	contractNames := map[string]string{
		"erc20":   "BitwrapERC20",
		"erc721":  "BitwrapERC721",
		"erc1155": "BitwrapERC1155",
		"erc4626": "BitwrapERC4626",
		"erc5725": "BitwrapERC5725",
		"vote":    "BitwrapZKPoll",
	}

	contractName := contractNames[templateID]
	if contractName == "" {
		contractName = "Bitwrap" + strings.ToUpper(templateID)
	}

	schema := tmpl.Schema()
	contractCode := solidity.Generate(schema)
	testCode := solidity.GenerateTests(schema)

	genesisConfig := solidity.GenesisConfig{}
	if strings.HasPrefix(schema.Version, "Vote:") {
		genesisConfig.ConstructorArgs = "0 /* voterRegistryRoot */, 10 /* maxChoices */, address(0) /* verifier — deploy Verifier.sol first */"
	}
	deployCode := solidity.GenerateGenesis(schema.Name, genesisConfig, solidity.DefaultAddresses())

	foundryToml := `[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"

[fmt]
line_length = 120
`

	readme := fmt.Sprintf(`# %s — Generated by bitwrap

## Quick Start

`+"```bash"+`
# Install Foundry if needed
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
forge install foundry-rs/forge-std

# Build
forge build

# Test
forge test -vv

# Deploy (local anvil)
anvil &
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
`+"```"+`
`, contractName)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.zip", contractName))

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Use the schema-derived name for the .sol file (matches import paths in tests/deploy)
	solContractName := solidity.ContractName(schema.Name)
	files := map[string]string{
		"foundry.toml":                                        foundryToml,
		fmt.Sprintf("src/%s.sol", solContractName):            contractCode,
		fmt.Sprintf("test/%s.t.sol", solContractName):         testCode,
		"script/Deploy.s.sol":                                 deployCode,
		"README.md":                                           readme,
	}

	// Add Solidity verifier: use voteCast circuit for vote template, transfer for others
	if s.keyStore != nil {
		verifierCircuit := "transfer"
		if templateID == "vote" {
			verifierCircuit = "voteCast"
		}
		if s.keyStore.Has(verifierCircuit) {
			verifierSol, err := s.keyStore.ExportSolidityVerifier(verifierCircuit)
			if err == nil {
				files["src/Verifier.sol"] = string(verifierSol)
			}
		}
	}

	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			log.Printf("bundle: failed to create zip entry %s: %v", name, err)
			return
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			log.Printf("bundle: failed to write zip entry %s: %v", name, err)
			return
		}
	}
}

