package server

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bitwrap-io/bitwrap/erc"
	"github.com/bitwrap-io/bitwrap/internal/seal"
	"github.com/bitwrap-io/bitwrap/internal/store"
	"github.com/bitwrap-io/bitwrap/internal/svg"
	"github.com/bitwrap-io/bitwrap/solidity"
)

// Options configures the server.
type Options struct {
	EnableProver   bool
	EnableSolidity bool
}

// Server is the bitwrap HTTP server.
type Server struct {
	store    *store.FSStore
	publicFS fs.FS
	opts     Options
}

// New creates a new server.
func New(s *store.FSStore, publicFS fs.FS, opts Options) *Server {
	return &Server{store: s, publicFS: publicFS, opts: opts}
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
		s.handleSolGen(w, r)

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

	var tmpl erc.Template
	switch req.Template {
	case "erc20":
		tmpl = erc.NewERC020("BitwrapERC20", "BWR", 18)
	case "erc721":
		tmpl = erc.NewERC0721("BitwrapERC721", "BNFT")
	case "erc1155":
		tmpl = erc.NewERC01155("BitwrapERC1155")
	case "erc4626":
		tmpl = erc.NewERC04626("BitwrapERC4626", "BWR")
	default:
		http.Error(w, fmt.Sprintf("Unknown template: %s", req.Template), http.StatusBadRequest)
		return
	}

	code := solidity.Generate(tmpl.Schema())

	filenames := map[string]string{
		"erc20":  "BitwrapERC20.sol",
		"erc721": "BitwrapERC721.sol",
		"erc1155": "BitwrapERC1155.sol",
		"erc4626": "BitwrapERC4626.sol",
	}

	resp := solgenResponse{
		Name:     tmpl.Metadata().Name,
		Filename: filenames[req.Template],
		Solidity: code,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTemplate returns a specific template as JSON-LD.
func (s *Server) handleTemplate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/templates/")
	if id == "" {
		http.Error(w, "Template ID required", http.StatusBadRequest)
		return
	}

	// Find template
	var found *Template
	for _, t := range templates {
		if t.ID == id {
			found = &t
			break
		}
	}
	if found == nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	// Return a minimal JSON-LD skeleton for the template
	skeleton := map[string]interface{}{
		"@context": "https://pflow.xyz/schema",
		"@type":    "PetriNet",
		"name":     found.Name,
		"description": found.Description,
	}

	w.Header().Set("Content-Type", "application/ld+json")
	json.NewEncoder(w).Encode(skeleton)
}

