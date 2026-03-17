package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackdump/bitwrap-io/internal/static"
	"github.com/stackdump/bitwrap-io/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	s := store.NewFSStore(dir)
	pub, err := static.Public()
	if err != nil {
		t.Fatal(err)
	}
	return New(s, pub, Options{EnableSolidity: true})
}

func TestGetIndex(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "bitwrap") {
		t.Fatal("index page missing bitwrap content")
	}
}

func TestGetEditor(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/editor", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /editor = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "petri-view") {
		t.Fatal("editor page missing petri-view")
	}
}

func TestGetRemix(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/remix", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /remix = %d, want 200", w.Code)
	}
}

func TestSaveAndLoad(t *testing.T) {
	srv := testServer(t)

	// Save
	model := `{"@context":"https://pflow.xyz/schema","@type":"PetriNet","places":{},"transitions":{},"arcs":[],"token":[]}`
	req := httptest.NewRequest("POST", "/api/save", strings.NewReader(model))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST /api/save = %d: %s", w.Code, w.Body.String())
	}

	var saveResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &saveResp)
	cid := saveResp["cid"]
	if cid == "" {
		t.Fatal("save returned empty CID")
	}

	// Load
	req = httptest.NewRequest("GET", "/o/"+cid, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /o/%s = %d", cid, w.Code)
	}
	if w.Header().Get("Content-Type") != "application/ld+json" {
		t.Fatalf("wrong content type: %s", w.Header().Get("Content-Type"))
	}
}

func TestSaveMissingContext(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/api/save", strings.NewReader(`{"foo":"bar"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing @context, got %d", w.Code)
	}
}

func TestGetObjectNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/o/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestTemplatesList(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/templates", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/templates = %d", w.Code)
	}
	var resp map[string][]Template
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp["templates"]) != 5 {
		t.Fatalf("expected 5 templates, got %d", len(resp["templates"]))
	}
}

func TestTemplateDetail(t *testing.T) {
	srv := testServer(t)
	for _, id := range []string{"erc20", "erc721", "erc1155", "erc4626"} {
		req := httptest.NewRequest("GET", "/api/templates/"+id, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("GET /api/templates/%s = %d", id, w.Code)
		}
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["name"] == nil || resp["name"] == "" {
			t.Fatalf("template %s missing name", id)
		}
		// Should have schema structure, not just a skeleton
		if resp["actions"] == nil {
			t.Fatalf("template %s missing actions -- should return full model", id)
		}
		if resp["arcs"] == nil {
			t.Fatalf("template %s missing arcs", id)
		}
	}
}

func TestTemplateNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/templates/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestSolGen(t *testing.T) {
	srv := testServer(t)
	body := `{"template":"erc20"}`
	req := httptest.NewRequest("POST", "/api/solgen", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST /api/solgen = %d: %s", w.Code, w.Body.String())
	}
	var resp solgenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Solidity == "" {
		t.Fatal("empty solidity output")
	}
	if !strings.Contains(resp.Solidity, "pragma solidity") {
		t.Fatal("output missing pragma")
	}
	if resp.Filename == "" {
		t.Fatal("missing filename")
	}
}

func TestSolGenUnknownTemplate(t *testing.T) {
	srv := testServer(t)
	body := `{"template":"unknown"}`
	req := httptest.NewRequest("POST", "/api/solgen", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCircuits(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/circuits", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/circuits = %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	circuits := resp["circuits"].([]interface{})
	if len(circuits) == 0 {
		t.Fatal("no circuits returned")
	}
}

func TestProveDisabled(t *testing.T) {
	srv := testServer(t) // prover not enabled
	body := `{"circuit":"transfer","witness":{"from":"0x1","to":"0x2","amount":"100","preStateRoot":"0","postStateRoot":"0","balanceFrom":"1000","balanceTo":"0","pathElement0":"0","pathIndex0":"0","pathElement1":"0","pathIndex1":"0","pathElement2":"0","pathIndex2":"0","pathElement3":"0","pathIndex3":"0","pathElement4":"0","pathIndex4":"0","pathElement5":"0","pathIndex5":"0","pathElement6":"0","pathIndex6":"0","pathElement7":"0","pathIndex7":"0","pathElement8":"0","pathIndex8":"0","pathElement9":"0","pathIndex9":"0","pathElement10":"0","pathIndex10":"0","pathElement11":"0","pathIndex11":"0","pathElement12":"0","pathIndex12":"0","pathElement13":"0","pathIndex13":"0","pathElement14":"0","pathIndex14":"0","pathElement15":"0","pathIndex15":"0","pathElement16":"0","pathIndex16":"0","pathElement17":"0","pathIndex17":"0","pathElement18":"0","pathIndex18":"0","pathElement19":"0","pathIndex19":"0"}}`
	req := httptest.NewRequest("POST", "/api/prove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatalf("POST /api/prove with disabled prover = %d, want 503: %s", w.Code, w.Body.String())
	}
}

func TestProveUnknownCircuit(t *testing.T) {
	srv := testServer(t) // prover not enabled
	body := `{"circuit":"unknown","witness":{"x":"1"}}`
	req := httptest.NewRequest("POST", "/api/prove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestProveMissingWitness(t *testing.T) {
	srv := testServer(t)
	body := `{"circuit":"transfer"}`
	req := httptest.NewRequest("POST", "/api/prove", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCORS(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("OPTIONS", "/api/templates", nil)
	req.Header.Set("Origin", "https://remix.ethereum.org")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("OPTIONS = %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://remix.ethereum.org" {
		t.Fatal("CORS origin not reflected")
	}
}

func TestPostSVG(t *testing.T) {
	srv := testServer(t)
	model := `{"@context":"https://pflow.xyz/schema","@type":"PetriNet","places":{"p0":{"@type":"Place","x":100,"y":100,"initial":[0],"capacity":[1]}},"transitions":{"t0":{"@type":"Transition","x":200,"y":100}},"arcs":[{"@type":"Arrow","source":"p0","target":"t0","weight":[1]}],"token":["https://pflow.xyz/tokens/black"]}`
	req := httptest.NewRequest("POST", "/api/svg", strings.NewReader(model))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST /api/svg = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "<svg") {
		t.Fatal("response is not SVG")
	}
}

func TestCompile(t *testing.T) {
	srv := testServer(t)
	btw := `schema Test {
  version "1.0"
  register balance uint256 observable
  fn(inc) {
    var amount amount
    inc -|amount|> balance
  }
}`
	req := httptest.NewRequest("POST", "/api/compile", strings.NewReader(btw))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/compile = %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["name"] != "Test" {
		t.Fatalf("expected name=Test, got %v", resp["name"])
	}
}
