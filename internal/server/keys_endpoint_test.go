package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stackdump/bitwrap-io/prover"
)

// TestHandleKeysServesAll404 — when no keystore is attached (default
// in tests), every /api/keys request returns 503.
func TestHandleKeysWithoutKeyStore(t *testing.T) {
	srv := testServer(t)
	w := getReq(t, srv, "/api/keys/voteCastHomomorphic_8.cs")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestHandleKeysShape — once a keystore + compiled circuit is
// attached, the endpoint serves cs/pk/vk bytes for that circuit.
// Uses tallyDecrypt_8 (smallest v3 circuit) to keep test runtime
// reasonable; the dispatch path is the same for all circuits.
func TestHandleKeysShape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles a tallyDecrypt_8 circuit (~1s)")
	}
	srv := testServer(t)

	// Compile + persist into a real keystore.
	dir := t.TempDir()
	ks, err := prover.NewKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := prover.NewProver()
	cc, err := ks.CompileAndSave(p, "tallyDecrypt_8", &prover.TallyDecryptCircuit_8{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p.StoreCircuit("tallyDecrypt_8", cc)
	srv.proverSvc = prover.NewService(p, &prover.ArcnetWitnessFactory{})
	srv.keyStore = ks

	for _, ext := range []string{"cs", "pk", "vk"} {
		w := getReq(t, srv, "/api/keys/tallyDecrypt_8."+ext)
		if w.Code != 200 {
			t.Errorf("ext=%s: got %d body=%q", ext, w.Code, w.Body.String())
			continue
		}
		if w.Body.Len() == 0 {
			t.Errorf("ext=%s: empty body", ext)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("ext=%s: Content-Type %q", ext, ct)
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "tallyDecrypt_8."+ext) {
			t.Errorf("ext=%s: Content-Disposition %q lacks filename", ext, cd)
		}
	}
}

// TestHandleKeysUnknownCircuit returns 404.
func TestHandleKeysUnknownCircuit(t *testing.T) {
	srv := testServer(t)
	dir := t.TempDir()
	ks, _ := prover.NewKeyStore(dir)
	srv.keyStore = ks
	w := getReq(t, srv, "/api/keys/nope.cs")
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestHandleKeysBadExtension — requests for unknown extensions reject.
func TestHandleKeysBadExtension(t *testing.T) {
	srv := testServer(t)
	dir := t.TempDir()
	ks, _ := prover.NewKeyStore(dir)
	srv.keyStore = ks
	w := getReq(t, srv, "/api/keys/voteCastHomomorphic_8.txt")
	if w.Code != 404 && w.Code != 400 {
		t.Fatalf("expected 400 or 404, got %d", w.Code)
	}
}

// TestHandleKeysMalformedPath — /api/keys/no-dot-in-tail rejects with 400.
func TestHandleKeysMalformedPath(t *testing.T) {
	srv := testServer(t)
	dir := t.TempDir()
	ks, _ := prover.NewKeyStore(dir)
	srv.keyStore = ks
	w := getReq(t, srv, "/api/keys/missingDot")
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
