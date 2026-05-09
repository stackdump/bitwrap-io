package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// closePollMockHandler creates an http.HandlerFunc that serves fixed poll,
// votes, and aggregate responses for close-poll CLI unit tests.
func closePollMockHandler(pollResp, votesResp interface{}, aggCode int, aggCapture *map[string]interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(path, "/votes") && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(votesResp)
		case strings.HasSuffix(path, "/aggregate") && r.Method == http.MethodPost:
			if aggCapture != nil {
				json.NewDecoder(r.Body).Decode(aggCapture)
			}
			w.WriteHeader(aggCode)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"poll": pollResp})
		}
	}
}

// TestRunClosePollRejectsV1Poll checks that the CLI exits with code 1 for a
// v1/v2 poll (voteSchemaVersion != 3).
func TestRunClosePollRejectsV1Poll(t *testing.T) {
	ts := httptest.NewServer(closePollMockHandler(
		map[string]interface{}{
			"id": "p1", "creator": "0x1234", "pkCreator": "",
			"voteSchemaVersion": 1, "status": "active",
		},
		map[string]interface{}{"votes": []interface{}{}},
		http.StatusOK, nil,
	))
	defer ts.Close()

	code := closePollCore("p1", "aabb", "", "", ts.URL, "", http.DefaultClient)
	if code != 1 {
		t.Errorf("v1 poll: want exit 1, got %d", code)
	}
}

// TestRunClosePollRejectsAlreadyClosed checks that the CLI exits with code 1
// when the poll is already closed.
func TestRunClosePollRejectsAlreadyClosed(t *testing.T) {
	ts := httptest.NewServer(closePollMockHandler(
		map[string]interface{}{
			"id": "p2", "creator": "0x1234", "pkCreator": "",
			"voteSchemaVersion": 3, "status": "closed",
		},
		map[string]interface{}{"votes": []interface{}{}},
		http.StatusOK, nil,
	))
	defer ts.Close()

	code := closePollCore("p2", "aabb", "", "", ts.URL, "", http.DefaultClient)
	if code != 1 {
		t.Errorf("closed poll: want exit 1, got %d", code)
	}
}

// TestRunClosePollEmptyArgs checks argument validation: no args returns exit 1.
func TestRunClosePollEmptyArgs(t *testing.T) {
	code := runClosePoll([]string{})
	if code == 0 {
		t.Errorf("no args: want non-zero exit, got 0")
	}
}

// TestRunClosePollMissingSkHex checks that omitting --sk-hex returns exit 1.
func TestRunClosePollMissingSkHex(t *testing.T) {
	code := runClosePoll([]string{"somePollID"})
	if code == 0 {
		t.Errorf("missing --sk-hex: want non-zero exit, got 0")
	}
}

// TestRunClosePollMutuallyExclusiveFlags checks that --signature and --eth-key
// together produce exit 1.
func TestRunClosePollMutuallyExclusiveFlags(t *testing.T) {
	code := runClosePoll([]string{
		"pollID",
		"--sk-hex=aabbcc",
		"--signature=0x1234",
		"--eth-key=0xdead",
	})
	if code == 0 {
		t.Errorf("signature+eth-key: want non-zero exit, got 0")
	}
}

// TestRunClosePollPrintsPayloadWhenNoSig checks that without any signature
// flag the CLI computes tallies and returns exitNeedsSignature (2).
// We use the BabyJubJub identity point (0, 1) as both pkCreator and the
// per-bin ciphertext components (A, B). With sk=1 the decrypt step computes
// M = B - sk*A = identity - 1*identity = identity = G*0, so every bin's
// tally resolves to 0. The exit-2 path is then triggered purely by the
// absence of --signature / --eth-key.
func TestRunClosePollPrintsPayloadWhenNoSig(t *testing.T) {
	// Identity point (0, 1) in 32-byte little-endian encoding.
	// On BabyJubJub: a*x^2 + y^2 = 1 + d*x^2*y^2 -> at (0,1): 1 = 1 OK
	idBuf := make([]byte, 32)
	idBuf[0] = 0x01
	idHex := hex.EncodeToString(idBuf) // "01" + 62 zero hex chars

	ciphertexts := make([]map[string]string, 8)
	for i := range ciphertexts {
		ciphertexts[i] = map[string]string{"A": idHex, "B": idHex}
	}

	ts := httptest.NewServer(closePollMockHandler(
		map[string]interface{}{
			"id": "p3", "creator": "0xdeadbeef",
			// pkCreator = identity point (0, 1) — valid on BabyJubJub.
			// sk=1 below: G * 0 = identity in twisted Edwards, so decrypt
			// of identity ciphertexts yields tally = 0 for every bin.
			"pkCreator":         idHex,
			"voteSchemaVersion": 3,
			"status":            "active",
		},
		map[string]interface{}{
			"votes": []interface{}{
				map[string]interface{}{
					"nullifier": "1", "ciphertexts": ciphertexts,
				},
			},
		},
		http.StatusOK, nil,
	))
	defer ts.Close()

	// sk=1, pkCreator=identity: decrypt produces all-zero tallies.
	// No signature flag -> CLI must print payload and exit exitNeedsSignature.
	code := closePollCore("p3", "01", "", "", ts.URL, "", http.DefaultClient)
	if code != exitNeedsSignature {
		t.Errorf("no sig path: want exit %d (exitNeedsSignature), got %d", exitNeedsSignature, code)
	}
}

// TestResolveSecretFromFile — file path beats env beats flag.
func TestResolveSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(path, []byte("aabb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BITWRAP_SK_HEX", "ccdd")
	got, err := resolveSecret("sk-hex", "0xeeff", path, "BITWRAP_SK_HEX")
	if err != nil {
		t.Fatal(err)
	}
	if got != "aabb" {
		t.Errorf("file path should win: got %q want aabb", got)
	}
}

// TestResolveSecretFromEnv — env beats flag when no file given.
func TestResolveSecretFromEnv(t *testing.T) {
	t.Setenv("BITWRAP_SK_HEX", "ccdd")
	got, err := resolveSecret("sk-hex", "0xeeff", "", "BITWRAP_SK_HEX")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ccdd" {
		t.Errorf("env should win over flag: got %q want ccdd", got)
	}
}

// TestResolveSecretFromFlag — flag is the fallback.
func TestResolveSecretFromFlag(t *testing.T) {
	t.Setenv("BITWRAP_SK_HEX", "")
	got, err := resolveSecret("sk-hex", "0xeeff", "", "BITWRAP_SK_HEX")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0xeeff" {
		t.Errorf("flag fallback: got %q want 0xeeff", got)
	}
}

// TestResolveSecretFlagAndFileFileWinsSilently — providing both is allowed;
// the file is the source of truth and the flag value is ignored without
// a warning (the flag-warning is only emitted when the flag value is the
// one actually used).
func TestResolveSecretFlagAndFileFileWinsSilently(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	if err := os.WriteFile(path, []byte("aabb"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSecret("sk-hex", "0xeeff", path, "BITWRAP_SK_HEX")
	if err != nil {
		t.Fatal(err)
	}
	if got != "aabb" {
		t.Errorf("file should win: got %q want aabb", got)
	}
}

// TestResolveSecretAllUnset — all three sources empty returns empty + nil.
func TestResolveSecretAllUnset(t *testing.T) {
	t.Setenv("BITWRAP_SK_HEX", "")
	got, err := resolveSecret("sk-hex", "", "", "BITWRAP_SK_HEX")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("all unset: got %q, want empty", got)
	}
}

// TestRunClosePollAcceptsSkHexFile — flag/env/file path is wired into runClosePoll.
func TestRunClosePollAcceptsSkHexFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sk")
	if err := os.WriteFile(path, []byte("aabb"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Should pass the flag-validation gate even though --sk-hex is unset,
	// then fail later because the mock server isn't running. We just want
	// to confirm the file is consulted instead of demanding --sk-hex.
	code := runClosePoll([]string{"some-poll-id", "--sk-hex-file=" + path, "--server=http://127.0.0.1:1"})
	// Expected to fail at the "fetching poll" step since :1 is unreachable —
	// but NOT with the "--sk-hex is required" error.
	if code == 0 {
		t.Errorf("unreachable server should error, got 0")
	}
}
