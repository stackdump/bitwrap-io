package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
// We use the BabyJubJub identity point (0, 1) as pkCreator with sk=1 and
// identity ciphertexts (encryptions of 0 under any key) so the aggregation
// and decryption succeed with all-zero tallies, and the exit-2 path is
// triggered purely by the absence of --signature / --eth-key.
func TestRunClosePollPrintsPayloadWhenNoSig(t *testing.T) {
	// Identity point (0, 1) in 32-byte little-endian encoding.
	// On BabyJubJub: a*x^2 + y^2 = 1 + d*x^2*y^2 → at (0,1): 1 = 1 ✓
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
	// No signature flag → CLI must print payload and exit exitNeedsSignature.
	code := closePollCore("p3", "01", "", "", ts.URL, "", http.DefaultClient)
	if code != exitNeedsSignature {
		t.Errorf("no sig path: want exit %d (exitNeedsSignature), got %d", exitNeedsSignature, code)
	}
}
