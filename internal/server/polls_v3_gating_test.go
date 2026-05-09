package server

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestRevealOnV3Poll404 — POST /reveal on a v3 poll must return 404.
// The absence of a reveal phase is structural, not a permissions
// thing, so 404 (not 403/405) is the right signal to clients.
func TestRevealOnV3Poll404(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)

	body := map[string]any{
		"nullifier":   "0x1",
		"voteChoice":  0,
		"voterSecret": "42",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/reveal", body)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "v3") {
		t.Errorf("error message should mention v3: %q", w.Body.String())
	}
}

// TestResultsV3ActiveSealed — GET /results on an active v3 poll must
// expose voteCount but never tally / nullifiers / commitments /
// ciphertexts.
func TestResultsV3ActiveSealed(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	srv := testServer(t)
	attachV3Prover(t, srv)
	pollID, _, pk := seedV3Poll(t, srv)

	castV3Vote(t, srv, pollID, pk, 1, 8)

	w := getReq(t, srv, "/api/polls/"+pollID+"/results")
	if w.Code != 200 {
		t.Fatalf("results: got %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["voteCount"].(float64) != 1 {
		t.Errorf("voteCount: got %v", got["voteCount"])
	}
	for _, leaky := range []string{"tally", "tallies", "nullifiers", "commitments", "ciphertexts"} {
		if _, present := got[leaky]; present {
			t.Errorf("active v3 results leaks field %q: %v", leaky, got[leaky])
		}
	}
	if got["voteSchemaVersion"].(float64) != 3 {
		t.Errorf("voteSchemaVersion: got %v", got["voteSchemaVersion"])
	}
}

// TestResultsV3ClosedExposesTally — after aggregate, results endpoint
// returns the tally artifact, but never per-voter ciphertexts or
// nullifiers.
func TestResultsV3ClosedExposesTally(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	srv := testServer(t)
	attachV3FullProver(t, srv)
	pollID, sk, pk := seedV3Poll(t, srv)

	poll, _ := srv.store.ReadPoll(pollID)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	castV3Vote(t, srv, pollID, pk, 4, 8)
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	if r := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body); r.Code != 200 {
		t.Fatalf("aggregate: %d body=%q", r.Code, r.Body.String())
	}

	w := getReq(t, srv, "/api/polls/"+pollID+"/results")
	if w.Code != 200 {
		t.Fatalf("results: got %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["status"].(string) != "closed" {
		t.Errorf("status: got %v", got["status"])
	}
	tallyAny, ok := got["tally"]
	if !ok {
		t.Fatalf("closed v3 results missing tally artifact: %s", w.Body.String())
	}
	tallyMap, _ := tallyAny.(map[string]any)
	tArr, _ := tallyMap["tallies"].([]any)
	if len(tArr) != 8 {
		t.Errorf("tallies length: got %d, want 8", len(tArr))
	}
	if tArr[4].(float64) != 1 {
		t.Errorf("tallies[4]: got %v want 1", tArr[4])
	}

	// Per-voter leakage checks: results must not include a top-level
	// nullifiers/commitments/ciphertexts list.
	for _, leaky := range []string{"nullifiers", "commitments", "ciphertexts"} {
		if _, present := got[leaky]; present {
			t.Errorf("closed v3 results leaks field %q", leaky)
		}
	}
}

// TestResultsV2Unchanged — pre-existing v1/v2 behavior must keep
// emitting nullifiers/commitments after close, since the audit
// surface is documented and clients depend on it.
func TestResultsV2Unchanged(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "v2 unchanged", []string{"a", "b"})

	// Mark closed + drop a fake vote with a commitment so we can see
	// the v2 fields surface.
	poll, _ := srv.store.ReadPoll(pollID)
	poll.Status = "closed"
	_ = srv.store.SavePoll(poll)

	w := getReq(t, srv, "/api/polls/"+pollID+"/results")
	if w.Code != 200 {
		t.Fatalf("results: got %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// Both fields should be present (possibly empty) for v1/v2 closed.
	if _, ok := got["nullifiers"]; !ok {
		t.Error("v1/v2 closed results missing nullifiers field")
	}
	if _, ok := got["commitments"]; !ok {
		t.Error("v1/v2 closed results missing commitments field")
	}
}
