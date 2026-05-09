package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// TestClosePollCLIFlow exercises the full create -> cast -> server-side-close
// lifecycle for a v3 poll.  It reuses the existing test helpers (seedV3Poll,
// attachV3FullProver, castV3Vote, buildTallyDecryptProof, signAggregate) to
// set up state, spins up a real httptest.Server, and closes the poll by
// posting the aggregate request through HTTP — exactly the sequence that the
// `bitwrap close-poll` CLI subcommand performs against a live server.
func TestClosePollCLIFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 close-poll CLI flow compiles two large circuits; skipping in short mode")
	}

	srv := testServer(t)
	attachV3FullProver(t, srv)

	// Spin up a real HTTP test server so we exercise the full HTTP layer.
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Seed a v3 poll and reassign creator to the dev address so
	// signAggregate's signature will verify on the server side.
	pollID, sk, pk := seedV3Poll(t, srv)
	poll, _ := srv.store.ReadPoll(pollID)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	// Three votes; castV3Vote needs one extra slot per vote beyond the
	// first (createTestPoll seeds one slot already via seedV3Poll).
	registerTestVoter(t, srv, pollID)
	registerTestVoter(t, srv, pollID)
	castV3Vote(t, srv, pollID, pk, 0, 8)
	castV3Vote(t, srv, pollID, pk, 1, 8)
	castV3Vote(t, srv, pollID, pk, 0, 8)

	// Compute expected tallies in-process (mirrors CLI step 5-6).
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	if tallies[0] != 2 || tallies[1] != 1 {
		t.Fatalf("decrypted tallies wrong: %v (want [2,1,...])", tallies)
	}

	// Sign the aggregate payload (same canonical format as aggregateSigPayload).
	sig, _ := signAggregate(t, pollID, tallies)

	// POST via the HTTP test server — this is what the CLI does.
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	bodyBytes, _ := json.Marshal(body)
	resp, err := http.Post(
		ts.URL+"/api/polls/"+pollID+"/aggregate",
		"application/json",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		t.Fatalf("POST aggregate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		t.Fatalf("aggregate: got %d body=%q", resp.StatusCode, buf.String())
	}

	// Assert poll closed and artifact persisted.
	poll2, _ := srv.store.ReadPoll(pollID)
	if poll2.Status != "closed" {
		t.Errorf("poll status: got %q, want closed", poll2.Status)
	}
	artifact, err := srv.store.ReadHomomorphicTally(pollID)
	if err != nil {
		t.Fatalf("ReadHomomorphicTally: %v", err)
	}
	if artifact.Tallies[0] != 2 || artifact.Tallies[1] != 1 {
		t.Errorf("artifact tallies: got %v, want [2,1,...]", artifact.Tallies)
	}
	if artifact.NumBallots != 3 {
		t.Errorf("NumBallots: got %d, want 3", artifact.NumBallots)
	}

	// GET /tally returns the artifact too.
	tallyResp, err := http.Get(ts.URL + "/api/polls/" + pollID + "/tally")
	if err != nil {
		t.Fatalf("GET tally: %v", err)
	}
	defer tallyResp.Body.Close()
	if tallyResp.StatusCode != http.StatusOK {
		t.Fatalf("GET tally: %d", tallyResp.StatusCode)
	}
	var gotArtifact store.HomomorphicTallyArtifact
	if err := json.NewDecoder(tallyResp.Body).Decode(&gotArtifact); err != nil {
		t.Fatalf("decode tally artifact: %v", err)
	}
	if gotArtifact.Tallies[0] != 2 || gotArtifact.Tallies[1] != 1 {
		t.Errorf("GET tally artifact tallies: %v", gotArtifact.Tallies)
	}

	// Idempotency: a second POST returns 409 with the existing artifact.
	resp2, _ := http.Post(
		ts.URL+"/api/polls/"+pollID+"/aggregate",
		"application/json",
		bytes.NewReader(bodyBytes),
	)
	if resp2 != nil {
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusConflict {
			t.Errorf("idempotent second POST: got %d, want 409", resp2.StatusCode)
		}
	}
}

// TestClosePollCLIRejectsNonV3 verifies that the aggregate endpoint returns
// 400 for v1/v2 polls — the CLI must surface this error cleanly.
func TestClosePollCLIRejectsNonV3(t *testing.T) {
	srv := testServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	pollID := createTestPoll(t, srv, "v2 poll", []string{"a", "b"})

	body := map[string]any{
		"creator":           "0x00",
		"signature":         "0x00",
		"tallies":           make([]int64, 8),
		"decryptProofBytes": "AAAA",
	}
	bodyBytes, _ := json.Marshal(body)
	resp, err := http.Post(
		ts.URL+"/api/polls/"+pollID+"/aggregate",
		"application/json",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for v1/v2 poll, got %d", resp.StatusCode)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "v3") {
		t.Errorf("error body should mention v3: %q", buf.String())
	}
}

// TestClosePollSKDecrypt is a lightweight sanity check that the CLI's
// aggregation + decryption math (no ZK proof) produces correct tallies
// when the sk matches the pk used to encrypt the votes.  It replicates
// only the aggregate+decrypt steps from buildTallyDecryptProof so the
// tallyDecrypt_8 circuit is not needed (and the test runs in seconds).
func TestClosePollSKDecrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 vote circuit compilation takes a few seconds; skip in short mode")
	}
	srv := testServer(t)
	attachV3Prover(t, srv) // vote circuit only — we do not need tallyDecrypt here

	pollID, sk, pk := seedV3Poll(t, srv)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll, _ := srv.store.ReadPoll(pollID)
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	registerTestVoter(t, srv, pollID)
	castV3Vote(t, srv, pollID, pk, 2, 8)
	castV3Vote(t, srv, pollID, pk, 2, 8)

	// Aggregate ciphertexts inline (same math as closePollCore).
	votes, err := srv.store.ListVotes(pollID)
	if err != nil {
		t.Fatal(err)
	}
	aggA := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	aggB := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	for j := range aggA {
		aggA[j].X.SetZero()
		aggA[j].Y.SetOne()
		aggB[j].X.SetZero()
		aggB[j].Y.SetOne()
	}
	for _, v := range votes {
		for j := 0; j < prover.TallyDecryptChoices; j++ {
			aBuf, _ := hex.DecodeString(v.Ciphertexts[j].A)
			bBuf, _ := hex.DecodeString(v.Ciphertexts[j].B)
			a, _ := prover.DecodePoint(aBuf)
			b, _ := prover.DecodePoint(bBuf)
			aggA[j].Add(&aggA[j], &a)
			aggB[j].Add(&aggB[j], &b)
		}
	}

	// Decrypt.
	tallies := make([]int64, prover.TallyDecryptChoices)
	for j := 0; j < prover.TallyDecryptChoices; j++ {
		ct := prover.Ciphertext{A: aggA[j], B: aggB[j]}
		t_, err := prover.Decrypt(ct, sk, len(votes))
		if err != nil {
			t.Fatalf("decrypt bin %d: %v", j, err)
		}
		tallies[j] = int64(t_)
	}

	if tallies[2] != 2 {
		t.Errorf("expected tally[2]=2, got %v", tallies)
	}
	for j, v := range tallies {
		if j != 2 && v != 0 {
			t.Errorf("expected tally[%d]=0, got %d", j, v)
		}
	}

	// Also verify the sk -> hex -> sk round-trip (the CLI parses sk from hex).
	skHex := hex.EncodeToString(sk.Bytes())
	skBack, ok := hexToBigInt(skHex)
	if !ok || skBack.Cmp(sk) != 0 {
		t.Errorf("sk hex round-trip failed: got %s", skHex)
	}
}

// hexToBigInt parses a hex string (with or without 0x) to *big.Int.
func hexToBigInt(h string) (*big.Int, bool) {
	h = strings.TrimPrefix(h, "0x")
	n, ok := new(big.Int).SetString(h, 16)
	return n, ok
}
