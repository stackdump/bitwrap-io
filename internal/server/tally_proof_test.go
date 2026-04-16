package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// writeTestVoteAndReveal is a store-level fixture: creates a vote record
// keyed by a deterministic (secret, choice) pair so BuildTallyProofWitness
// has matching positional commitments to pair against reveal bundles.
// pollIDField must be the field element the circuit uses for PollID —
// matching whatever pollIDToField returns for the poll's string ID.
func writeTestVoteAndReveal(t *testing.T, s *store.FSStore, pollID string, secret int64, pollIDField *big.Int, choice int64) {
	t.Helper()
	secretBig := big.NewInt(secret)
	choiceBig := big.NewInt(choice)

	commitment := prover.MiMCHashBigInt(secretBig, choiceBig)
	nullifier := prover.MiMCHashBigInt(secretBig, pollIDField)
	commitHex := "0x" + commitment.Text(16)
	nullHex := "0x" + nullifier.Text(16)

	if err := s.SaveVote(pollID, &store.VoteRecord{
		Nullifier:      nullHex,
		VoteCommitment: commitHex,
		Proof:          "test-stub",
		Timestamp:      time.Now().UTC().Add(time.Duration(secret) * time.Nanosecond),
	}); err != nil {
		t.Fatalf("SaveVote: %v", err)
	}
	if err := s.SaveRevealBundle(pollID, store.RevealBundle{
		Nullifier: nullHex,
		Choice:    int(choice),
		Secret:    secretBig.String(),
	}); err != nil {
		t.Fatalf("SaveRevealBundle: %v", err)
	}
}

// seedTallyProofPoll builds a closed poll. Uses a hex-style poll ID so
// pollIDToField applies its canonical hex-decode path — matching the JS
// client's BigInt('0x' + pollId.slice(0, 16)) derivation.
func seedTallyProofPoll(t *testing.T, s *store.FSStore, pollIDHex string, reveals []struct {
	secret int64
	choice int64
}) string {
	t.Helper()
	pollID := pollIDHex
	pollIDField, err := pollIDToField(pollID)
	if err != nil {
		t.Fatalf("pollIDToField(%q): %v", pollID, err)
	}
	poll := &store.Poll{
		ID:        pollID,
		Title:     "tally-proof integration",
		Choices:   []string{"A", "B", "C", "D"},
		Creator:   "0x0000000000000000000000000000000000000001",
		CreatedAt: time.Now().UTC(),
		Status:    "closed",
	}
	if err := s.SavePoll(poll); err != nil {
		t.Fatalf("SavePoll: %v", err)
	}
	for _, r := range reveals {
		writeTestVoteAndReveal(t, s, pollID, r.secret, pollIDField, r.choice)
	}
	return pollID
}

func TestBuildTallyProofWitness(t *testing.T) {
	srv := testServer(t)
	reveals := []struct{ secret, choice int64 }{
		{secret: 101, choice: 0},
		{secret: 202, choice: 2},
		{secret: 303, choice: 0},
	}
	pollID := seedTallyProofPoll(t, srv.store, "a1b2c3d4e5f60708", reveals)

	c, err := BuildTallyProofWitness(srv.store, pollID)
	if err != nil {
		t.Fatalf("BuildTallyProofWitness: %v", err)
	}

	// Tally expectations: two votes for choice 0, one for choice 2.
	wantTally := map[int]int64{0: 2, 2: 1}
	for j := 0; j < prover.TallyProofMaxChoices; j++ {
		got := c.Tallies[j].(int64)
		if got != wantTally[j] {
			t.Errorf("Tallies[%d] = %d, want %d", j, got, wantTally[j])
		}
	}
	if got, want := c.NumReveals.(int64), int64(len(reveals)); got != want {
		t.Errorf("NumReveals = %d, want %d", got, want)
	}

	// Active mask: first three true, rest zero.
	for i := 0; i < prover.TallyProofMaxReveals; i++ {
		want := int64(0)
		if i < len(reveals) {
			want = 1
		}
		if got := c.Active[i].(int64); got != want {
			t.Errorf("Active[%d] = %d, want %d", i, got, want)
		}
	}
}

// TestGenerateTallyProofEndToEnd runs the full prover pipeline over a
// closed poll: build witness, prove, persist, re-verify from bytes.
// Skipped in -short because gnark setup takes a few seconds per run.
func TestGenerateTallyProofEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full prover pipeline in short mode")
	}

	// Directly compile the tallyProof circuit into a standalone prover —
	// cheaper than booting the full NewArcnetService (which compiles every
	// ERC circuit).
	p := prover.NewProver()
	cc, err := p.CompileCircuit("tallyProof_16", &prover.TallyProofCircuit16{})
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	p.StoreCircuit("tallyProof_16", cc)

	srv := testServer(t)
	reveals := []struct{ secret, choice int64 }{
		{secret: 11, choice: 1},
		{secret: 22, choice: 3},
		{secret: 33, choice: 1},
		{secret: 44, choice: 0},
	}
	pollID := seedTallyProofPoll(t, srv.store, "cafebabedeadbeef", reveals)

	stored, err := GenerateTallyProof(srv.store, p, pollID)
	if err != nil {
		t.Fatalf("GenerateTallyProof: %v", err)
	}
	if stored.NumReveals != len(reveals) {
		t.Errorf("NumReveals = %d, want %d", stored.NumReveals, len(reveals))
	}
	wantTally := map[int]int64{0: 1, 1: 2, 3: 1}
	for j, count := range stored.Tallies {
		if count != wantTally[j] {
			t.Errorf("Tallies[%d] = %d, want %d", j, count, wantTally[j])
		}
	}

	// Re-decode the cached artifact and re-verify from raw bytes — this is
	// the path an external verifier (or Solidity verifier) would walk.
	proofBytes, err := base64.StdEncoding.DecodeString(stored.ProofBytes)
	if err != nil {
		t.Fatalf("decode proof bytes: %v", err)
	}
	// Re-verify directly from the cached artifact bytes. PublicWitnessBytes
	// is now persisted as part of the artifact (A1), so we don't need a
	// fresh prove round to obtain them.
	pubWitnessBytes, err := base64.StdEncoding.DecodeString(stored.PublicWitnessBytes)
	if err != nil {
		t.Fatalf("decode public witness bytes: %v", err)
	}
	if err := prover.VerifyTallyBytes(p, stored.CircuitName, proofBytes, pubWitnessBytes); err != nil {
		t.Fatalf("VerifyTallyBytes(%s): %v", stored.CircuitName, err)
	}
	if len(proofBytes) == 0 {
		t.Error("cached proofBytes empty")
	}

	t.Logf("tally proof OK: %d reveals, %d constraints", stored.NumReveals, cc.Constraints)
}

// TestTallyProofHTTPEndpoints exercises the JSON endpoints themselves so
// route wiring, content types, and the store→prover glue all line up.
// Bypasses wallet auth by seeding the store directly and attaching a
// standalone tallyProof-only prover to the server.
func TestTallyProofHTTPEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping HTTP prover pipeline in short mode")
	}

	srv := testServer(t)

	// Attach a minimal prover with only tallyProof compiled. The server
	// normally wires a full service; this test doesn't need it.
	p := prover.NewProver()
	cc, err := p.CompileCircuit("tallyProof_16", &prover.TallyProofCircuit16{})
	if err != nil {
		t.Fatalf("CompileCircuit: %v", err)
	}
	p.StoreCircuit("tallyProof_16", cc)
	srv.proverSvc = prover.NewService(p, &prover.ArcnetWitnessFactory{})

	reveals := []struct{ secret, choice int64 }{
		{secret: 555, choice: 2},
		{secret: 666, choice: 2},
		{secret: 777, choice: 0},
	}
	pollID := seedTallyProofPoll(t, srv.store, "0123456789abcdef", reveals)

	// POST generates the proof.
	postReq := httptest.NewRequest("POST", "/api/polls/"+pollID+"/tally-proof", nil)
	postW := httptest.NewRecorder()
	srv.ServeHTTP(postW, postReq)
	if postW.Code != 200 {
		t.Fatalf("POST tally-proof = %d, body=%q", postW.Code, postW.Body.String())
	}

	var postArtifact store.TallyProofArtifact
	if err := json.Unmarshal(postW.Body.Bytes(), &postArtifact); err != nil {
		t.Fatalf("decode POST body: %v", err)
	}
	if postArtifact.NumReveals != len(reveals) {
		t.Errorf("POST NumReveals = %d, want %d", postArtifact.NumReveals, len(reveals))
	}
	if postArtifact.Tallies[2] != 2 || postArtifact.Tallies[0] != 1 {
		t.Errorf("unexpected tallies: %v", postArtifact.Tallies)
	}
	if postArtifact.ProofBytes == "" {
		t.Error("POST returned empty proof bytes")
	}

	// GET returns the cached proof.
	getReq := httptest.NewRequest("GET", "/api/polls/"+pollID+"/tally-proof", nil)
	getW := httptest.NewRecorder()
	srv.ServeHTTP(getW, getReq)
	if getW.Code != 200 {
		t.Fatalf("GET tally-proof = %d, body=%q", getW.Code, getW.Body.String())
	}
	var getArtifact store.TallyProofArtifact
	if err := json.Unmarshal(getW.Body.Bytes(), &getArtifact); err != nil {
		t.Fatalf("decode GET body: %v", err)
	}
	if getArtifact.ProofBytes != postArtifact.ProofBytes {
		t.Error("GET returned a different proof than POST persisted")
	}
	if len(getArtifact.PublicInputs) == 0 {
		t.Error("GET returned no public inputs")
	}
}

// TestSelectTallyCircuitSize covers the size-dispatch boundaries. Any
// drift in the tier table will flip one of these expectations.
func TestSelectTallyCircuitSize(t *testing.T) {
	cases := []struct {
		voteCount    int
		wantName     string
		wantCapacity int
		wantErr      bool
	}{
		{1, "tallyProof_16", 16, false},
		{15, "tallyProof_16", 16, false},
		{16, "tallyProof_16", 16, false},
		{17, "tallyProof_64", 64, false},
		{64, "tallyProof_64", 64, false},
		{65, "tallyProof_256", 256, false},
		{256, "tallyProof_256", 256, false},
		{257, "", 0, true},
		{0, "", 0, true},
		{-1, "", 0, true},
	}
	for _, tc := range cases {
		got, cap, err := selectTallyCircuitSize(tc.voteCount)
		if tc.wantErr {
			if err == nil {
				t.Errorf("selectTallyCircuitSize(%d): expected error, got %s/%d", tc.voteCount, got, cap)
			}
			continue
		}
		if err != nil {
			t.Errorf("selectTallyCircuitSize(%d): unexpected error %v", tc.voteCount, err)
			continue
		}
		if got != tc.wantName || cap != tc.wantCapacity {
			t.Errorf("selectTallyCircuitSize(%d) = (%s, %d), want (%s, %d)",
				tc.voteCount, got, cap, tc.wantName, tc.wantCapacity)
		}
	}
}

// TestGenerateTallyProofAt64Slots exercises the 64-slot circuit
// end-to-end. Exactly 17 votes/reveals so we're above the 16-slot tier
// and forced onto tallyProof_64. Without the sized dispatch this test
// would fail with a capacity-exceeded error.
func TestGenerateTallyProofAt64Slots(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64-slot prover pipeline in short mode")
	}

	p := prover.NewProver()
	cc, err := p.CompileCircuit("tallyProof_64", &prover.TallyProofCircuit64{})
	if err != nil {
		t.Fatalf("CompileCircuit tallyProof_64: %v", err)
	}
	p.StoreCircuit("tallyProof_64", cc)

	srv := testServer(t)
	reveals := make([]struct{ secret, choice int64 }, 17)
	for i := range reveals {
		reveals[i] = struct{ secret, choice int64 }{secret: int64(1000 + i), choice: int64(i % 4)}
	}
	pollID := seedTallyProofPoll(t, srv.store, "1234567890abcdef", reveals)

	stored, err := GenerateTallyProof(srv.store, p, pollID)
	if err != nil {
		t.Fatalf("GenerateTallyProof: %v", err)
	}
	if stored.CircuitName != "tallyProof_64" {
		t.Errorf("expected circuit=tallyProof_64, got %s", stored.CircuitName)
	}
	if stored.NumReveals != 17 {
		t.Errorf("NumReveals = %d, want 17", stored.NumReveals)
	}
	// 17 reveals cycling through choices 0..3: choice 0 gets 5, 1 gets 4,
	// 2 gets 4, 3 gets 4 (indices 0,4,8,12,16 → 0; 1,5,9,13 → 1; etc.).
	wantTally := map[int]int64{0: 5, 1: 4, 2: 4, 3: 4}
	for j, count := range stored.Tallies {
		if count != wantTally[j] {
			t.Errorf("Tallies[%d] = %d, want %d", j, count, wantTally[j])
		}
	}

	// Re-verify from stored bytes to confirm the artifact is self-contained.
	proofBytes, err := base64.StdEncoding.DecodeString(stored.ProofBytes)
	if err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	pubWitnessBytes, err := base64.StdEncoding.DecodeString(stored.PublicWitnessBytes)
	if err != nil {
		t.Fatalf("decode public witness: %v", err)
	}
	if err := prover.VerifyTallyBytes(p, "tallyProof_64", proofBytes, pubWitnessBytes); err != nil {
		t.Fatalf("VerifyTallyBytes tallyProof_64: %v", err)
	}
	t.Logf("tallyProof_64 OK: %d reveals, %d constraints", stored.NumReveals, cc.Constraints)
}

// TestTallyProofRejectsWrongSizedVK — a proof generated against the
// 16-slot circuit must not verify under the 64-slot verifying key.
// Catches any dispatch bug where the wrong VK gets used.
func TestTallyProofRejectsWrongSizedVK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping wrong-size VK test in short mode")
	}

	p := prover.NewProver()
	for _, size := range []int{16, 64} {
		name := fmt.Sprintf("tallyProof_%d", size)
		var c interface {
			frontend.Circuit
		}
		if size == 16 {
			c = &prover.TallyProofCircuit16{}
		} else {
			c = &prover.TallyProofCircuit64{}
		}
		cc, err := p.CompileCircuit(name, c)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		p.StoreCircuit(name, cc)
	}

	srv := testServer(t)
	reveals := []struct{ secret, choice int64 }{
		{secret: 1, choice: 0},
		{secret: 2, choice: 1},
	}
	pollID := seedTallyProofPoll(t, srv.store, "fedcba9876543210", reveals)

	stored, err := GenerateTallyProof(srv.store, p, pollID)
	if err != nil {
		t.Fatalf("GenerateTallyProof: %v", err)
	}
	if stored.CircuitName != "tallyProof_16" {
		t.Fatalf("expected dispatch to tallyProof_16 for 2 reveals, got %s", stored.CircuitName)
	}

	proofBytes, _ := base64.StdEncoding.DecodeString(stored.ProofBytes)
	pubWitnessBytes, _ := base64.StdEncoding.DecodeString(stored.PublicWitnessBytes)
	// Verifying under the wrong-sized VK must fail.
	if err := prover.VerifyTallyBytes(p, "tallyProof_64", proofBytes, pubWitnessBytes); err == nil {
		t.Error("verification unexpectedly succeeded against wrong-sized VK")
	}
}

// TestTallyProofRejectsActivePoll — the proof makes sense only after the
// poll is closed (all commitments fixed, reveals collected). A POST
// against an active poll must be rejected.
func TestTallyProofRejectsActivePoll(t *testing.T) {
	srv := testServer(t)
	p := prover.NewProver()
	srv.proverSvc = prover.NewService(p, &prover.ArcnetWitnessFactory{})

	poll := &store.Poll{
		ID:        "active-poll",
		Title:     "still running",
		Choices:   []string{"A", "B"},
		Creator:   "0x0000000000000000000000000000000000000001",
		CreatedAt: time.Now().UTC(),
		Status:    "active",
	}
	if err := srv.store.SavePoll(poll); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/polls/active-poll/tally-proof", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for active poll, got %d: %s", w.Code, w.Body.String())
	}
}
