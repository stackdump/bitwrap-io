package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// attachV3FullProver compiles both v3 circuits (voteCastHomomorphic_8
// and tallyDecrypt_8) into the server's prover service. Idempotent.
func attachV3FullProver(t *testing.T, srv *Server) {
	t.Helper()
	attachV3Prover(t, srv) // ensures voteCastHomomorphic_8

	if _, ok := srv.proverSvc.Prover().GetCircuit("tallyDecrypt_8"); ok {
		return
	}
	cc, err := srv.proverSvc.Prover().CompileCircuit("tallyDecrypt_8", &prover.TallyDecryptCircuit_8{})
	if err != nil {
		t.Fatalf("compile tallyDecrypt: %v", err)
	}
	srv.proverSvc.Prover().StoreCircuit("tallyDecrypt_8", cc)
}

// castV3Vote casts one fully-proved v3 ballot at choice bin `choice`
// against pollID. Returns the nullifier so callers can register a
// matching slot if needed.
func castV3Vote(t *testing.T, srv *Server, pollID string, pk tedwards.PointAffine, choice int, maxChoices int) *big.Int {
	t.Helper()
	proofBytes, cthex, nullifier, root := buildV3VoteRequest(t, srv, pollID, pk, choice, maxChoices)
	alignPollRoot(t, srv, pollID, root)

	body := map[string]any{
		"nullifier":   nullifier.String(),
		"ciphertexts": cthex,
		"proofBytes":  base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 200 {
		t.Fatalf("vote: got %d body=%q", w.Code, w.Body.String())
	}
	return nullifier
}

// buildTallyDecryptProof aggregates the on-disk votes and produces a
// real decrypt proof for the matching tallies. Mirrors what a creator
// would do client-side.
func buildTallyDecryptProof(
	t *testing.T,
	srv *Server,
	pollID string,
	sk *big.Int,
	pk tedwards.PointAffine,
) (proofBytes []byte, tallies []int64) {
	t.Helper()
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
		if len(v.Ciphertexts) != prover.TallyDecryptChoices {
			t.Fatalf("vote has %d ciphertexts, want %d", len(v.Ciphertexts), prover.TallyDecryptChoices)
		}
		for j := 0; j < prover.TallyDecryptChoices; j++ {
			aBuf, _ := hex.DecodeString(v.Ciphertexts[j].A)
			bBuf, _ := hex.DecodeString(v.Ciphertexts[j].B)
			a, _ := prover.DecodePoint(aBuf)
			b, _ := prover.DecodePoint(bBuf)
			aggA[j].Add(&aggA[j], &a)
			aggB[j].Add(&aggB[j], &b)
		}
	}

	// Decrypt each bin's aggregate to recover the tally. Bound = N voters.
	tallies = make([]int64, prover.TallyDecryptChoices)
	for j := 0; j < prover.TallyDecryptChoices; j++ {
		ct := prover.Ciphertext{A: aggA[j], B: aggB[j]}
		t_, err := prover.Decrypt(ct, sk, len(votes))
		if err != nil {
			t.Fatalf("decrypt bin %d: %v", j, err)
		}
		tallies[j] = int64(t_)
	}

	// Build witness.
	w := &prover.TallyDecryptCircuit_8{}
	w.SkCreator = sk
	w.PkCreator = pointAsVar(&pk)
	for j := 0; j < prover.TallyDecryptChoices; j++ {
		w.A[j] = pointAsVar(&aggA[j])
		w.B[j] = pointAsVar(&aggB[j])
		w.Tallies[j] = tallies[j]
	}

	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	cc, ok := srv.proverSvc.Prover().GetCircuit("tallyDecrypt_8")
	if !ok {
		t.Fatalf("tallyDecrypt_8 not registered")
	}
	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, wit)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes(), tallies
}

// signAggregate signs the canonical aggregate payload as the poll's
// creator (anvil dev account 0).
func signAggregate(t *testing.T, pollID string, tallies []int64) (sig, addr string) {
	t.Helper()
	payload := AggregateSigPayload(pollID, tallies)
	return testCreatorDevSign(t, payload)
}

// --- tests ---------------------------------------------------------------

// TestAggregateV3HappyPath — three v3 ballots in bins {0, 1, 0}; creator
// closes the poll; resulting tally artifact has [2,1,0,0,0,0,0,0].
func TestAggregateV3HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 aggregate test compiles two large circuits")
	}
	srv := testServer(t)
	attachV3FullProver(t, srv)

	pollID, sk, pk := seedV3Poll(t, srv)
	// Reassign creator to the dev address so signAggregate verifies.
	poll, _ := srv.store.ReadPoll(pollID)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	// Three votes; need three registration slots (one is seeded).
	registerTestVoter(t, srv, pollID)
	registerTestVoter(t, srv, pollID)
	castV3Vote(t, srv, pollID, pk, 0, 8)
	castV3Vote(t, srv, pollID, pk, 1, 8)
	castV3Vote(t, srv, pollID, pk, 0, 8)

	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	if tallies[0] != 2 || tallies[1] != 1 {
		t.Fatalf("decrypt produced wrong tallies: %v", tallies)
	}

	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 200 {
		t.Fatalf("aggregate: got %d body=%q", w.Code, w.Body.String())
	}

	// Poll closed, artifact persisted.
	poll, _ = srv.store.ReadPoll(pollID)
	if poll.Status != "closed" {
		t.Errorf("poll not closed: %q", poll.Status)
	}
	artifact, err := srv.store.ReadHomomorphicTally(pollID)
	if err != nil {
		t.Fatalf("read tally: %v", err)
	}
	if artifact.Tallies[0] != 2 || artifact.Tallies[1] != 1 {
		t.Errorf("artifact tallies wrong: %v", artifact.Tallies)
	}
	if artifact.NumBallots != 3 {
		t.Errorf("NumBallots: got %d, want 3", artifact.NumBallots)
	}

	// Acceptance criterion: no reveals.json on a closed v3 poll.
	has, err := srv.store.HasReveals(pollID)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("v3 poll has reveals.json — structural privacy bug")
	}
}

// TestAggregateV3Idempotent — second call returns 409 with existing tally.
func TestAggregateV3Idempotent(t *testing.T) {
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

	castV3Vote(t, srv, pollID, pk, 2, 8)
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)

	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	if w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body); w.Code != 200 {
		t.Fatalf("first call: %d body=%q", w.Code, w.Body.String())
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 409 {
		t.Fatalf("second call: expected 409, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "tally") {
		t.Errorf("409 body should include existing tally: %q", w.Body.String())
	}
}

// TestAggregateV3RejectsNonV3Poll — 400 for v1/v2 polls.
func TestAggregateV3RejectsNonV3Poll(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "v2 poll", []string{"a", "b"})
	body := map[string]any{
		"creator":           "0x00",
		"signature":         "0x00",
		"tallies":           []int64{0, 0, 0, 0, 0, 0, 0, 0},
		"decryptProofBytes": "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestAggregateV3RejectsBadSig — wrong signer returns 403.
func TestAggregateV3RejectsBadSig(t *testing.T) {
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

	castV3Vote(t, srv, pollID, pk, 1, 8)
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)

	body := map[string]any{
		"creator":           "0x000000000000000000000000000000000000dEAD",
		"signature":         "0xdeadbeef",
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

// TestAggregateV3RejectsWrongTally — claim tallies that don't match
// the actual decrypt; proof won't verify; 403.
func TestAggregateV3RejectsWrongTally(t *testing.T) {
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

	castV3Vote(t, srv, pollID, pk, 0, 8)
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)

	// Claim bin 0 has 5 instead of 1. Server signs it (its sig payload
	// uses the lying tallies) but the proof won't pass verification.
	wrong := append([]int64(nil), tallies...)
	wrong[0] = 5

	sig, _ := signAggregate(t, pollID, wrong)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           wrong,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d body=%q", w.Code, w.Body.String())
	}
	// Poll must remain active — failed close is a no-op.
	poll2, _ := srv.store.ReadPoll(pollID)
	if poll2.Status != "active" {
		t.Errorf("failed close mutated status: %q", poll2.Status)
	}
}

// TestAggregateV3RejectsNoVotes — empty poll → 400.
func TestAggregateV3RejectsNoVotes(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	srv := testServer(t)
	attachV3FullProver(t, srv)

	pollID, _, _ := seedV3Poll(t, srv)
	poll, _ := srv.store.ReadPoll(pollID)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	tallies := make([]int64, 8)
	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestGetHomomorphicTally — GET /tally returns the artifact after close.
func TestGetHomomorphicTally(t *testing.T) {
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

	castV3Vote(t, srv, pollID, pk, 3, 8)
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	if w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body); w.Code != 200 {
		t.Fatalf("aggregate: %d body=%q", w.Code, w.Body.String())
	}

	// GET /tally
	resp := getReq(t, srv, "/api/polls/"+pollID+"/tally")
	if resp.Code != 200 {
		t.Fatalf("get tally: %d body=%q", resp.Code, resp.Body.String())
	}
	var got store.HomomorphicTallyArtifact
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tallies[3] != 1 {
		t.Errorf("tally[3]: got %d, want 1", got.Tallies[3])
	}
}

// getReq — small helper to GET with the test server.
func getReq(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}
