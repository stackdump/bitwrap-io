package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// seedV3Poll writes a v3 poll with 8 choices, a creator, an empty
// registry, and a single registerVoter event so one castVote slot is
// available. Returns (pollID, sk, pk).
func seedV3Poll(t *testing.T, srv *Server) (string, *big.Int, tedwards.PointAffine) {
	t.Helper()
	g := prover.PedersenG()
	sk := big.NewInt(0xfeedface)
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)
	pkHex := hex.EncodeToString(prover.EncodePoint(&pk))

	pollID := fmt.Sprintf("v3test-%d", time.Now().UnixNano())
	poll := &store.Poll{
		ID:                pollID,
		Title:             "v3 vote test",
		Choices:           []string{"A", "B", "C", "D", "E", "F", "G", "H"},
		Creator:           "0x0000000000000000000000000000000000000001",
		CreatedAt:         time.Now().UTC(),
		Status:            "active",
		RegistryRoot:      "0x1",
		VoteSchemaVersion: 3,
		PkCreator:         pkHex,
	}
	if err := srv.store.SavePoll(poll); err != nil {
		t.Fatal(err)
	}
	_ = srv.store.AppendEvent(pollID, store.PollEvent{Action: "createPoll"})
	_ = srv.store.AppendEvent(pollID, store.PollEvent{Action: "registerVoter"})
	return pollID, sk, pk
}

// buildV3VoteRequest produces a fresh real proof for a vote in the
// given choice bin. Heavy — compiles the circuit on first call (~5s).
// Reuses srv.proverSvc to amortize across tests in the same run.
//
// Returns proofBytes, ciphertexts (hex), nullifier, and the registry
// root the witness was built against — the caller must mirror this
// onto the poll's RegistryRoot or the server-rebuilt public witness
// will diverge from what was proved against.
func buildV3VoteRequest(
	t *testing.T,
	srv *Server,
	pollID string,
	pk tedwards.PointAffine,
	choice int,
	maxChoices int,
) ([]byte, []store.HomomorphicCiphertext, *big.Int, *big.Int) {
	t.Helper()

	pollIDInt := new(big.Int).SetBytes([]byte(pollID))
	secret := big.NewInt(int64(7777 + time.Now().UnixNano()&0xffff)) // semi-unique per call to avoid nullifier reuse
	weight := big.NewInt(1)

	// Witness build (mirrors prover/vote_homomorphic_test.go).
	w := &prover.VoteCastHomomorphicCircuit_8{}
	w.PollID = pollIDInt
	w.MaxChoices = maxChoices
	w.VoterSecret = secret
	w.VoterWeight = weight

	leaf := prover.MiMCHashBigInt(secret, weight)
	current := leaf
	zero := big.NewInt(0)
	for i := 0; i < 20; i++ {
		w.PathElements[i] = zero
		w.PathIndices[i] = 0
		current = prover.MiMCHashBigInt(current, zero)
	}
	w.VoterRegistryRoot = current
	nullifier := prover.MiMCHashBigInt(secret, pollIDInt)
	w.Nullifier = nullifier

	w.PkCreator = pointAsVar(&pk)

	cthex := make([]store.HomomorphicCiphertext, prover.VoteCastHomomorphicChoices)
	for j := 0; j < prover.VoteCastHomomorphicChoices; j++ {
		var vj int64
		if j == choice {
			vj = 1
		}
		r := big.NewInt(int64(3_000_000 + j*97 + 1))
		ct := prover.Encrypt(big.NewInt(vj), r, &pk)
		w.V[j] = vj
		w.R[j] = r
		w.CtA[j] = ctPointAsVar(&ct.A)
		w.CtB[j] = ctPointAsVar(&ct.B)
		cthex[j] = store.HomomorphicCiphertext{
			A: hex.EncodeToString(prover.EncodePoint(&ct.A)),
			B: hex.EncodeToString(prover.EncodePoint(&ct.B)),
		}
	}

	// Compile circuit + prove. We have to use the gnark frontend
	// directly here because the lazy-circuit registration in
	// prover/circuits.go needs proverSvc.Prover() and we want this
	// helper to be usable even when proverSvc=nil.
	ccs, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}

	// Use the server's prover service: ensures circuit compile is
	// cached for repeated calls.
	if srv.proverSvc == nil {
		t.Fatalf("buildV3VoteRequest needs srv.proverSvc — call attachV3Prover first")
	}
	cc, ok := srv.proverSvc.Prover().GetCircuit("voteCastHomomorphic_8")
	if !ok {
		t.Fatalf("voteCastHomomorphic_8 not registered on prover")
	}

	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, ccs)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		t.Fatalf("proof serialize: %v", err)
	}
	return buf.Bytes(), cthex, nullifier, current
}

// alignPollRoot writes the witness-derived registry root onto the poll
// so the server's public-witness reconstruction matches what the
// prover used. Real polls compute root from VoterCommitments at create
// time; in tests we compute it from a synthetic merkle path inside
// buildV3VoteRequest, so the alignment is explicit.
func alignPollRoot(t *testing.T, srv *Server, pollID string, root *big.Int) {
	t.Helper()
	poll, err := srv.store.ReadPoll(pollID)
	if err != nil {
		t.Fatal(err)
	}
	poll.RegistryRoot = root.String()
	if err := srv.store.SavePoll(poll); err != nil {
		t.Fatal(err)
	}
}

// attachV3Prover compiles voteCastHomomorphic_8 into a fresh prover
// service and attaches it to srv. Returns immediately if already
// attached so a test can call it idempotently.
func attachV3Prover(t *testing.T, srv *Server) {
	t.Helper()
	if srv.proverSvc != nil {
		if _, ok := srv.proverSvc.Prover().GetCircuit("voteCastHomomorphic_8"); ok {
			return
		}
	}
	p := prover.NewProver()
	cc, err := p.CompileCircuit("voteCastHomomorphic_8", &prover.VoteCastHomomorphicCircuit_8{})
	if err != nil {
		t.Fatalf("compile homomorphic circuit: %v", err)
	}
	p.StoreCircuit("voteCastHomomorphic_8", cc)
	srv.proverSvc = prover.NewService(p, &prover.ArcnetWitnessFactory{})
}

// pointAsVar / ctPointAsVar — convert PointAffine to gnark's circuit
// Point. Tests-only helpers; not exported beyond this file.
func pointAsVar(p *tedwards.PointAffine) gtwPointVar {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return gtwPointVar{X: &x, Y: &y}
}
func ctPointAsVar(p *tedwards.PointAffine) gtwPointVar { return pointAsVar(p) }

// gtwPointVar is a thin alias so we don't import gnark's twistededwards
// type in every test. Concrete type matches frontend.Variable layout.
type gtwPointVar = struct {
	X frontend.Variable
	Y frontend.Variable
}

// --- v3 vote tests ---------------------------------------------------------

// TestCastVoteV3HappyPath — real witness, real proof, server validates
// and persists. Slow on first run (~5s for circuit compile + prove).
func TestCastVoteV3HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 vote test compiles a 70k-constraint circuit; skip in short mode")
	}
	srv := testServer(t)
	attachV3Prover(t, srv)

	pollID, _, pk := seedV3Poll(t, srv)
	proofBytes, cthex, nullifier, root := buildV3VoteRequest(t, srv, pollID, pk, 2, 8)
	alignPollRoot(t, srv, pollID, root)

	body := map[string]any{
		"nullifier":   nullifier.String(),
		"ciphertexts": cthex,
		"proofBytes":  base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 200 {
		t.Fatalf("v3 vote: got %d body=%q", w.Code, w.Body.String())
	}

	// Stored vote must carry ciphertexts, no voteCommitment.
	votes, err := srv.store.ListVotes(pollID)
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) != 1 {
		t.Fatalf("expected 1 vote, got %d", len(votes))
	}
	v := votes[0]
	if v.VoteCommitment != "" {
		t.Errorf("v3 vote has VoteCommitment: %q", v.VoteCommitment)
	}
	if len(v.Ciphertexts) != 8 {
		t.Errorf("v3 vote has %d ciphertexts, want 8", len(v.Ciphertexts))
	}

	// No reveals.json for v3 polls — the structural privacy property.
	has, err := srv.store.HasReveals(pollID)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("v3 poll has reveals.json after a vote — structural bug")
	}
}

// TestCastVoteV3RejectsVoteCommitment — sending a v1/v2-style
// voteCommitment on a v3 poll must 400 so client misconfigurations
// fail loudly.
func TestCastVoteV3RejectsVoteCommitment(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)
	body := map[string]any{
		"nullifier":      "0x1",
		"voteCommitment": "0xdeadbeef",
		"proofBytes":     "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestCastVoteV3RejectsVoterSecret — sending witness.voterSecret must
// 400 (the server must never see it for v3).
func TestCastVoteV3RejectsVoterSecret(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)
	body := map[string]any{
		"nullifier":   "0x1",
		"witness":     map[string]string{"voterSecret": "42"},
		"ciphertexts": fakeCipherTexts(),
		"proofBytes":  "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "voterSecret") {
		t.Errorf("expected voterSecret in error: %q", w.Body.String())
	}
}

// TestCastVoteV3RejectsCipherCount — wrong number of ciphertexts must 400.
func TestCastVoteV3RejectsCipherCount(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)
	body := map[string]any{
		"nullifier":   "0x1",
		"ciphertexts": fakeCipherTexts()[:3],
		"proofBytes":  "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestCastVoteV3RejectsBadCiphertextHex — malformed hex must 400.
func TestCastVoteV3RejectsBadCiphertextHex(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)
	cts := fakeCipherTexts()
	cts[0].A = "not-hex-at-all"
	body := map[string]any{
		"nullifier":   "0x1",
		"ciphertexts": cts,
		"proofBytes":  "AAAA",
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestCastVoteV3RejectsTamperedProof — flip a byte in the proof and
// expect 403 from the verifier.
func TestCastVoteV3RejectsTamperedProof(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	srv := testServer(t)
	attachV3Prover(t, srv)

	pollID, _, pk := seedV3Poll(t, srv)
	proofBytes, cthex, nullifier, root := buildV3VoteRequest(t, srv, pollID, pk, 0, 8)
	alignPollRoot(t, srv, pollID, root)
	proofBytes[10] ^= 0xff // tamper

	body := map[string]any{
		"nullifier":   nullifier.String(),
		"ciphertexts": cthex,
		"proofBytes":  base64.StdEncoding.EncodeToString(proofBytes),
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestCastVoteV3DoubleSpend — same nullifier twice returns 409 on
// second submission. Re-uses the same proof on purpose; the server's
// uniqueness check sits in front of the verifier.
func TestCastVoteV3DoubleSpend(t *testing.T) {
	if testing.Short() {
		t.Skip("")
	}
	srv := testServer(t)
	attachV3Prover(t, srv)

	pollID, _, pk := seedV3Poll(t, srv)
	registerTestVoter(t, srv, pollID) // open a second slot
	proofBytes, cthex, nullifier, root := buildV3VoteRequest(t, srv, pollID, pk, 1, 8)
	alignPollRoot(t, srv, pollID, root)
	encoded := base64.StdEncoding.EncodeToString(proofBytes)

	body := map[string]any{
		"nullifier":   nullifier.String(),
		"ciphertexts": cthex,
		"proofBytes":  encoded,
	}
	w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w.Code != 200 {
		t.Fatalf("first vote: got %d body=%q", w.Code, w.Body.String())
	}
	w2 := postJSON(t, srv, "/api/polls/"+pollID+"/vote", body)
	if w2.Code != 409 {
		t.Fatalf("double spend: expected 409, got %d body=%q", w2.Code, w2.Body.String())
	}
}

// fakeCipherTexts produces 8 random-looking but well-formed-hex
// ciphertexts (not actually on curve). Used in negative tests where
// we expect failure before subgroup-check.
func fakeCipherTexts() []store.HomomorphicCiphertext {
	out := make([]store.HomomorphicCiphertext, 8)
	for j := range out {
		out[j] = store.HomomorphicCiphertext{
			A: strings.Repeat("aa", 32),
			B: strings.Repeat("bb", 32),
		}
	}
	return out
}

