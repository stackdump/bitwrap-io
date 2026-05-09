package server

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// handleCastVoteV3 processes a vote against a v3 (homomorphic-tally)
// poll. Returns a non-nil error iff a response has already been
// written; the caller should bail out without writing again.
//
// Defensive contract: this function must not store or log anything
// that could be used to recover an individual voter's choice. The
// only inputs persisted are (nullifier, ciphertexts, proof). The
// proof's private witness (one-hot V[K], randomness R[K], voter
// secret) is never sent over the wire.
func (s *Server) handleCastVoteV3(w http.ResponseWriter, r *http.Request, poll *store.Poll, req *castVoteRequest) error {
	// Reject leakage fields. A v3 client that sends voteCommitment is
	// confused — fail loudly so the bug surfaces at submit time
	// instead of as a silently-stored choice trail later.
	if req.VoteCommitment != "" {
		http.Error(w, "voteCommitment is not valid on v3 polls (use ciphertexts)", http.StatusBadRequest)
		return fmt.Errorf("voteCommitment present")
	}
	if _, ok := req.Witness["voterSecret"]; ok {
		http.Error(w, "voterSecret must not be sent for v3 polls", http.StatusBadRequest)
		return fmt.Errorf("voterSecret in witness")
	}
	if _, ok := req.Witness["voteChoice"]; ok {
		http.Error(w, "voteChoice must not be sent for v3 polls", http.StatusBadRequest)
		return fmt.Errorf("voteChoice in witness")
	}

	if len(req.Ciphertexts) != prover.VoteCastHomomorphicChoices {
		http.Error(w, fmt.Sprintf("expected %d ciphertexts, got %d",
			prover.VoteCastHomomorphicChoices, len(req.Ciphertexts)), http.StatusBadRequest)
		return fmt.Errorf("ciphertext count mismatch")
	}
	if req.ProofBytes == "" {
		http.Error(w, "proofBytes required for v3 vote", http.StatusBadRequest)
		return fmt.Errorf("missing proofBytes")
	}

	// Decode ciphertext points and check on-curve / in-subgroup. Without
	// the subgroup check, a voter with a small-subgroup-crafted point
	// could leak server-internal state during aggregation; the prover
	// would still accept it because the curve has cofactor 8.
	cts := make([]prover.Ciphertext, prover.VoteCastHomomorphicChoices)
	for j := 0; j < prover.VoteCastHomomorphicChoices; j++ {
		a, err := decodeAndCheckPoint(req.Ciphertexts[j].A)
		if err != nil {
			http.Error(w, fmt.Sprintf("ciphertext[%d].A: %v", j, err), http.StatusBadRequest)
			return err
		}
		b, err := decodeAndCheckPoint(req.Ciphertexts[j].B)
		if err != nil {
			http.Error(w, fmt.Sprintf("ciphertext[%d].B: %v", j, err), http.StatusBadRequest)
			return err
		}
		cts[j] = prover.Ciphertext{A: a, B: b}
	}

	// Poll's PkCreator must already be valid (validated at create time)
	// but defensively re-decode here in case storage was tampered with.
	pkBytes, err := hex.DecodeString(poll.PkCreator)
	if err != nil || len(pkBytes) != 32 {
		http.Error(w, "stored pkCreator is malformed", http.StatusInternalServerError)
		return fmt.Errorf("bad stored pkCreator")
	}
	pk, err := prover.DecodePoint(pkBytes)
	if err != nil {
		http.Error(w, "stored pkCreator failed to decode", http.StatusInternalServerError)
		return err
	}

	proofBytes, err := base64.StdEncoding.DecodeString(req.ProofBytes)
	if err != nil {
		http.Error(w, "invalid proofBytes encoding", http.StatusBadRequest)
		return err
	}

	if s.proverSvc != nil {
		// pollId is hex-decoded into a 128-bit big int, matching the v2 path.
		pollIDInt := new(big.Int).SetBytes([]byte(poll.ID))
		registryRoot, err := parseHexToBig(poll.RegistryRoot)
		if err != nil {
			http.Error(w, fmt.Sprintf("registry root parse: %v", err), http.StatusInternalServerError)
			return err
		}
		nullifierInt, err := parseHexToBig(req.Nullifier)
		if err != nil {
			http.Error(w, fmt.Sprintf("nullifier parse: %v", err), http.StatusBadRequest)
			return err
		}

		inputs := prover.VoteCastHomomorphicProofInputs{
			PollID:       pollIDInt,
			RegistryRoot: registryRoot,
			Nullifier:    nullifierInt,
			MaxChoices:   len(poll.Choices),
			PkCreator:    pk,
			Ciphertexts:  cts,
		}
		if err := prover.VerifyVoteCastHomomorphicProofBytes(s.proverSvc.Prover(), proofBytes, inputs); err != nil {
			log.Printf("v3 proof verification failed: %v", err)
			http.Error(w, fmt.Sprintf("ZK proof verification failed: %v", err), http.StatusForbidden)
			return err
		}
	}

	vote := &store.VoteRecord{
		Nullifier:   req.Nullifier,
		Proof:       "client-side:" + req.ProofBytes[:min(32, len(req.ProofBytes))] + "...",
		Timestamp:   time.Now().UTC(),
		Ciphertexts: req.Ciphertexts,
	}
	if err := s.store.SaveVote(poll.ID, vote); err != nil {
		if strings.Contains(err.Error(), "nullifier already used") {
			http.Error(w, "Vote already cast (nullifier used)", http.StatusConflict)
			return err
		}
		log.Printf("Failed to save v3 vote: %v", err)
		http.Error(w, "Failed to record vote", http.StatusInternalServerError)
		return err
	}

	// Append castVote event with nullifier only — choice and weight
	// are deliberately not bound (the server doesn't know them, by
	// design). The Petri runtime's "one vote per registration"
	// invariant is satisfied by the nullifier alone.
	_ = s.store.AppendEvent(poll.ID, store.PollEvent{
		Action:   "castVote",
		Bindings: map[string]string{"nullifier": req.Nullifier},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
	return nil
}

// decodeAndCheckPoint parses a 32-byte compressed BabyJubJub hex point
// and verifies it lies in the prime-order subgroup.
func decodeAndCheckPoint(hx string) (tedwards.PointAffine, error) {
	var p tedwards.PointAffine
	buf, err := hex.DecodeString(hx)
	if err != nil {
		return p, fmt.Errorf("hex decode: %w", err)
	}
	p, err = prover.DecodePoint(buf)
	if err != nil {
		return p, err
	}
	if !prover.IsInPrimeSubgroup(&p) {
		return p, fmt.Errorf("not in prime-order subgroup")
	}
	return p, nil
}

// parseHexToBig accepts hex with or without 0x prefix and parses it as
// a big.Int. Decimal input also works (existing fixtures store
// registry roots as decimal-stringified field elements).
func parseHexToBig(s string) (*big.Int, error) {
	s = strings.TrimPrefix(s, "0x")
	n, ok := new(big.Int).SetString(s, 0)
	if ok {
		return n, nil
	}
	// Try decimal explicitly (SetString with base 0 needs a 0x/0o/0b prefix).
	n, ok = new(big.Int).SetString(s, 10)
	if !ok {
		// Last resort: try as bare hex.
		n, ok = new(big.Int).SetString(s, 16)
		if !ok {
			return nil, fmt.Errorf("could not parse %q", s)
		}
	}
	return n, nil
}
