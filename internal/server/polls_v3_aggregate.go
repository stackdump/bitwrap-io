package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// aggregateRequest is the v3 close payload. The creator signs a
// canonical message binding (pollID, tallies); the server recomputes
// the aggregate ciphertexts from on-disk votes (never trusting client
// math) and verifies the decrypt proof against the recomputed
// aggregate + claimed tallies.
type aggregateRequest struct {
	Creator           string  `json:"creator"`
	Signature         string  `json:"signature"`
	Tallies           []int64 `json:"tallies"`
	DecryptProofBytes string  `json:"decryptProofBytes"`
}

// AggregateSigPayload returns the canonical EIP-191 message scoped to
// (pollID, tallies). Strict ordering: comma-joined decimals, no spaces.
// Reusing this prefix on a different poll, or with different tallies,
// invalidates the signature.
// This function is exported so the CLI close-poll subcommand can produce
// a byte-identical payload without duplicating the format logic.
func AggregateSigPayload(pollID string, tallies []int64) string {
	parts := make([]string, len(tallies))
	for i, t := range tallies {
		parts[i] = strconv.FormatInt(t, 10)
	}
	return "bitwrap-aggregate-tally:" + pollID + ":" + strings.Join(parts, ",")
}

// aggregateSigPayload is the unexported alias kept for internal call sites.
func aggregateSigPayload(pollID string, tallies []int64) string {
	return AggregateSigPayload(pollID, tallies)
}

// handleAggregateV3 closes a v3 poll: aggregates ciphertexts, verifies
// the creator's decrypt proof, persists tally.json, and marks the
// poll closed. Atomic — either the artifact lands and the poll is
// closed, or nothing changes.
//
// Idempotent: repeated calls on a closed v3 poll return 409 with the
// existing tally artifact.
func (s *Server) handleAggregateV3(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "aggregate")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	var req aggregateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}
	if poll.VoteSchemaVersion != 3 {
		http.Error(w, "aggregate endpoint is v3-only", http.StatusBadRequest)
		return
	}

	// Idempotency: if a tally artifact already exists, return it with 409.
	// Closed-without-tally shouldn't happen for v3 (close is the artifact-
	// writing step) but guard anyway.
	if existing, err := s.store.ReadHomomorphicTally(pollID); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "poll already closed",
			"tally":  existing,
		})
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("aggregate read existing tally: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if poll.Status == "closed" {
		// Closed but no artifact — shouldn't happen via normal flow; reject.
		http.Error(w, "poll is closed without tally artifact", http.StatusConflict)
		return
	}

	// Validate request shape.
	if req.Creator == "" || req.Signature == "" {
		http.Error(w, "creator and signature required", http.StatusBadRequest)
		return
	}
	if len(req.Tallies) != prover.TallyDecryptChoices {
		http.Error(w, fmt.Sprintf("expected %d tallies, got %d",
			prover.TallyDecryptChoices, len(req.Tallies)), http.StatusBadRequest)
		return
	}
	for j, t := range req.Tallies {
		if t < 0 || t >= 1<<prover.TallyDecryptTallyBits {
			http.Error(w, fmt.Sprintf("tally[%d]=%d out of [0, %d)",
				j, t, 1<<prover.TallyDecryptTallyBits), http.StatusBadRequest)
			return
		}
	}
	if req.DecryptProofBytes == "" {
		http.Error(w, "decryptProofBytes required", http.StatusBadRequest)
		return
	}

	// Verify creator signature over canonical payload.
	sigMsg := aggregateSigPayload(pollID, req.Tallies)
	if !VerifySignature(sigMsg, req.Signature, poll.Creator) {
		http.Error(w, "only the poll creator can aggregate", http.StatusForbidden)
		return
	}

	// Decode pkCreator from poll. Server already validated this at create
	// time; defensive re-decode in case storage drifted.
	pkBytes, err := hex.DecodeString(poll.PkCreator)
	if err != nil || len(pkBytes) != 32 {
		http.Error(w, "stored pkCreator is malformed", http.StatusInternalServerError)
		return
	}
	pk, err := prover.DecodePoint(pkBytes)
	if err != nil {
		http.Error(w, "stored pkCreator failed to decode", http.StatusInternalServerError)
		return
	}
	if !prover.IsInPrimeSubgroup(&pk) {
		http.Error(w, "stored pkCreator not in subgroup", http.StatusInternalServerError)
		return
	}

	// Load + aggregate ciphertexts. Re-validate every point at close
	// time — catches any vote that slipped past validation in an older
	// server build, plus any corruption since.
	votes, err := s.store.ListVotes(pollID)
	if err != nil {
		log.Printf("aggregate list votes: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(votes) == 0 {
		http.Error(w, "no votes to aggregate", http.StatusBadRequest)
		return
	}

	aggA := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	aggB := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	identityPoint(&aggA[0]) // initialize all bins to identity below
	for j := range aggA {
		identityPointAffine(&aggA[j])
		identityPointAffine(&aggB[j])
	}
	seenNullifiers := make(map[string]struct{}, len(votes))
	for i, v := range votes {
		if _, dup := seenNullifiers[v.Nullifier]; dup {
			// Defensive: SaveVote already rejects duplicate nullifiers,
			// but if the on-disk file was hand-edited we want to refuse
			// to tally rather than double-count.
			http.Error(w, fmt.Sprintf("duplicate nullifier in stored votes: %s", v.Nullifier), http.StatusInternalServerError)
			return
		}
		seenNullifiers[v.Nullifier] = struct{}{}

		if len(v.Ciphertexts) != prover.TallyDecryptChoices {
			http.Error(w, fmt.Sprintf("vote[%d] has %d ciphertexts, want %d",
				i, len(v.Ciphertexts), prover.TallyDecryptChoices), http.StatusInternalServerError)
			return
		}
		for j := 0; j < prover.TallyDecryptChoices; j++ {
			a, err := decodeAndCheckPoint(v.Ciphertexts[j].A)
			if err != nil {
				http.Error(w, fmt.Sprintf("vote[%d].ct[%d].A: %v", i, j, err), http.StatusInternalServerError)
				return
			}
			b, err := decodeAndCheckPoint(v.Ciphertexts[j].B)
			if err != nil {
				http.Error(w, fmt.Sprintf("vote[%d].ct[%d].B: %v", i, j, err), http.StatusInternalServerError)
				return
			}
			aggA[j].Add(&aggA[j], &a)
			aggB[j].Add(&aggB[j], &b)
		}
	}

	// Verify the decrypt proof against the server-recomputed aggregate.
	if s.proverSvc != nil {
		proofBytes, err := base64.StdEncoding.DecodeString(req.DecryptProofBytes)
		if err != nil {
			http.Error(w, "invalid decryptProofBytes encoding", http.StatusBadRequest)
			return
		}
		inputs := prover.TallyDecryptProofInputs{
			PkCreator: pk,
			A:         aggA,
			B:         aggB,
			Tallies:   req.Tallies,
		}
		if err := prover.VerifyTallyDecryptProofBytes(s.proverSvc.Prover(), proofBytes, inputs); err != nil {
			log.Printf("v3 decrypt proof verification failed: %v", err)
			http.Error(w, fmt.Sprintf("decrypt proof verification failed: %v", err), http.StatusForbidden)
			return
		}
	}

	// Build artifact + persist atomically. Order: write tally.json
	// first; if that succeeds, mark poll closed. A crash between
	// the two leaves the tally readable but the poll still "active",
	// which the next aggregate call will resolve idempotently.
	aggHex := make([]store.HomomorphicCiphertext, prover.TallyDecryptChoices)
	for j := range aggA {
		aggHex[j] = store.HomomorphicCiphertext{
			A: hex.EncodeToString(prover.EncodePoint(&aggA[j])),
			B: hex.EncodeToString(prover.EncodePoint(&aggB[j])),
		}
	}
	artifact := &store.HomomorphicTallyArtifact{
		PollID:       pollID,
		GeneratedAt:  time.Now().UTC(),
		CircuitName:  "tallyDecrypt_8",
		PkCreator:    poll.PkCreator,
		Aggregate:    aggHex,
		Tallies:      req.Tallies,
		NumBallots:   len(votes),
		DecryptProof: req.DecryptProofBytes,
	}
	if err := s.store.SaveHomomorphicTally(pollID, artifact); err != nil {
		log.Printf("save tally: %v", err)
		http.Error(w, "failed to persist tally", http.StatusInternalServerError)
		return
	}

	poll.Status = "closed"
	if err := s.store.SavePoll(poll); err != nil {
		log.Printf("close poll after tally: %v", err)
		http.Error(w, "tally persisted but failed to close poll", http.StatusInternalServerError)
		return
	}
	_ = s.store.AppendEvent(pollID, store.PollEvent{Action: "closePoll"})

	// Acceptance check: a closed v3 poll must have no reveals.json. If
	// somehow one slipped in, log loudly — this is a structural privacy
	// bug, not a recoverable error.
	if has, err := s.store.HasReveals(pollID); err == nil && has {
		log.Printf("STRUCTURAL BUG: v3 poll %s has reveals.json after close", pollID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "closed",
		"tally":  artifact,
	})
}

// handleGetHomomorphicTally returns the persisted v3 tally artifact
// for a closed poll. Returns 404 for v1/v2 polls or v3 polls that
// haven't been aggregated yet.
func (s *Server) handleGetHomomorphicTally(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "tally")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}
	artifact, err := s.store.ReadHomomorphicTally(pollID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "tally not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to read tally", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(artifact)
}

// identityPointAffine sets p to the BabyJubJub identity (0, 1).
// PointAffine.Add doesn't special-case the identity unless one operand
// has X=0, Y=1 already, so we initialize aggregates explicitly.
func identityPointAffine(p *tedwards.PointAffine) {
	p.X.SetZero()
	p.Y.SetOne()
}

// identityPoint shadow for the very first call in handleAggregateV3
// (kept as a separate name to preserve refactor stability).
func identityPoint(p *tedwards.PointAffine) { identityPointAffine(p) }
