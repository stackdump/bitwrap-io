package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// createPollRequest is the request body for POST /api/polls.
type createPollRequest struct {
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Choices          []string `json:"choices"`
	DurationMinutes  int      `json:"durationMinutes"`
	VoterCommitments []string `json:"voterCommitments"`
	RegistryRoot     string   `json:"registryRoot"`
	Creator          string   `json:"creator"`   // Ethereum address (0x...)
	Signature        string   `json:"signature"` // EIP-191 personal_sign of "bitwrap-create-poll:{title}"
}

// castVoteRequest is the request body for POST /api/polls/{id}/vote.
type castVoteRequest struct {
	Nullifier      string            `json:"nullifier"`
	VoteCommitment string            `json:"voteCommitment"`             // mimcHash(voterSecret, voteChoice) — blinded
	Proof          string            `json:"proof"`
	Witness        map[string]string `json:"witness,omitempty"`          // full witness for server-side verification
	PublicInputs   []string          `json:"publicInputs,omitempty"`     // proof public inputs for validation

	// Client-side proof bytes (privacy-preserving path — server never sees private inputs)
	ProofBytes         string `json:"proofBytes,omitempty"`         // base64 gnark proof
	PublicWitnessBytes string `json:"publicWitnessBytes,omitempty"` // base64 gnark public witness
}

// revealVoteRequest is the request body for POST /api/polls/{id}/reveal.
type revealVoteRequest struct {
	Nullifier   string `json:"nullifier"`
	VoteChoice  int    `json:"voteChoice"`
	VoterSecret string `json:"voterSecret"` // needed to verify: mimcHash(secret, choice) == commitment
}

// handleCreatePoll creates a new ZK poll.
func (s *Server) handleCreatePoll(w http.ResponseWriter, r *http.Request) {
	var req createPollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Rate limit by IP
	clientIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.SplitN(fwd, ",", 2)[0]
	}
	if !s.opts.DevMode && !s.pollRateLimiter.Allow(clientIP) {
		http.Error(w, "rate limit exceeded (5 polls per hour)", http.StatusTooManyRequests)
		return
	}

	// Require wallet signature
	if req.Creator == "" || req.Signature == "" {
		http.Error(w, "creator address and signature required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.Creator, "0x") || len(req.Creator) != 42 {
		http.Error(w, "invalid creator address", http.StatusBadRequest)
		return
	}
	sigMsg := "bitwrap-create-poll:" + req.Title
	if !VerifySignature(sigMsg, req.Signature, req.Creator) {
		http.Error(w, "signature does not match creator address", http.StatusForbidden)
		return
	}

	// Also rate limit by wallet address
	if !s.opts.DevMode && !s.pollRateLimiter.Allow("wallet:"+strings.ToLower(req.Creator)) {
		http.Error(w, "rate limit exceeded for this wallet (5 polls per hour)", http.StatusTooManyRequests)
		return
	}

	// Validate limits
	if req.Title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}
	if len(req.Title) > 200 {
		http.Error(w, "title too long (max 200 chars)", http.StatusBadRequest)
		return
	}
	if len(req.Description) > 2000 {
		http.Error(w, "description too long (max 2000 chars)", http.StatusBadRequest)
		return
	}
	if len(req.Choices) < 2 {
		http.Error(w, "at least 2 choices required", http.StatusBadRequest)
		return
	}
	if len(req.Choices) > 256 {
		http.Error(w, "too many choices (max 256, matching ZK circuit's 8-bit range)", http.StatusBadRequest)
		return
	}
	for _, c := range req.Choices {
		if len(c) > 500 {
			http.Error(w, "choice text too long (max 500 chars)", http.StatusBadRequest)
			return
		}
	}
	if len(req.VoterCommitments) > 10000 {
		http.Error(w, "too many voter commitments (max 10000)", http.StatusBadRequest)
		return
	}
	if req.DurationMinutes < 0 {
		http.Error(w, "duration cannot be negative", http.StatusBadRequest)
		return
	}
	const maxDuration = 60 * 24 * 90 // 90 days
	if req.DurationMinutes > maxDuration {
		http.Error(w, "duration too long (max 90 days)", http.StatusBadRequest)
		return
	}

	// Generate poll ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "failed to generate poll ID", http.StatusInternalServerError)
		return
	}
	pollID := hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	var expiresAt time.Time
	if req.DurationMinutes > 0 {
		expiresAt = now.Add(time.Duration(req.DurationMinutes) * time.Minute)
	}

	poll := &store.Poll{
		ID:                pollID,
		Title:             req.Title,
		Description:       req.Description,
		Choices:           req.Choices,
		Creator:           strings.ToLower(req.Creator),
		CreatedAt:         now,
		ExpiresAt:         expiresAt,
		Status:            "active",
		VoterCommitments:  req.VoterCommitments,
		RegistryRoot:      req.RegistryRoot,
		VoteSchemaVersion: 2, // coercion-resistant nonce-augmented scheme; legacy polls keep v1
	}

	// Compute registry root from commitments if provided but root not set
	if len(poll.VoterCommitments) > 0 && poll.RegistryRoot == "" {
		poll.RegistryRoot = computeRegistryRoot(poll.VoterCommitments)
	}

	if err := s.store.SavePoll(poll); err != nil {
		log.Printf("Failed to save poll: %v", err)
		http.Error(w, "Failed to create poll", http.StatusInternalServerError)
		return
	}

	// Append createPoll event to the Petri net event log
	_ = s.store.AppendEvent(pollID, store.PollEvent{Action: "createPoll"})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":  pollID,
		"url": fmt.Sprintf("/poll#%s", pollID),
	})
}

// handleGetPoll returns a poll's config and current state.
func (s *Server) handleGetPoll(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollID(r.URL.Path)
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	// Auto-close expired polls
	if poll.Status == "active" && !poll.ExpiresAt.IsZero() && time.Now().UTC().After(poll.ExpiresAt) {
		poll.Status = "closed"
		_ = s.store.SavePoll(poll)
	}

	votes, _ := s.store.ListVotes(pollID)
	voteCount := len(votes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"poll":      poll,
		"voteCount": voteCount,
	})
}

// handleCastVote submits a ZK-proven vote.
func (s *Server) handleCastVote(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollID(r.URL.Path)
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	if poll.Status != "active" {
		http.Error(w, "Poll is not active", http.StatusBadRequest)
		return
	}

	// Auto-close expired polls
	if !poll.ExpiresAt.IsZero() && time.Now().UTC().After(poll.ExpiresAt) {
		poll.Status = "closed"
		_ = s.store.SavePoll(poll)
		http.Error(w, "Poll has expired", http.StatusBadRequest)
		return
	}

	if poll.RegistryRoot == "" {
		http.Error(w, "voter registry is empty — register before voting", http.StatusBadRequest)
		return
	}

	// Registry root must be under a creator-signed acknowledgement. Without
	// this, the server could inject a shadow commitment between register
	// and vote. We skip the check on polls created before the feature
	// landed (no RegistryRootSigs entry yet means legacy; those polls keep
	// their pre-existing trust model).
	if len(poll.RegistryRootSigs) > 0 {
		latest := poll.RegistryRootSigs[len(poll.RegistryRootSigs)-1]
		if latest.Root != poll.RegistryRoot {
			http.Error(w, "registry root has new registrations awaiting creator sign-off; try again shortly", http.StatusConflict)
			return
		}
	}

	// Petri net runtime gate (phase 2.7): replay past events through the
	// schema Runtime and check if the castVote transition is enabled.
	// The registrySlots TokenState + its registerVoter→registrySlots→castVote
	// arcs enforce the "one vote per registration" invariant at the net
	// level, replacing the phase-1 event-count counter.
	storeEvents, _ := s.store.ReadEvents(pollID)
	events := make([]PollEvent, 0, len(storeEvents))
	for _, e := range storeEvents {
		events = append(events, PollEvent{Action: e.Action, Bindings: e.Bindings})
	}
	rt := PollRuntime(events)
	if !rt.Enabled("castVote") {
		http.Error(w, "voter registry exhausted — all registration slots have been used", http.StatusConflict)
		return
	}

	var req castVoteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Nullifier == "" {
		http.Error(w, "nullifier required", http.StatusBadRequest)
		return
	}
	if req.VoteCommitment == "" {
		http.Error(w, "voteCommitment required (blinded vote hash)", http.StatusBadRequest)
		return
	}
	if req.Proof == "" && len(req.Witness) == 0 && req.ProofBytes == "" {
		http.Error(w, "proof, witness, or proofBytes required", http.StatusBadRequest)
		return
	}

	// ZK proof verification
	if s.proverSvc != nil {
		p := s.proverSvc.Prover()

		if req.ProofBytes != "" && req.PublicWitnessBytes != "" {
			// Client-side proof path — server never sees private inputs.
			// Decode base64 proof and public witness bytes.
			proofBytes, err := base64.StdEncoding.DecodeString(req.ProofBytes)
			if err != nil {
				http.Error(w, "invalid proofBytes encoding", http.StatusBadRequest)
				return
			}
			pubWitnessBytes, err := base64.StdEncoding.DecodeString(req.PublicWitnessBytes)
			if err != nil {
				http.Error(w, "invalid publicWitnessBytes encoding", http.StatusBadRequest)
				return
			}

			// Validate public inputs match poll registry root
			if len(req.PublicInputs) < 5 {
				http.Error(w, "publicInputs required for client-side proof", http.StatusBadRequest)
				return
			}
			if err := prover.ValidateVoteCastPublicInputs(
				req.PublicInputs, "", poll.RegistryRoot,
			); err != nil {
				http.Error(w, fmt.Sprintf("registry root mismatch: %v", err), http.StatusForbidden)
				return
			}

			// Verify the proof against the verifying key — no re-proving needed
			if err := prover.VerifyVoteCastProofBytes(p, proofBytes, pubWitnessBytes); err != nil {
				log.Printf("Client-side proof verification failed: %v", err)
				http.Error(w, fmt.Sprintf("ZK proof verification failed: %v", err), http.StatusForbidden)
				return
			}
		} else if len(req.Witness) > 0 {
			// Server-side re-proving path (fallback — server sees full witness)
			if wNull, ok := req.Witness["nullifier"]; ok && wNull != req.Nullifier {
				http.Error(w, "witness nullifier does not match request nullifier", http.StatusBadRequest)
				return
			}

			wRoot, ok := req.Witness["voterRegistryRoot"]
			if !ok {
				http.Error(w, "witness missing voterRegistryRoot", http.StatusBadRequest)
				return
			}
			if err := prover.ValidateVoteCastPublicInputs(
				[]string{req.Witness["pollId"], wRoot, req.Nullifier, req.VoteCommitment, req.Witness["maxChoices"]},
				req.Witness["pollId"], poll.RegistryRoot,
			); err != nil {
				http.Error(w, fmt.Sprintf("registry root mismatch: %v", err), http.StatusForbidden)
				return
			}

			if err := prover.VerifyVoteCastWitness(p, req.Witness); err != nil {
				log.Printf("Vote proof verification failed: %v", err)
				http.Error(w, fmt.Sprintf("ZK proof verification failed: %v", err), http.StatusForbidden)
				return
			}
		} else if len(req.PublicInputs) > 0 {
			// Proof + public inputs only — validate inputs match poll
			if err := prover.ValidateVoteCastPublicInputs(
				req.PublicInputs, "", poll.RegistryRoot,
			); err != nil {
				http.Error(w, fmt.Sprintf("public input validation failed: %v", err), http.StatusForbidden)
				return
			}
		}
	}

	proofStr := req.Proof
	if proofStr == "" && req.ProofBytes != "" {
		proofStr = "client-side:" + req.ProofBytes[:min(32, len(req.ProofBytes))] + "..."
	}
	vote := &store.VoteRecord{
		Nullifier:      req.Nullifier,
		VoteCommitment: req.VoteCommitment,
		Proof:          proofStr,
		Timestamp:      time.Now().UTC(),
	}

	if err := s.store.SaveVote(pollID, vote); err != nil {
		if strings.Contains(err.Error(), "nullifier already used") {
			http.Error(w, "Vote already cast (nullifier used)", http.StatusConflict)
			return
		}
		log.Printf("Failed to save vote: %v", err)
		http.Error(w, "Failed to record vote", http.StatusInternalServerError)
		return
	}

	// Append castVote event to the poll's event log — state derived via Petri net runtime.
	// When client-side proving was used, we don't have the choice (by design).
	// The choice will be recorded during the reveal phase.
	eventBindings := map[string]string{"nullifier": req.Nullifier}
	if choiceStr, ok := req.Witness["voteChoice"]; ok {
		eventBindings["choice"] = choiceStr
		eventBindings["weight"] = "1"
	}
	_ = s.store.AppendEvent(pollID, store.PollEvent{
		Action:   "castVote",
		Bindings: eventBindings,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

// handleClosePoll allows the poll creator to close it (requires wallet signature).
func (s *Server) handleClosePoll(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollID(r.URL.Path)
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	var req struct {
		Creator   string `json:"creator"`
		Signature string `json:"signature"`
	}
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

	if poll.Status != "active" {
		http.Error(w, "Poll is not active", http.StatusBadRequest)
		return
	}

	// Verify the closer is the creator
	if req.Creator == "" || req.Signature == "" {
		http.Error(w, "creator and signature required", http.StatusBadRequest)
		return
	}
	sigMsg := "bitwrap-close-poll:" + pollID
	if !VerifySignature(sigMsg, req.Signature, poll.Creator) {
		http.Error(w, "only the poll creator can close it", http.StatusForbidden)
		return
	}

	poll.Status = "closed"
	if err := s.store.SavePoll(poll); err != nil {
		http.Error(w, "Failed to close poll", http.StatusInternalServerError)
		return
	}

	// Append closePoll event to the Petri net event log
	_ = s.store.AppendEvent(pollID, store.PollEvent{Action: "closePoll"})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "closed"})
}

// handleRevealVote allows a voter to reveal their choice after the poll closes.
// Verifies mimcHash(voterSecret, voteChoice) == storedCommitment.
func (s *Server) handleRevealVote(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollID(r.URL.Path)
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	if poll.Status != "closed" {
		http.Error(w, "Poll must be closed before votes can be revealed", http.StatusBadRequest)
		return
	}

	var req revealVoteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Nullifier == "" || req.VoterSecret == "" {
		http.Error(w, "nullifier and voterSecret required", http.StatusBadRequest)
		return
	}
	if req.VoteChoice < 0 || req.VoteChoice > 255 {
		http.Error(w, "voteChoice must be 0-255", http.StatusBadRequest)
		return
	}

	// Find the vote record to get the stored commitment
	votes, err := s.store.ListVotes(pollID)
	if err != nil {
		http.Error(w, "Failed to read votes", http.StatusInternalServerError)
		return
	}

	var storedCommitment string
	for _, v := range votes {
		if v.Nullifier == req.Nullifier {
			if v.Revealed {
				http.Error(w, "Vote already revealed", http.StatusConflict)
				return
			}
			storedCommitment = v.VoteCommitment
			break
		}
	}
	if storedCommitment == "" {
		http.Error(w, "Vote not found for this nullifier", http.StatusNotFound)
		return
	}

	// Verify: mimcHash(voterSecret, voteChoice) == storedCommitment
	if err := prover.ValidateVoteReveal(req.VoterSecret, req.VoteChoice, storedCommitment); err != nil {
		http.Error(w, fmt.Sprintf("Reveal verification failed: %v", err), http.StatusForbidden)
		return
	}

	// Update the vote record
	if err := s.store.RevealVote(pollID, req.Nullifier, req.VoteChoice); err != nil {
		log.Printf("Failed to reveal vote: %v", err)
		http.Error(w, "Failed to record reveal", http.StatusInternalServerError)
		return
	}

	// Persist the (nullifier, choice, secret) bundle so the tally-proof
	// witness builder can later fold these reveals through the Petri net
	// `castVote` arc in ZK. This file is the only place the server keeps
	// per-vote secrets; it becomes safe to delete once the tally proof
	// has been generated and the poll is finalized.
	if err := s.store.SaveRevealBundle(pollID, store.RevealBundle{
		Nullifier: req.Nullifier,
		Choice:    req.VoteChoice,
		Secret:    req.VoterSecret,
	}); err != nil {
		log.Printf("SaveRevealBundle failed (non-fatal for reveal): %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "revealed",
		"choice": req.VoteChoice,
	})
}

// handlePollResults returns the current tally for a poll.
// During voting: only shows vote count and commitments (choices are secret).
// After close + reveal: shows per-choice tallies.
func (s *Server) handlePollResults(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "results")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	votes, _ := s.store.ListVotes(pollID)
	nullifiers := make([]string, len(votes))
	commitments := make([]string, len(votes))
	for i, v := range votes {
		nullifiers[i] = v.Nullifier
		commitments[i] = v.VoteCommitment
	}

	result := map[string]interface{}{
		"pollId":  pollID,
		"title":   poll.Title,
		"choices": poll.Choices,
		"status":  poll.Status,
	}

	// While active, only expose vote count — no tallies, nullifiers, or
	// commitments.  Revealing per-vote data while voting is open lets an
	// observer diff the tally after each vote and de-anonymize voters.
	if poll.Status == "active" {
		result["voteCount"] = len(votes)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	// Poll is closed — full results are safe to expose.
	result["voteCount"] = len(votes)
	result["nullifiers"] = nullifiers
	result["commitments"] = commitments

	// Derive tallies from the Petri net event log (event sourcing)
	events, _ := s.store.ReadEvents(pollID)
	if len(events) > 0 {
		pollEvents := make([]PollEvent, len(events))
		for i, e := range events {
			pollEvents[i] = PollEvent{Action: e.Action, Bindings: e.Bindings}
		}
		rt := PollRuntime(pollEvents)
		tallies := PollTallies(rt, len(poll.Choices))

		// Check if any votes have been tallied
		var tallied int64
		choiceTallies := make([]int64, len(tallies))
		for i, t := range tallies {
			choiceTallies[i] = t
			tallied += t
		}
		if tallied > 0 {
			result["tallies"] = choiceTallies
			result["talliedCount"] = tallied
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handlePollNullifiers returns the public nullifier list for audit.
func (s *Server) handlePollNullifiers(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "nullifiers")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	nullifiers, err := s.store.ListNullifiers(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pollId":     pollID,
		"nullifiers": nullifiers,
	})
}

// handleRegisterVoter registers a voter commitment for a poll's Merkle registry.
func (s *Server) handleRegisterVoter(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "register")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}
	if poll.Status != "active" {
		http.Error(w, "Poll is not active", http.StatusBadRequest)
		return
	}

	var req struct {
		Commitment string `json:"commitment"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.Commitment == "" {
		http.Error(w, "commitment required", http.StatusBadRequest)
		return
	}

	// Check for duplicate commitment
	for _, c := range poll.VoterCommitments {
		if c == req.Commitment {
			http.Error(w, "already registered", http.StatusConflict)
			return
		}
	}

	// Append commitment and recompute registry root
	poll.VoterCommitments = append(poll.VoterCommitments, req.Commitment)
	poll.RegistryRoot = computeRegistryRoot(poll.VoterCommitments)

	if err := s.store.SavePoll(poll); err != nil {
		http.Error(w, "Failed to save registration", http.StatusInternalServerError)
		return
	}

	// Record as a Petri net event so the runtime can gate castVote on
	// available registration slots (phase-1 exhaustion check).
	_ = s.store.AppendEvent(pollID, store.PollEvent{
		Action:   "registerVoter",
		Bindings: map[string]string{"commitment": req.Commitment},
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "registered",
		"root":   poll.RegistryRoot,
		"count":  len(poll.VoterCommitments),
	})
}

// handleGetRegistry returns the voter registry commitments and Merkle root.
func (s *Server) handleGetRegistry(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "registry")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}

	commitments := poll.VoterCommitments
	if commitments == nil {
		commitments = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"commitments": commitments,
		"root":        poll.RegistryRoot,
		"count":       len(commitments),
	})
}

// handleListPolls returns all polls.
func (s *Server) handleListPolls(w http.ResponseWriter, r *http.Request) {
	polls, err := s.store.ListPolls()
	if err != nil {
		http.Error(w, "Failed to list polls", http.StatusInternalServerError)
		return
	}
	if polls == nil {
		polls = []store.Poll{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"polls": polls})
}

// extractPollID extracts poll ID from /api/polls/{id} or /api/polls/{id}/vote
func extractPollID(path string) string {
	path = strings.TrimPrefix(path, "/api/polls/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}

// extractPollIDSegment extracts poll ID from /api/polls/{id}/{segment}
func extractPollIDSegment(path, segment string) string {
	path = strings.TrimPrefix(path, "/api/polls/")
	suffix := "/" + segment
	if !strings.HasSuffix(path, suffix) {
		return ""
	}
	return strings.TrimSuffix(path, suffix)
}

// handleSignRegistryRoot records a creator's EIP-191 signature over the
// current (pollId, root, count) tuple. Only the creator address can
// sign. The server appends to RegistryRootSigs; the count field must be
// strictly greater than any prior signature's count, so replaying an
// old signature after more voters register is rejected. Voters check
// that poll.RegistryRoot matches the latest signed root before casting.
func (s *Server) handleSignRegistryRoot(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "sign-registry-root")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	var req struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Signature == "" {
		http.Error(w, "signature required", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}
	if poll.Status != "active" {
		http.Error(w, "poll is not active", http.StatusBadRequest)
		return
	}
	if poll.RegistryRoot == "" || len(poll.VoterCommitments) == 0 {
		http.Error(w, "registry is empty", http.StatusBadRequest)
		return
	}

	count := len(poll.VoterCommitments)
	if n := len(poll.RegistryRootSigs); n > 0 {
		prev := poll.RegistryRootSigs[n-1]
		if count <= prev.Count {
			// Replay / downgrade attempt: refuse to persist an older or
			// equal-count signature. Counts must strictly increase so a
			// captured earlier signature can't be re-submitted after more
			// registrations.
			http.Error(w, "registry count must exceed prior signed count", http.StatusConflict)
			return
		}
		if prev.Root == poll.RegistryRoot {
			// Idempotent: already signed at this exact state. Accept
			// without appending a duplicate.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"status": "already-signed", "count": prev.Count})
			return
		}
	}

	msg := fmt.Sprintf("bitwrap-registry-root:%s:%s:%d", pollID, poll.RegistryRoot, count)
	if !VerifySignature(msg, req.Signature, poll.Creator) {
		http.Error(w, "signature does not match poll creator", http.StatusForbidden)
		return
	}

	poll.RegistryRootSigs = append(poll.RegistryRootSigs, store.RegistryRootSig{
		Root:      poll.RegistryRoot,
		Count:     count,
		Signature: req.Signature,
		SignedAt:  time.Now().UTC(),
	})
	if err := s.store.SavePoll(poll); err != nil {
		http.Error(w, "failed to persist signature", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "signed",
		"root":   poll.RegistryRoot,
		"count":  count,
	})
}

// handleGenerateTallyProof runs the ZK prover over the poll's reveal
// bundles and persists a TallyProofCircuit proof. Anyone may request
// generation — the witness data is already persisted during the reveal
// phase, and the resulting artifact is public and independently
// verifiable against the tallyProof verifying key.
func (s *Server) handleGenerateTallyProof(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "tally-proof")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}
	if s.proverSvc == nil {
		http.Error(w, "prover not configured", http.StatusServiceUnavailable)
		return
	}

	poll, err := s.store.ReadPoll(pollID)
	if err != nil {
		http.Error(w, "Poll not found", http.StatusNotFound)
		return
	}
	if poll.Status != "closed" {
		http.Error(w, "Tally proof can only be generated after the poll is closed", http.StatusBadRequest)
		return
	}

	artifact, err := GenerateTallyProof(s.store, s.proverSvc.Prover(), pollID)
	if err != nil {
		log.Printf("GenerateTallyProof(%s): %v", pollID, err)
		http.Error(w, fmt.Sprintf("tally proof failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(artifact)
}

// handleGetTallyProof returns the cached tally proof artifact so any
// client can independently verify it against the tallyProof verifying
// key (served from /api/vk/tallyProof).
func (s *Server) handleGetTallyProof(w http.ResponseWriter, r *http.Request) {
	pollID := extractPollIDSegment(r.URL.Path, "tally-proof")
	if pollID == "" {
		http.Error(w, "Poll ID required", http.StatusBadRequest)
		return
	}

	artifact, err := s.store.ReadTallyProof(pollID)
	if err != nil {
		http.Error(w, "no tally proof generated yet", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(artifact)
}
