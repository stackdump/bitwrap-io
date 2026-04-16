package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Poll represents a ZK poll configuration.
type Poll struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Choices     []string  `json:"choices"`
	Creator     string    `json:"creator"`          // Ethereum address of poll creator
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	Status      string    `json:"status"` // "active", "closed"

	// Voter registry: commitments for Merkle tree construction
	VoterCommitments []string `json:"voterCommitments"`
	RegistryRoot     string   `json:"registryRoot,omitempty"`

	// VoteSchemaVersion selects the secret-derivation protocol.
	// 1 = legacy: voterSecret = BigInt(sig.slice(2, 64)), fully
	//     reconstructable from the wallet signature — coercion-exposed.
	// 2 = nonce-augmented: voterSecret = mimcHash(sigDerived, voterNonce)
	//     where voterNonce is a per-voter random field element the voter
	//     alone possesses (localStorage + auto-downloaded backup). A
	//     coerced wallet signature no longer deanonymizes the voter.
	// Polls stored before this field existed unmarshal as 0; the server
	// treats 0 and 1 identically (both are legacy). New polls created
	// via handleCreatePoll are stamped with 2.
	VoteSchemaVersion int `json:"voteSchemaVersion,omitempty"`

	// RegistryRootSigs is an append-only log of creator signatures over
	// registry-root transitions. Each entry binds (root, count) so a voter
	// can verify — before casting — that the root the server returned has
	// actually been acknowledged by the creator. Without this, the server
	// can silently inject a shadow voter (commitment in registry but not
	// in the signed set) and accept a vote from it.
	//
	// Semantics:
	//   - handleRegisterVoter appends to VoterCommitments WITHOUT signing;
	//     creator signs in batches via POST .../sign-registry-root.
	//   - handleCastVote rejects unless the current RegistryRoot matches
	//     the Root in the most recent RegistryRootSigs entry.
	//   - Each signature commits to (pollId, root, count); replaying an
	//     old sig with a lower count is caught by the count field.
	RegistryRootSigs []RegistryRootSig `json:"registryRootSigs,omitempty"`
}

// RegistryRootSig is one entry in the creator's signed registry log.
type RegistryRootSig struct {
	Root      string    `json:"root"`
	Count     int       `json:"count"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signedAt"`
}

// VoteRecord stores a verified vote submission.
// Note: individual vote choices are NEVER stored — only the blinded commitment.
// Tallying is done via aggregate counters that can't be linked back to individual voters.
type VoteRecord struct {
	Nullifier      string    `json:"nullifier"`
	VoteCommitment string    `json:"voteCommitment"` // mimcHash(voterSecret, voteChoice) — blinded, can't reverse
	Proof          string    `json:"proof"`
	Timestamp      time.Time `json:"timestamp"`
	Revealed       bool      `json:"revealed,omitempty"` // true after voter revealed (choice NOT stored here)
}

// PollResults holds tallied results for a poll.
type PollResults struct {
	PollID     string         `json:"pollId"`
	VoteCount  int            `json:"voteCount"`
	Nullifiers []string       `json:"nullifiers"`
	Status     string         `json:"status"`
}

// pollDir returns the base directory for polls.
func (s *FSStore) pollDir() string {
	return filepath.Join(s.base, "polls")
}

// pollPath returns the path for a specific poll config.
func (s *FSStore) pollPath(pollID string) (string, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return "", fmt.Errorf("invalid poll ID: %w", err)
	}
	return filepath.Join(s.pollDir(), clean+".json"), nil
}

// votesDir returns the directory for a poll's votes.
func (s *FSStore) votesDir(pollID string) (string, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return "", fmt.Errorf("invalid poll ID: %w", err)
	}
	return filepath.Join(s.pollDir(), clean, "votes"), nil
}

// SavePoll persists a poll configuration.
func (s *FSStore) SavePoll(poll *Poll) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.pollDir(), 0o755); err != nil {
		return err
	}

	path, err := s.pollPath(poll.ID)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(poll, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

// ReadPoll loads a poll by ID.
func (s *FSStore) ReadPoll(pollID string) (*Poll, error) {
	path, err := s.pollPath(pollID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var poll Poll
	if err := json.Unmarshal(data, &poll); err != nil {
		return nil, err
	}
	return &poll, nil
}

// SaveVote stores a verified vote for a poll. Returns error if nullifier already used.
func (s *FSStore) SaveVote(pollID string, vote *VoteRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.votesDir(pollID)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	cleanNull, err := sanitizePathComponent(vote.Nullifier)
	if err != nil {
		return fmt.Errorf("invalid nullifier: %w", err)
	}

	votePath := filepath.Join(dir, cleanNull+".json")

	// Check for double-vote
	if _, err := os.Stat(votePath); err == nil {
		return fmt.Errorf("nullifier already used")
	}

	data, err := json.MarshalIndent(vote, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(votePath, data, 0o644)
}

// ListVotes returns all vote records for a poll.
func (s *FSStore) ListVotes(pollID string) ([]VoteRecord, error) {
	dir, err := s.votesDir(pollID)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var votes []VoteRecord
	for _, entry := range entries {
		if entry.IsDir() || !isJSONFile(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var vote VoteRecord
		if err := json.Unmarshal(data, &vote); err != nil {
			continue
		}
		votes = append(votes, vote)
	}

	sort.Slice(votes, func(i, j int) bool {
		return votes[i].Timestamp.Before(votes[j].Timestamp)
	})

	return votes, nil
}

// ListNullifiers returns all used nullifiers for a poll.
func (s *FSStore) ListNullifiers(pollID string) ([]string, error) {
	votes, err := s.ListVotes(pollID)
	if err != nil {
		return nil, err
	}
	nullifiers := make([]string, len(votes))
	for i, v := range votes {
		nullifiers[i] = v.Nullifier
	}
	return nullifiers, nil
}

// ListPolls returns all polls, newest first.
func (s *FSStore) ListPolls() ([]Poll, error) {
	entries, err := os.ReadDir(s.pollDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var polls []Poll
	for _, entry := range entries {
		if entry.IsDir() || !isJSONFile(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.pollDir(), entry.Name()))
		if err != nil {
			continue
		}
		var poll Poll
		if err := json.Unmarshal(data, &poll); err != nil {
			continue
		}
		polls = append(polls, poll)
	}

	sort.Slice(polls, func(i, j int) bool {
		return polls[i].CreatedAt.After(polls[j].CreatedAt)
	})

	return polls, nil
}

// RevealVote marks a vote as revealed and increments the aggregate tally.
// The choice is verified against the commitment but NEVER stored per-vote —
// only the aggregate counter is updated, preserving individual ballot secrecy.
func (s *FSStore) RevealVote(pollID string, nullifier string, choice int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir, err := s.votesDir(pollID)
	if err != nil {
		return err
	}

	cleanNull, err := sanitizePathComponent(nullifier)
	if err != nil {
		return fmt.Errorf("invalid nullifier: %w", err)
	}

	// Mark vote as revealed (without recording which choice)
	votePath := filepath.Join(dir, cleanNull+".json")
	data, err := os.ReadFile(votePath)
	if err != nil {
		return fmt.Errorf("vote not found")
	}

	var vote VoteRecord
	if err := json.Unmarshal(data, &vote); err != nil {
		return err
	}

	if vote.Revealed {
		return fmt.Errorf("vote already revealed")
	}

	vote.Revealed = true
	out, err := json.MarshalIndent(vote, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(votePath, out, 0o644); err != nil {
		return err
	}

	// Increment aggregate tally — choice is only recorded here as a count
	return s.incrementTally(pollID, choice)
}

// AggregateTally holds per-choice vote counts with no link to individual voters.
type AggregateTally struct {
	Counts        map[string]int `json:"counts"`        // choice index (as string) → count
	RevealedTotal int            `json:"revealedTotal"`
}

func (s *FSStore) tallyPath(pollID string) (string, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.pollDir(), clean, "tally.json"), nil
}

// IncrementTally adds one vote to the aggregate tally for a choice.
// The tally file only contains totals — no link to individual voters.
func (s *FSStore) IncrementTally(pollID string, choice int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incrementTally(pollID, choice)
}

func (s *FSStore) incrementTally(pollID string, choice int) error {
	path, err := s.tallyPath(pollID)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var tally AggregateTally
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &tally)
	}
	if tally.Counts == nil {
		tally.Counts = make(map[string]int)
	}

	key := fmt.Sprintf("%d", choice)
	tally.Counts[key]++
	tally.RevealedTotal++

	out, err := json.MarshalIndent(tally, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// ReadTally returns the aggregate tally for a poll.
func (s *FSStore) ReadTally(pollID string) (*AggregateTally, error) {
	path, err := s.tallyPath(pollID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AggregateTally{Counts: make(map[string]int)}, nil
		}
		return nil, err
	}

	var tally AggregateTally
	if err := json.Unmarshal(data, &tally); err != nil {
		return nil, err
	}
	return &tally, nil
}

// PollEvent represents a single action fired on a poll's state machine.
type PollEvent struct {
	Action   string            `json:"action"`
	Bindings map[string]string `json:"bindings,omitempty"`
}

// RevealBundle records the private data a voter surrendered during the
// reveal phase, kept so the server can later build the tally-proof
// witness. This is the ONLY place on the server where per-vote secrets
// are persisted. Once a tally proof has been generated and the poll is
// finalized, these bundles can be purged (PurgeReveals) — the proof
// stands on its own.
type RevealBundle struct {
	Nullifier string `json:"nullifier"`
	Choice    int    `json:"choice"`
	Secret    string `json:"secret"` // voterSecret as decimal/hex big int
}

// SaveRevealBundle appends a reveal bundle to the poll's reveals.json.
// Appended, not indexed by nullifier, so we keep insertion order for
// deterministic witness builds.
func (s *FSStore) SaveRevealBundle(pollID string, bundle RevealBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.pollDir(), clean)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	path := filepath.Join(dir, "reveals.json")
	var bundles []RevealBundle
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &bundles)
	}
	// Idempotence: skip if this nullifier is already recorded. A buggy
	// client retrying reveals shouldn't inflate the witness.
	for _, b := range bundles {
		if b.Nullifier == bundle.Nullifier {
			return nil
		}
	}
	bundles = append(bundles, bundle)

	out, err := json.MarshalIndent(bundles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// ListRevealBundles returns all reveal bundles for a poll in insertion
// order. Returns an empty slice if no reveals have been recorded.
func (s *FSStore) ListRevealBundles(pollID string) ([]RevealBundle, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(s.pollDir(), clean, "reveals.json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var bundles []RevealBundle
	if err := json.Unmarshal(data, &bundles); err != nil {
		return nil, err
	}
	return bundles, nil
}

// TallyProofArtifact is what we persist to tallyproof.json after a
// successful prove — everything a verifier needs to independently check
// the proof against the circuit's verifying key.
type TallyProofArtifact struct {
	PollID             string    `json:"pollId"`
	GeneratedAt        time.Time `json:"generatedAt"`
	CircuitName        string    `json:"circuitName"`
	ProofBytes         string    `json:"proofBytes"`         // base64 gnark proof
	PublicWitnessBytes string    `json:"publicWitnessBytes"` // base64 gnark public witness — consumed by in-browser Verify
	PublicInputs       []string  `json:"publicInputs"`       // hex-encoded public witness, circuit order (human-readable)
	Tallies            []int64   `json:"tallies"`            // the claimed tally vector (also in PublicInputs)
	NumReveals         int       `json:"numReveals"`
}

// SaveTallyProof persists a generated tally proof artifact.
func (s *FSStore) SaveTallyProof(pollID string, artifact *TallyProofArtifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.pollDir(), clean)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "tallyproof.json")

	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadTallyProof returns the cached tally proof, or os.ErrNotExist if
// none has been generated yet.
func (s *FSStore) ReadTallyProof(pollID string) (*TallyProofArtifact, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(s.pollDir(), clean, "tallyproof.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var artifact TallyProofArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, err
	}
	return &artifact, nil
}

// AppendEvent appends an event to a poll's event log.
func (s *FSStore) AppendEvent(pollID string, event PollEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.pollDir(), clean)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	eventsPath := filepath.Join(dir, "events.json")

	var events []PollEvent
	if data, err := os.ReadFile(eventsPath); err == nil {
		_ = json.Unmarshal(data, &events)
	}

	events = append(events, event)

	out, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(eventsPath, out, 0o644)
}

// ReadEvents returns all events for a poll.
func (s *FSStore) ReadEvents(pollID string) ([]PollEvent, error) {
	clean, err := sanitizePathComponent(pollID)
	if err != nil {
		return nil, err
	}
	eventsPath := filepath.Join(s.pollDir(), clean, "events.json")

	data, err := os.ReadFile(eventsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var events []PollEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func isJSONFile(name string) bool {
	return len(name) > 5 && name[len(name)-5:] == ".json"
}
