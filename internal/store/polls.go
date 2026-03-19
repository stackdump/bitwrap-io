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
}

// VoteRecord stores a verified vote submission.
type VoteRecord struct {
	Nullifier      string    `json:"nullifier"`
	VoteCommitment string    `json:"voteCommitment"`       // mimcHash(voterSecret, voteChoice) — blinded, can't reverse
	Proof          string    `json:"proof"`
	Timestamp      time.Time `json:"timestamp"`
	// RevealedChoice is set after the voter reveals their choice post-close
	RevealedChoice int       `json:"revealedChoice,omitempty"`
	Revealed       bool      `json:"revealed,omitempty"`
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

// RevealVote updates a vote record with the revealed choice.
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

	vote.RevealedChoice = choice
	vote.Revealed = true

	out, err := json.MarshalIndent(vote, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(votePath, out, 0o644)
}

// TallyRevealed counts revealed votes by choice.
func (s *FSStore) TallyRevealed(pollID string) (map[int]int, int, error) {
	votes, err := s.ListVotes(pollID)
	if err != nil {
		return nil, 0, err
	}

	tally := make(map[int]int)
	revealed := 0
	for _, v := range votes {
		if v.Revealed {
			tally[v.RevealedChoice]++
			revealed++
		}
	}
	return tally, revealed, nil
}

func isJSONFile(name string) bool {
	return len(name) > 5 && name[len(name)-5:] == ".json"
}
