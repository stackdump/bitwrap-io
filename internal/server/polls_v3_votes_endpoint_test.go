package server

import (
	"encoding/json"
	"testing"

	"github.com/stackdump/bitwrap-io/internal/store"
)

// TestGetPollVotesV2Shape — v1/v2 audit shape: {nullifier, voteCommitment, timestamp}.
func TestGetPollVotesV2Shape(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "votes shape v2", []string{"a", "b"})

	// Drop a fake vote with a commitment.
	_ = srv.store.SaveVote(pollID, &store.VoteRecord{
		Nullifier:      "0x1111",
		VoteCommitment: "0xaaaa",
	})

	w := getReq(t, srv, "/api/polls/"+pollID+"/votes")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}
	var got struct {
		PollID string `json:"pollId"`
		Votes  []map[string]any `json:"votes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Votes) != 1 {
		t.Fatalf("expected 1 vote, got %d", len(got.Votes))
	}
	v := got.Votes[0]
	if v["nullifier"] != "0x1111" {
		t.Errorf("nullifier: got %v", v["nullifier"])
	}
	if v["voteCommitment"] != "0xaaaa" {
		t.Errorf("voteCommitment: got %v", v["voteCommitment"])
	}
	if _, leaked := v["ciphertexts"]; leaked {
		t.Errorf("v2 vote leaked ciphertexts field")
	}
}

// TestGetPollVotesV3Shape — v3 audit shape: {nullifier, ciphertexts, timestamp},
// no voteCommitment field.
func TestGetPollVotesV3Shape(t *testing.T) {
	srv := testServer(t)
	pollID, _, _ := seedV3Poll(t, srv)

	cts := []store.HomomorphicCiphertext{}
	for i := 0; i < 8; i++ {
		cts = append(cts, store.HomomorphicCiphertext{
			A: "aabbccdd",
			B: "eeff0011",
		})
	}
	_ = srv.store.SaveVote(pollID, &store.VoteRecord{
		Nullifier:   "0x2222",
		Ciphertexts: cts,
	})

	w := getReq(t, srv, "/api/polls/"+pollID+"/votes")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}
	var got struct {
		PollID            string           `json:"pollId"`
		VoteSchemaVersion int              `json:"voteSchemaVersion"`
		Votes             []map[string]any `json:"votes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.VoteSchemaVersion != 3 {
		t.Errorf("voteSchemaVersion: got %d, want 3", got.VoteSchemaVersion)
	}
	if len(got.Votes) != 1 {
		t.Fatalf("expected 1 vote, got %d", len(got.Votes))
	}
	v := got.Votes[0]
	if v["nullifier"] != "0x2222" {
		t.Errorf("nullifier: got %v", v["nullifier"])
	}
	cipherArr, ok := v["ciphertexts"].([]any)
	if !ok {
		t.Fatalf("ciphertexts missing or wrong type: %T", v["ciphertexts"])
	}
	if len(cipherArr) != 8 {
		t.Errorf("ciphertexts length: got %d, want 8", len(cipherArr))
	}
	if _, leaked := v["voteCommitment"]; leaked {
		t.Errorf("v3 vote leaked voteCommitment field")
	}
}

// TestGetPollVotesNotFound — unknown poll returns 404.
func TestGetPollVotesNotFound(t *testing.T) {
	srv := testServer(t)
	w := getReq(t, srv, "/api/polls/nonexistent/votes")
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestGetPollVotesEmpty — a poll with no votes returns an empty list, not 404.
func TestGetPollVotesEmpty(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "empty", []string{"a", "b"})

	w := getReq(t, srv, "/api/polls/"+pollID+"/votes")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var got struct {
		Votes []map[string]any `json:"votes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Votes) != 0 {
		t.Errorf("expected empty votes, got %d", len(got.Votes))
	}
}
