package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackdump/bitwrap-io/internal/store"
)

// createTestPoll creates a poll via the store directly (bypasses wallet auth).
func createTestPoll(t *testing.T, srv *Server, title string, choices []string) string {
	t.Helper()
	poll := &store.Poll{
		ID:        fmt.Sprintf("test%d", time.Now().UnixNano()),
		Title:     title,
		Choices:   choices,
		Creator:   "0x0000000000000000000000000000000000000001",
		CreatedAt: time.Now().UTC(),
		Status:    "active",
	}
	if err := srv.store.SavePoll(poll); err != nil {
		t.Fatal(err)
	}
	_ = srv.store.AppendEvent(poll.ID, store.PollEvent{Action: "createPoll"})
	return poll.ID
}

// --- Create poll validation tests ---

func TestCreatePollMissingSignature(t *testing.T) {
	srv := testServer(t)
	body := `{"title":"Test","choices":["A","B"],"creator":"0x0000000000000000000000000000000000000001"}`
	req := httptest.NewRequest("POST", "/api/polls", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing signature, got %d", w.Code)
	}
}

func TestCreatePollMissingCreator(t *testing.T) {
	srv := testServer(t)
	body := `{"title":"Test","choices":["A","B"],"signature":"0xdeadbeef"}`
	req := httptest.NewRequest("POST", "/api/polls", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing creator, got %d", w.Code)
	}
}

func TestCreatePollInvalidAddress(t *testing.T) {
	srv := testServer(t)
	body := `{"title":"Test","choices":["A","B"],"creator":"not-an-address","signature":"0xdeadbeef"}`
	req := httptest.NewRequest("POST", "/api/polls", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid address, got %d", w.Code)
	}
}

// --- Get poll tests ---

func TestGetPoll(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Get Test", []string{"A", "B"})

	req := httptest.NewRequest("GET", "/api/polls/"+pollID, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/polls/%s = %d", pollID, w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	poll := resp["poll"].(map[string]interface{})
	if poll["title"] != "Get Test" {
		t.Fatalf("expected title 'Get Test', got %v", poll["title"])
	}
}

func TestGetPollNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/polls/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetPollAutoClose(t *testing.T) {
	srv := testServer(t)
	poll := &store.Poll{
		ID:        "expired-poll",
		Title:     "Expired",
		Choices:   []string{"A", "B"},
		Creator:   "0x0000000000000000000000000000000000000001",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour), // expired 1h ago
		Status:    "active",
	}
	srv.store.SavePoll(poll)

	req := httptest.NewRequest("GET", "/api/polls/expired-poll", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET = %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	p := resp["poll"].(map[string]interface{})
	if p["status"] != "closed" {
		t.Fatalf("expired poll should auto-close, got status=%v", p["status"])
	}
}

// --- List polls tests ---

func TestListPolls(t *testing.T) {
	srv := testServer(t)
	createTestPoll(t, srv, "Poll 1", []string{"A", "B"})
	createTestPoll(t, srv, "Poll 2", []string{"X", "Y", "Z"})

	req := httptest.NewRequest("GET", "/api/polls", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /api/polls = %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	polls := resp["polls"].([]interface{})
	if len(polls) < 2 {
		t.Fatalf("expected at least 2 polls, got %d", len(polls))
	}
}

// --- Vote tests ---

func TestCastVote(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Vote Test", []string{"Yes", "No"})

	body := `{
		"nullifier": "0xabc123",
		"voteCommitment": "0xdef456",
		"proof": "dummy-proof-data"
	}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST vote = %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "accepted" {
		t.Fatalf("expected status=accepted, got %v", resp["status"])
	}
}

func TestCastVoteDuplicateNullifier(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Dup Test", []string{"A", "B"})

	body := `{"nullifier":"0xsame","voteCommitment":"0xc1","proof":"p"}`

	// First vote
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("first vote = %d", w.Code)
	}

	// Duplicate
	req = httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409 for duplicate nullifier, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCastVoteMissingNullifier(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Missing Null", []string{"A", "B"})

	body := `{"voteCommitment":"0xc1","proof":"p"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCastVoteMissingProof(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "No Proof", []string{"A", "B"})

	body := `{"nullifier":"0x1","voteCommitment":"0xc"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing proof, got %d", w.Code)
	}
}

func TestCastVoteOnClosedPoll(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Closed", []string{"A", "B"})

	// Close the poll directly
	poll, _ := srv.store.ReadPoll(pollID)
	poll.Status = "closed"
	srv.store.SavePoll(poll)

	body := `{"nullifier":"0x1","voteCommitment":"0xc","proof":"p"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for closed poll, got %d", w.Code)
	}
}

func TestCastVoteOnExpiredPoll(t *testing.T) {
	srv := testServer(t)
	poll := &store.Poll{
		ID:        "vote-expired",
		Title:     "Expired Vote",
		Choices:   []string{"A", "B"},
		Creator:   "0x0000000000000000000000000000000000000001",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		Status:    "active",
	}
	srv.store.SavePoll(poll)

	body := `{"nullifier":"0x1","voteCommitment":"0xc","proof":"p"}`
	req := httptest.NewRequest("POST", "/api/polls/vote-expired/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for expired poll, got %d", w.Code)
	}
}

func TestCastVoteNotFound(t *testing.T) {
	srv := testServer(t)
	body := `{"nullifier":"0x1","voteCommitment":"0xc","proof":"p"}`
	req := httptest.NewRequest("POST", "/api/polls/nonexistent/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Results tests ---

func TestResultsSealedWhileActive(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Sealed", []string{"A", "B", "C"})

	// Cast a vote
	body := `{"nullifier":"0xn1","voteCommitment":"0xc1","proof":"p"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("vote failed: %d", w.Code)
	}

	// Check results while active — should not contain tallies or nullifiers
	req = httptest.NewRequest("GET", "/api/polls/"+pollID+"/results", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET results = %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "active" {
		t.Fatalf("expected status=active, got %v", resp["status"])
	}
	if resp["tallies"] != nil {
		t.Fatal("tallies should be hidden while poll is active")
	}
	if resp["nullifiers"] != nil {
		t.Fatal("nullifiers should be hidden while poll is active")
	}
	if resp["commitments"] != nil {
		t.Fatal("commitments should be hidden while poll is active")
	}
	// Vote count should still be visible
	voteCount := int(resp["voteCount"].(float64))
	if voteCount != 1 {
		t.Fatalf("expected voteCount=1, got %d", voteCount)
	}
}

func TestResultsVisibleWhenClosed(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Visible", []string{"X", "Y"})

	// Cast two votes
	for i, null := range []string{"0xn1", "0xn2"} {
		body := fmt.Sprintf(`{"nullifier":%q,"voteCommitment":"0xc%d","proof":"p"}`, null, i)
		req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("vote %d failed: %d", i, w.Code)
		}
	}

	// Close the poll
	poll, _ := srv.store.ReadPoll(pollID)
	poll.Status = "closed"
	srv.store.SavePoll(poll)

	// Check results — nullifiers and commitments should now be visible
	req := httptest.NewRequest("GET", "/api/polls/"+pollID+"/results", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET results = %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "closed" {
		t.Fatalf("expected status=closed, got %v", resp["status"])
	}
	if resp["nullifiers"] == nil {
		t.Fatal("nullifiers should be visible when poll is closed")
	}
	nulls := resp["nullifiers"].([]interface{})
	if len(nulls) != 2 {
		t.Fatalf("expected 2 nullifiers, got %d", len(nulls))
	}
	if resp["commitments"] == nil {
		t.Fatal("commitments should be visible when poll is closed")
	}
	voteCount := int(resp["voteCount"].(float64))
	if voteCount != 2 {
		t.Fatalf("expected voteCount=2, got %d", voteCount)
	}
}

func TestResultsNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/api/polls/nonexistent/results", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Multi-vote count accuracy ---

func TestVoteCountAccuracy(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Count Test", []string{"A", "B"})

	// Cast 5 votes
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"nullifier":"0xnull%d","voteCommitment":"0xc%d","proof":"p"}`, i, i)
		req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("vote %d = %d", i, w.Code)
		}
	}

	// Results should show count=5 even while active
	req := httptest.NewRequest("GET", "/api/polls/"+pollID+"/results", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["voteCount"].(float64)) != 5 {
		t.Fatalf("expected voteCount=5, got %v", resp["voteCount"])
	}
	// But no tallies
	if resp["tallies"] != nil {
		t.Fatal("tallies should be hidden while active")
	}
}

// --- Voter registration tests ---

func TestRegisterVoter(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Reg Test", []string{"A", "B"})

	body := `{"commitment":"12345678901234567890"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST register = %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "registered" {
		t.Fatalf("expected status=registered, got %v", resp["status"])
	}
	if int(resp["count"].(float64)) != 1 {
		t.Fatalf("expected count=1, got %v", resp["count"])
	}
	if resp["root"] == nil || resp["root"] == "" {
		t.Fatal("expected non-empty registry root")
	}
}

func TestRegisterVoterDuplicate(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Dup Reg", []string{"A", "B"})

	body := `{"commitment":"99999"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("first register = %d", w.Code)
	}

	// Duplicate
	req = httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409 for duplicate, got %d", w.Code)
	}
}

func TestGetRegistry(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Reg Query", []string{"A", "B"})

	// Register two voters
	for _, c := range []string{"111", "222"} {
		body := fmt.Sprintf(`{"commitment":%q}`, c)
		req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("register = %d", w.Code)
		}
	}

	// Query registry
	req := httptest.NewRequest("GET", "/api/polls/"+pollID+"/registry", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET registry = %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	commitments := resp["commitments"].([]interface{})
	if len(commitments) != 2 {
		t.Fatalf("expected 2 commitments, got %d", len(commitments))
	}
	if resp["root"] == nil || resp["root"] == "" {
		t.Fatal("expected non-empty root")
	}
	if int(resp["count"].(float64)) != 2 {
		t.Fatalf("expected count=2, got %v", resp["count"])
	}
}

func TestRegistryRootConsistency(t *testing.T) {
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "Root Test", []string{"A", "B"})

	// Register a voter
	body := `{"commitment":"42"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var regResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &regResp)
	rootAfterReg := regResp["root"].(string)

	// Query registry — root should match
	req = httptest.NewRequest("GET", "/api/polls/"+pollID+"/registry", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var queryResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &queryResp)
	if queryResp["root"].(string) != rootAfterReg {
		t.Fatalf("registry root mismatch: register=%s query=%s", rootAfterReg, queryResp["root"])
	}
}
