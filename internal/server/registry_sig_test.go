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

// testCreatorDevSign signs (message) with anvil account 0 and returns
// (signature, address). Mirrors what a voter's wallet would do; used to
// avoid plumbing a real wallet into the test suite.
func testCreatorDevSign(t *testing.T, message string) (string, string) {
	t.Helper()
	sig, addr := devSign(message)
	if sig == "" || addr == "" {
		t.Fatalf("devSign returned empty for message %q", message)
	}
	return sig, strings.ToLower(addr)
}

// seedPollWithCreator creates a poll owned by a known dev-signed creator
// so we can exercise the sign-registry-root flow against real signatures.
func seedPollWithCreator(t *testing.T, srv *Server, title string) (string, string) {
	t.Helper()
	_, creator := testCreatorDevSign(t, "seed:"+title)

	poll := &store.Poll{
		ID:        fmt.Sprintf("regsigtest-%d", time.Now().UnixNano()),
		Title:     title,
		Choices:   []string{"A", "B"},
		Creator:   creator,
		CreatedAt: time.Now().UTC(),
		Status:    "active",
	}
	if err := srv.store.SavePoll(poll); err != nil {
		t.Fatal(err)
	}
	_ = srv.store.AppendEvent(poll.ID, store.PollEvent{Action: "createPoll"})
	return poll.ID, creator
}

// registerTestCommitment pushes a commitment through handleRegisterVoter
// so we hit the real commitment-appending path rather than forging poll state.
func registerTestCommitment(t *testing.T, srv *Server, pollID, commitment string) {
	t.Helper()
	body := fmt.Sprintf(`{"commitment":"%s"}`, commitment)
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/register", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("register %s: %d %s", commitment, w.Code, w.Body.String())
	}
}

func TestSignRegistryRootHappyPath(t *testing.T) {
	srv := testServer(t)
	pollID, creator := seedPollWithCreator(t, srv,"sign-happy")
	registerTestCommitment(t, srv, pollID, "0x1111")

	poll, _ := srv.store.ReadPoll(pollID)
	msg := fmt.Sprintf("bitwrap-registry-root:%s:%s:%d", pollID, poll.RegistryRoot, len(poll.VoterCommitments))
	sig, gotAddr := devSign(msg)
	if strings.ToLower(gotAddr) != creator {
		t.Fatalf("devSign returned %s, expected creator %s", gotAddr, creator)
	}

	body := fmt.Sprintf(`{"signature":"%s"}`, sig)
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/sign-registry-root", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("sign root: %d %s", w.Code, w.Body.String())
	}

	updated, _ := srv.store.ReadPoll(pollID)
	if n := len(updated.RegistryRootSigs); n != 1 {
		t.Fatalf("expected 1 signature recorded, got %d", n)
	}
	if updated.RegistryRootSigs[0].Count != 1 {
		t.Fatalf("expected count=1, got %d", updated.RegistryRootSigs[0].Count)
	}
}

func TestSignRegistryRootRejectsForgedSignature(t *testing.T) {
	srv := testServer(t)
	pollID, _ := seedPollWithCreator(t, srv,"sign-forged")
	registerTestCommitment(t, srv, pollID, "0x2222")

	// Sign with a different dev account than the poll creator — VerifySignature should reject.
	poll, _ := srv.store.ReadPoll(pollID)
	msg := fmt.Sprintf("bitwrap-registry-root:%s:%s:%d", pollID, poll.RegistryRoot, len(poll.VoterCommitments))
	wrongSig, _ := devSignWithKey(msg, devKeys[3])

	body := fmt.Sprintf(`{"signature":"%s"}`, wrongSig)
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/sign-registry-root", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("expected 403 for non-creator signer, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignRegistryRootRejectsReplay(t *testing.T) {
	srv := testServer(t)
	pollID, _ := seedPollWithCreator(t, srv,"sign-replay")

	// Register + sign at count=1.
	registerTestCommitment(t, srv, pollID, "0xa001")
	poll, _ := srv.store.ReadPoll(pollID)
	rootAt1 := poll.RegistryRoot
	msg1 := fmt.Sprintf("bitwrap-registry-root:%s:%s:%d", pollID, rootAt1, 1)
	sig1, _ := devSign(msg1)
	body1 := fmt.Sprintf(`{"signature":"%s"}`, sig1)
	req1 := httptest.NewRequest("POST", "/api/polls/"+pollID+"/sign-registry-root", strings.NewReader(body1))
	w1 := httptest.NewRecorder()
	srv.ServeHTTP(w1, req1)
	if w1.Code != 200 {
		t.Fatalf("first sign: %d %s", w1.Code, w1.Body.String())
	}

	// Register a second voter — count moves to 2, root changes.
	registerTestCommitment(t, srv, pollID, "0xa002")

	// Replay the count=1 signature. The server must reject because
	// count in the sig no longer matches current state and count<=prev.
	req2 := httptest.NewRequest("POST", "/api/polls/"+pollID+"/sign-registry-root", strings.NewReader(body1))
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code == 200 {
		t.Errorf("replay attack accepted (code=200); expected 403 or 409. Body: %s", w2.Body.String())
	}
}

func TestCastVoteRejectsUnsignedRegistryUpdate(t *testing.T) {
	srv := testServer(t)
	pollID, _ := seedPollWithCreator(t, srv,"cast-unsigned")

	// Register two voters. Sign after first, then register a second without re-signing.
	registerTestCommitment(t, srv, pollID, "0xb001")
	poll, _ := srv.store.ReadPoll(pollID)
	msg := fmt.Sprintf("bitwrap-registry-root:%s:%s:%d", pollID, poll.RegistryRoot, 1)
	sig, _ := devSign(msg)
	body := fmt.Sprintf(`{"signature":"%s"}`, sig)
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/sign-registry-root", strings.NewReader(body))
	srv.ServeHTTP(httptest.NewRecorder(), req)

	registerTestCommitment(t, srv, pollID, "0xb002")

	// Attempt to cast a vote now. Registry root has moved past signed root.
	voteBody := `{"nullifier":"0xdead","voteCommitment":"0xbeef","proof":"stub"}`
	vreq := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(voteBody))
	vw := httptest.NewRecorder()
	srv.ServeHTTP(vw, vreq)
	if vw.Code != 409 {
		t.Fatalf("expected 409 when registry has unsigned updates, got %d: %s", vw.Code, vw.Body.String())
	}
}

func TestCastVoteAcceptsLegacyPollsWithoutSigs(t *testing.T) {
	// Polls that existed before the signing feature have no
	// RegistryRootSigs entries. These must continue to work — otherwise
	// we break every in-flight poll. handleCastVote only enforces the
	// check when at least one signature has been recorded.
	srv := testServer(t)
	pollID := createTestPoll(t, srv, "legacy", []string{"A", "B"})

	voteBody := `{"nullifier":"0xbeadf00d","voteCommitment":"0xabba","proof":"stub"}`
	req := httptest.NewRequest("POST", "/api/polls/"+pollID+"/vote", strings.NewReader(voteBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// Anything OTHER than the registry-check 409 is acceptable here — the
	// vote may still bounce on proof validation etc.; we only care that
	// the registry-sig check doesn't gate legacy polls.
	if w.Code == 409 {
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		t.Fatalf("legacy poll rejected on registry-sig gate: %s", w.Body.String())
	}
}
