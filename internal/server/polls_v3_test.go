package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackdump/bitwrap-io/prover"
)

// pkCreatorHex returns a 32-byte compressed BabyJubJub public key as
// hex, derived from a fixed scalar. Sufficient as a real-but-test pk.
func pkCreatorHex(t *testing.T) string {
	t.Helper()
	g := prover.PedersenG()
	var pk = g
	pk.ScalarMultiplication(&g, big.NewInt(0xc0ffee))
	return hex.EncodeToString(prover.EncodePoint(&pk))
}

// --- Tests ----------------------------------------------------------------

// TestCreatePollV3Accepts — create a v3 poll with a valid pk and a
// real wallet signature; expect 200 + the v3 fields persisted.
func TestCreatePollV3Accepts(t *testing.T) {
	srv := testServer(t)
	pk := pkCreatorHex(t)

	title := "v3 poll accepts"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	body := map[string]any{
		"title":             title,
		"choices":           []string{"yes", "no"},
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 3,
		"pkCreator":         pk,
		"durationMinutes":   60,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 200 {
		t.Fatalf("v3 create: got %d, body=%q", w.Code, w.Body.String())
	}
	var resp struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ID == "" {
		t.Fatal("no poll id returned")
	}

	poll, err := srv.store.ReadPoll(resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if poll.VoteSchemaVersion != 3 {
		t.Errorf("VoteSchemaVersion: got %d, want 3", poll.VoteSchemaVersion)
	}
	if poll.PkCreator != pk {
		t.Errorf("PkCreator persisted wrong: got %q want %q", poll.PkCreator, pk)
	}
}

// TestCreatePollV3MissingPk — schemaVersion=3 without pkCreator must 400.
func TestCreatePollV3MissingPk(t *testing.T) {
	srv := testServer(t)
	title := "v3 missing pk"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)
	body := map[string]any{
		"title":             title,
		"choices":           []string{"yes", "no"},
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 3,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "pkCreator") {
		t.Errorf("error message should mention pkCreator: %q", w.Body.String())
	}
}

// TestCreatePollV3BadHexLen — pk that isn't 32 bytes must 400.
func TestCreatePollV3BadHexLen(t *testing.T) {
	srv := testServer(t)
	title := "v3 bad pk len"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)
	body := map[string]any{
		"title":             title,
		"choices":           []string{"yes", "no"},
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 3,
		"pkCreator":         "deadbeef",
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestCreatePollV3OffCurve — pk that's not on the curve must 400.
// Use 32 zero bytes — decodes as identity (valid in some encodings)
// or off-curve depending on flag, both must reject.
func TestCreatePollV3OffCurve(t *testing.T) {
	srv := testServer(t)
	title := "v3 off curve"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	// Construct an x-coordinate that probably isn't on the curve, with
	// a valid sign-bit-flag in byte 31 (high bit set means "x is
	// negative"). Most random y-bytes won't satisfy the curve eqn.
	bad := strings.Repeat("ab", 31) + "cd"

	body := map[string]any{
		"title":             title,
		"choices":           []string{"yes", "no"},
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 3,
		"pkCreator":         bad,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400 for off-curve pk, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestCreatePollV3PkOnV2Rejected — pkCreator is valid only for v3.
// Sending it with v2 (or default) is an error so a misconfigured client
// surface flags the problem at create time, not later.
func TestCreatePollV3PkOnV2Rejected(t *testing.T) {
	srv := testServer(t)
	pk := pkCreatorHex(t)
	title := "pk on v2"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	body := map[string]any{
		"title":     title,
		"choices":   []string{"yes", "no"},
		"creator":   creator,
		"signature": sig,
		"pkCreator": pk, // no schemaVersion → defaults to 2
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestCreatePollV3UnsupportedVersion — schemaVersion outside {0,2,3}.
func TestCreatePollV3UnsupportedVersion(t *testing.T) {
	srv := testServer(t)
	title := "bad version"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	body := map[string]any{
		"title":             title,
		"choices":           []string{"yes", "no"},
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 99,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestCreatePollV3TooManyChoices — v3's per-voter circuit fixes K=8.
func TestCreatePollV3TooManyChoices(t *testing.T) {
	srv := testServer(t)
	title := "too many choices"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	choices := make([]string, prover.VoteCastHomomorphicChoices+1)
	for i := range choices {
		choices[i] = fmt.Sprintf("opt%d", i)
	}
	pk := pkCreatorHex(t)

	body := map[string]any{
		"title":             title,
		"choices":           choices,
		"creator":           creator,
		"signature":         sig,
		"voteSchemaVersion": 3,
		"pkCreator":         pk,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d body=%q", w.Code, w.Body.String())
	}
}

// TestCreatePollV2DefaultStillWorks — confirms the existing v2 path is
// untouched after v3 wiring.
func TestCreatePollV2DefaultStillWorks(t *testing.T) {
	srv := testServer(t)
	title := "v2 default"
	sigMsg := "bitwrap-create-poll:" + title
	sig, creator := testCreatorDevSign(t, sigMsg)

	body := map[string]any{
		"title":     title,
		"choices":   []string{"yes", "no"},
		"creator":   creator,
		"signature": sig,
	}
	w := postJSON(t, srv, "/api/polls", body)
	if w.Code != 200 {
		t.Fatalf("v2 default: got %d body=%q", w.Code, w.Body.String())
	}
	var resp struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	poll, err := srv.store.ReadPoll(resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if poll.VoteSchemaVersion != 2 {
		t.Errorf("v2 default: VoteSchemaVersion got %d, want 2", poll.VoteSchemaVersion)
	}
	if poll.PkCreator != "" {
		t.Errorf("v2 default: PkCreator should be empty, got %q", poll.PkCreator)
	}
}

// postJSON — encode body as JSON and POST to path; return recorder.
func postJSON(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(buf)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}
