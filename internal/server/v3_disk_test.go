package server

import (
	"bytes"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestV3PollDirHasNoChoiceLeakage is the explicit acceptance test
// from the v3 spec (B5.10c). After running a complete v3 lifecycle
// — create poll, three voters cast ballots at distinct bins, creator
// closes — we walk every file under the poll's data directory and
// assert it contains no fields that would reveal a per-voter choice.
//
// Approach: grep for *structural leak indicators* rather than choice
// values themselves. Bin indices are tiny ints that appear naturally
// in timestamps, version fields, etc.; chasing them produces false
// positives. The honest leak surface is the v1/v2 reveal-vocabulary
// (`voteChoice`, `voterSecret`, `voteCommitment`, `reveals.json`), so
// asserting *those tokens are absent* is what catches a real privacy
// regression.
func TestV3PollDirHasNoChoiceLeakage(t *testing.T) {
	if testing.Short() {
		t.Skip("v3 lifecycle test compiles two large circuits; skip in short mode")
	}
	srv := testServer(t)
	attachV3FullProver(t, srv)

	pollID, sk, pk := seedV3Poll(t, srv)
	poll, _ := srv.store.ReadPoll(pollID)
	_, devAddr := testCreatorDevSign(t, "warm-up")
	poll.Creator = devAddr
	_ = srv.store.SavePoll(poll)

	// 3 ballots at three distinct bins so the close path actually
	// produces non-trivial tallies — a poll where everyone votes for
	// bin 0 would coincidentally contain the choice value `0` in many
	// places (timestamps, status fields) and obscure the assertion.
	registerTestVoter(t, srv, pollID)
	registerTestVoter(t, srv, pollID)
	castV3Vote(t, srv, pollID, pk, 1, 8)
	castV3Vote(t, srv, pollID, pk, 4, 8)
	castV3Vote(t, srv, pollID, pk, 6, 8)

	// Build + post the close artifact.
	proofBytes, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	sig, _ := signAggregate(t, pollID, tallies)
	body := map[string]any{
		"creator":           devAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	if w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", body); w.Code != 200 {
		t.Fatalf("aggregate: %d body=%q", w.Code, w.Body.String())
	}

	// Walk the poll directory and inspect every file.
	pollDir := filepath.Join(srv.store.Base(), "polls", pollID)
	if _, err := os.Stat(pollDir); err != nil {
		t.Fatalf("poll dir missing: %v", err)
	}

	// Tokens that appear only in v1/v2 reveal-bearing artifacts. A v3
	// poll's directory must not contain any of them.
	leakTokens := []string{
		"voteChoice",
		"voterSecret",
		"voteCommitment",
	}

	// Filenames that must not exist for v3 polls.
	forbiddenFiles := []string{
		"reveals.json",
		"tallyproof.json", // v1/v2 tally artifact
	}

	// Files we expect to find (positive check — proves the test ran).
	expectedFiles := map[string]bool{
		"tally.json": false,
	}

	walked := 0
	err := filepath.WalkDir(pollDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		walked++
		base := filepath.Base(path)

		for _, forbidden := range forbiddenFiles {
			if base == forbidden {
				t.Errorf("forbidden file present: %s", path)
			}
		}
		if _, ok := expectedFiles[base]; ok {
			expectedFiles[base] = true
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}
		for _, token := range leakTokens {
			if bytes.Contains(data, []byte(token)) {
				t.Errorf("file %s contains leak token %q\n  excerpt: %s",
					path, token, excerptAround(data, []byte(token)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if walked == 0 {
		t.Fatal("walked zero files — poll directory empty?")
	}
	for fname, found := range expectedFiles {
		if !found {
			t.Errorf("expected file %q not found in poll dir", fname)
		}
	}

	// Belt-and-suspenders: confirm via the store API that no reveal
	// bundle exists for this poll. The walk above already covers
	// reveals.json's filename, but this surfaces a different code path
	// (HasReveals reads existence directly) so a regression in the
	// path-derivation logic surfaces too.
	has, err := srv.store.HasReveals(pollID)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Error("store.HasReveals returned true for a closed v3 poll")
	}

	// Confirm the stored vote records have empty VoteCommitment — the
	// v3 path should never have populated this field.
	votes, err := srv.store.ListVotes(pollID)
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) != 3 {
		t.Errorf("expected 3 votes, got %d", len(votes))
	}
	for i, v := range votes {
		if v.VoteCommitment != "" {
			t.Errorf("v3 vote[%d] has VoteCommitment=%q (should be empty)", i, v.VoteCommitment)
		}
		if len(v.Ciphertexts) != 8 {
			t.Errorf("v3 vote[%d] has %d ciphertexts (want 8)", i, len(v.Ciphertexts))
		}
	}
}

// excerptAround returns ~80 chars of context around a token match in
// `data`, for clearer test failure messages.
func excerptAround(data, token []byte) string {
	idx := bytes.Index(data, token)
	if idx < 0 {
		return ""
	}
	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(token) + 30
	if end > len(data) {
		end = len(data)
	}
	excerpt := string(data[start:end])
	excerpt = strings.ReplaceAll(excerpt, "\n", "\\n")
	return "..." + excerpt + "..."
}
