package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestV3PollRoundtrip — a poll stamped with VoteSchemaVersion=3 and a
// PkCreator survives Save → Read with both fields intact.
func TestV3PollRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)

	pk := "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925"
	in := &Poll{
		ID:                "poll-v3-1",
		Title:             "v3 test",
		Choices:           []string{"yes", "no"},
		Creator:           "0xCAFE",
		CreatedAt:         time.Now().UTC(),
		Status:            "active",
		VoteSchemaVersion: 3,
		PkCreator:         pk,
	}
	if err := s.SavePoll(in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := s.ReadPoll("poll-v3-1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.VoteSchemaVersion != 3 {
		t.Errorf("VoteSchemaVersion: got %d, want 3", out.VoteSchemaVersion)
	}
	if out.PkCreator != pk {
		t.Errorf("PkCreator: got %q, want %q", out.PkCreator, pk)
	}
}

// TestLegacyPollLoads — a v1 fixture without VoteSchemaVersion or
// PkCreator unmarshals cleanly, leaving both as zero values. v1/v2
// readers must continue to function after the v3 schema additions.
func TestLegacyPollLoads(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)

	const legacy = `{
		"id": "poll-legacy",
		"title": "old",
		"choices": ["a", "b"],
		"creator": "0xDEAD",
		"createdAt": "2025-01-01T00:00:00Z",
		"status": "active"
	}`
	if err := os.MkdirAll(s.pollDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.pollDir(), "poll-legacy.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s.ReadPoll("poll-legacy")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.VoteSchemaVersion != 0 {
		t.Errorf("legacy VoteSchemaVersion: got %d, want 0", out.VoteSchemaVersion)
	}
	if out.PkCreator != "" {
		t.Errorf("legacy PkCreator: got %q, want empty", out.PkCreator)
	}
}

// TestHomomorphicTallyRoundtrip — tally artifact saves and reads back
// with byte-identical fields.
func TestHomomorphicTallyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)

	in := &HomomorphicTallyArtifact{
		PollID:      "poll-v3-1",
		GeneratedAt: time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC),
		CircuitName: "tallyDecrypt_8",
		PkCreator:   "8b7d2d877a253c4b7733e1b91f05e0fcedf96bd11c2e572549b2a0f703727925",
		Aggregate: []HomomorphicCiphertext{
			{A: "0e395cb83b724e315036f2829d619f053351bed321cadb7558de22ea10890e18",
				B: "5328ef54a988b6a5d5f256f5f1a46de110ad7105d38cf72cbef5c7ac2bf16c29"},
		},
		Tallies:       []int64{2, 0, 1, 0, 0, 0, 0, 0},
		NumBallots:    3,
		DecryptProof:  "AAAA",
		PublicWitness: "BBBB",
	}
	if err := s.SaveHomomorphicTally("poll-v3-1", in); err != nil {
		t.Fatalf("save: %v", err)
	}
	out, err := s.ReadHomomorphicTally("poll-v3-1")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Cheap deep-equal via JSON roundtrip — avoids importing reflect for
	// time and slice comparisons.
	a, _ := json.Marshal(in)
	b, _ := json.Marshal(out)
	if string(a) != string(b) {
		t.Errorf("roundtrip diverged:\n  in:  %s\n  out: %s", a, b)
	}
}

// TestSaveHomomorphicTallyAtomic — interrupting mid-write must never
// leave a parseable-but-truncated tally.json. We simulate by checking
// the tempfile pattern: after a successful save, no .tmp lingers.
func TestSaveHomomorphicTallyAtomic(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)
	in := &HomomorphicTallyArtifact{PollID: "p", CircuitName: "tallyDecrypt_8"}
	if err := s.SaveHomomorphicTally("p", in); err != nil {
		t.Fatalf("save: %v", err)
	}
	pollDir := filepath.Join(s.pollDir(), "p")
	entries, err := os.ReadDir(pollDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover tempfile: %s", e.Name())
		}
	}
}

// TestReadHomomorphicTallyMissing — absent file returns os.ErrNotExist
// (or wrapping thereof). Callers branch on os.IsNotExist.
func TestReadHomomorphicTallyMissing(t *testing.T) {
	s := NewFSStore(t.TempDir())
	_, err := s.ReadHomomorphicTally("nope")
	if !os.IsNotExist(err) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

// TestHasReveals — true when reveals.json exists, false otherwise.
// Critical: v3 polls must always have HasReveals == false.
func TestHasReveals(t *testing.T) {
	dir := t.TempDir()
	s := NewFSStore(dir)

	// no reveals → false
	got, err := s.HasReveals("p")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got {
		t.Errorf("HasReveals on empty poll: got true, want false")
	}

	// drop a reveals.json → true
	pdir := filepath.Join(s.pollDir(), "p")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "reveals.json"), []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = s.HasReveals("p")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got {
		t.Errorf("HasReveals after writing reveals.json: got false, want true")
	}
}

// TestSanitizePathRejectsTraversal — both new endpoints must refuse
// path-traversal attempts on pollID, since they're derived from
// untrusted input.
func TestSanitizePathRejectsTraversal(t *testing.T) {
	s := NewFSStore(t.TempDir())
	for _, bad := range []string{"../etc", "a/b", ""} {
		if _, err := s.ReadHomomorphicTally(bad); err == nil {
			t.Errorf("ReadHomomorphicTally(%q): expected error", bad)
		}
		if _, err := s.HasReveals(bad); err == nil {
			t.Errorf("HasReveals(%q): expected error", bad)
		}
	}
}
