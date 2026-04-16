package metamodel

import (
	"encoding/json"
	"testing"
)

// TestSynthMetadataOmittedByDefault — the Phase-2 synthesis fields (MerkleDepth,
// HashFunc, Roles, ZKOps) must all be `omitempty` so unpopulated schemas don't
// shift their content-addressed identity.
func TestSynthMetadataOmittedByDefault(t *testing.T) {
	st := State{ID: "foo"}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	want := `{"id":"foo"}`
	if got != want {
		t.Fatalf("unpopulated State marshaled to %s, want %s", got, want)
	}

	a := Action{ID: "bar"}
	b, err = json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	got = string(b)
	want = `{"id":"bar"}`
	if got != want {
		t.Fatalf("unpopulated Action marshaled to %s, want %s", got, want)
	}
}

// TestSynthMetadataRoundTrip — all new fields survive JSON serialization.
func TestSynthMetadataRoundTrip(t *testing.T) {
	src := &Schema{
		Name:    "Test",
		Version: "1.0",
		States: []State{
			{ID: "balances", Kind: DataState, Type: "map[address]uint256", MerkleDepth: 20, HashFunc: "mimc-bn254"},
			{ID: "owners", Kind: DataState, Type: "map[tokenId]address", MerkleDepth: 10},
		},
		Actions: []Action{
			{
				ID:    "mint",
				Roles: []string{"minter"},
			},
			{
				ID: "castVote",
				ZKOps: []ZKOp{
					{Kind: ZKOpNullifierBind, Inputs: []string{"voterSecret", "pollId"}, Output: "nullifier"},
					{Kind: ZKOpCommitmentBind, Inputs: []string{"voterSecret", "voteChoice"}, Output: "voteCommitment"},
					{Kind: ZKOpRangeCheck, Inputs: []string{"voteChoice"}, BitSize: 8},
				},
			},
		},
		Arcs: []Arc{},
	}

	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var dst Schema
	if err := json.Unmarshal(data, &dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// State metadata preserved
	if dst.States[0].MerkleDepth != 20 {
		t.Errorf("balances MerkleDepth: got %d, want 20", dst.States[0].MerkleDepth)
	}
	if dst.States[0].HashFunc != "mimc-bn254" {
		t.Errorf("balances HashFunc: got %q, want mimc-bn254", dst.States[0].HashFunc)
	}
	if dst.States[1].MerkleDepth != 10 {
		t.Errorf("owners MerkleDepth: got %d, want 10", dst.States[1].MerkleDepth)
	}

	// Action.Roles preserved
	if len(dst.Actions[0].Roles) != 1 || dst.Actions[0].Roles[0] != "minter" {
		t.Errorf("mint Roles: got %v, want [minter]", dst.Actions[0].Roles)
	}

	// ZKOps preserved in order
	ops := dst.Actions[1].ZKOps
	if len(ops) != 3 {
		t.Fatalf("expected 3 ZKOps, got %d", len(ops))
	}
	if ops[0].Kind != ZKOpNullifierBind || ops[0].Output != "nullifier" {
		t.Errorf("ZKOp[0] wrong: %+v", ops[0])
	}
	if ops[1].Kind != ZKOpCommitmentBind || ops[1].Output != "voteCommitment" {
		t.Errorf("ZKOp[1] wrong: %+v", ops[1])
	}
	if ops[2].Kind != ZKOpRangeCheck || ops[2].BitSize != 8 {
		t.Errorf("ZKOp[2] wrong: %+v", ops[2])
	}
}

// TestSynthMetadataDoesNotShiftCID — adding the fields (with omitempty, zero
// values) to an existing schema must leave the CID stable. This is what makes
// Slice 2.0 backward-compatible.
func TestSynthMetadataDoesNotShiftCID(t *testing.T) {
	before := &Schema{
		Name:    "ERC20",
		Version: "1.0",
		States:  []State{{ID: "balances", Kind: DataState, Type: "map"}},
		Actions: []Action{{ID: "transfer"}},
		Arcs:    []Arc{},
	}
	cidBefore := before.CID()

	// Same schema, but the new fields are present as zero values — omitempty
	// must elide them so the marshaled output is byte-identical.
	after := &Schema{
		Name:    "ERC20",
		Version: "1.0",
		States:  []State{{ID: "balances", Kind: DataState, Type: "map", MerkleDepth: 0, HashFunc: ""}},
		Actions: []Action{{ID: "transfer", Roles: nil, ZKOps: nil}},
		Arcs:    []Arc{},
	}
	cidAfter := after.CID()

	if cidBefore != cidAfter {
		t.Errorf("CID shifted when new fields are at zero values:\n  before: %s\n  after:  %s", cidBefore, cidAfter)
	}
}
