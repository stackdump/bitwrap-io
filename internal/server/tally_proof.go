package server

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/consensys/gnark/frontend"
	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

// tallyCircuitTiers lists the available sized variants in increasing
// capacity order. selectTallyCircuitSize walks this list and returns
// the first entry whose capacity accommodates the vote count.
var tallyCircuitTiers = []struct {
	Name     string
	Capacity int
}{
	{"tallyProof_16", 16},
	{"tallyProof_64", 64},
	{"tallyProof_256", 256},
}

// selectTallyCircuitSize picks the smallest-fitting sized circuit for a
// given number of votes. The 256-slot circuit is lazy-compiled (see
// prover.RegisterLazyCircuit in prover/circuits.go), so callers must
// invoke prover.EnsureCompiled(p, name) before using it.
func selectTallyCircuitSize(voteCount int) (string, int, error) {
	if voteCount <= 0 {
		return "", 0, fmt.Errorf("no votes")
	}
	for _, tier := range tallyCircuitTiers {
		if voteCount <= tier.Capacity {
			return tier.Name, tier.Capacity, nil
		}
	}
	last := tallyCircuitTiers[len(tallyCircuitTiers)-1]
	return "", 0, fmt.Errorf("vote count %d exceeds largest tally circuit (%s cap=%d)",
		voteCount, last.Name, last.Capacity)
}

// BuildTallyProofWitness returns a TallyProofCircuit16 assignment. Kept
// as a back-compat entry for callers that pre-date the sized variants.
// New code should use BuildTallyProofWitnessSized so it can dispatch
// against the correct sized circuit.
func BuildTallyProofWitness(s *store.FSStore, pollID string) (*prover.TallyProofCircuit16, error) {
	assignment, _, _, err := BuildTallyProofWitnessSized(s, pollID)
	if err != nil {
		return nil, err
	}
	c, ok := assignment.(*prover.TallyProofCircuit16)
	if !ok {
		return nil, fmt.Errorf("vote count exceeds 16-slot capacity; use BuildTallyProofWitnessSized")
	}
	return c, nil
}

// tallySlots holds the per-slot assignment data before we materialize it
// into a specific sized circuit struct. Kept separate from the circuit
// types so the population loop runs once regardless of target size.
type tallySlots struct {
	pollIDField *big.Int
	commitments []*big.Int
	nullifiers  []*big.Int
	secrets     []*big.Int
	choices     []int64
	active      []int64
	tallies     []int64
	numReveals  int64
}

// BuildTallyProofWitnessSized picks the smallest tally circuit that can
// fit the poll's vote count and builds a witness for that size. Returns
// the populated frontend.Circuit assignment, the selected circuit name
// (e.g., "tallyProof_64"), and the slot capacity it was padded to.
func BuildTallyProofWitnessSized(s *store.FSStore, pollID string) (frontend.Circuit, string, int, error) {
	votes, err := s.ListVotes(pollID)
	if err != nil {
		return nil, "", 0, fmt.Errorf("ListVotes: %w", err)
	}
	if len(votes) == 0 {
		return nil, "", 0, fmt.Errorf("no votes recorded")
	}
	name, capacity, err := selectTallyCircuitSize(len(votes))
	if err != nil {
		return nil, "", 0, err
	}

	bundles, err := s.ListRevealBundles(pollID)
	if err != nil {
		return nil, "", 0, fmt.Errorf("ListRevealBundles: %w", err)
	}
	if len(bundles) == 0 {
		return nil, "", 0, fmt.Errorf("no reveals recorded — cannot build tally witness")
	}

	reveals := make(map[string]store.RevealBundle, len(bundles))
	for _, b := range bundles {
		reveals[b.Nullifier] = b
	}

	pollIDField, err := pollIDToField(pollID)
	if err != nil {
		return nil, "", 0, fmt.Errorf("pollID: %w", err)
	}

	slots := tallySlots{
		pollIDField: pollIDField,
		commitments: make([]*big.Int, capacity),
		nullifiers:  make([]*big.Int, capacity),
		secrets:     make([]*big.Int, capacity),
		choices:     make([]int64, capacity),
		active:      make([]int64, capacity),
		tallies:     make([]int64, prover.TallyProofMaxChoices),
	}

	for i := 0; i < capacity; i++ {
		slots.commitments[i] = big.NewInt(0)
		slots.nullifiers[i] = big.NewInt(0)
		slots.secrets[i] = big.NewInt(0)
		if i >= len(votes) {
			continue
		}

		v := votes[i]
		commit, err := parseFieldLoose(v.VoteCommitment)
		if err != nil {
			return nil, "", 0, fmt.Errorf("vote %d commitment: %w", i, err)
		}
		null, err := parseFieldLoose(v.Nullifier)
		if err != nil {
			return nil, "", 0, fmt.Errorf("vote %d nullifier: %w", i, err)
		}
		slots.commitments[i] = commit
		slots.nullifiers[i] = null

		bundle, revealed := reveals[v.Nullifier]
		if !revealed {
			continue
		}
		secret, err := parseFieldLoose(bundle.Secret)
		if err != nil {
			return nil, "", 0, fmt.Errorf("reveal %s secret: %w", v.Nullifier, err)
		}
		if bundle.Choice < 0 || bundle.Choice >= prover.TallyProofMaxChoices {
			return nil, "", 0, fmt.Errorf("reveal %s choice %d out of circuit range [0, %d)",
				v.Nullifier, bundle.Choice, prover.TallyProofMaxChoices)
		}
		slots.secrets[i] = secret
		slots.choices[i] = int64(bundle.Choice)
		slots.active[i] = 1
		slots.tallies[bundle.Choice]++
		slots.numReveals++
	}

	return assembleSizedWitness(name, capacity, slots), name, capacity, nil
}

// assembleSizedWitness copies slots into the correctly-sized circuit
// struct. Because gnark circuits require fixed-size arrays, we can't use
// a generic populator — switch on capacity and assign into the matching
// array type.
func assembleSizedWitness(name string, capacity int, s tallySlots) frontend.Circuit {
	switch capacity {
	case 16:
		c := &prover.TallyProofCircuit16{}
		c.PollID = s.pollIDField
		c.NumReveals = s.numReveals
		for i := 0; i < 16; i++ {
			c.Commitments[i] = s.commitments[i]
			c.Nullifiers[i] = s.nullifiers[i]
			c.Secrets[i] = s.secrets[i]
			c.Choices[i] = s.choices[i]
			c.Active[i] = s.active[i]
		}
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			c.Tallies[j] = s.tallies[j]
		}
		return c
	case 64:
		c := &prover.TallyProofCircuit64{}
		c.PollID = s.pollIDField
		c.NumReveals = s.numReveals
		for i := 0; i < 64; i++ {
			c.Commitments[i] = s.commitments[i]
			c.Nullifiers[i] = s.nullifiers[i]
			c.Secrets[i] = s.secrets[i]
			c.Choices[i] = s.choices[i]
			c.Active[i] = s.active[i]
		}
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			c.Tallies[j] = s.tallies[j]
		}
		return c
	case 256:
		c := &prover.TallyProofCircuit256{}
		c.PollID = s.pollIDField
		c.NumReveals = s.numReveals
		for i := 0; i < 256; i++ {
			c.Commitments[i] = s.commitments[i]
			c.Nullifiers[i] = s.nullifiers[i]
			c.Secrets[i] = s.secrets[i]
			c.Choices[i] = s.choices[i]
			c.Active[i] = s.active[i]
		}
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			c.Tallies[j] = s.tallies[j]
		}
		return c
	default:
		return nil
	}
}

// GenerateTallyProof builds the witness for the smallest-fitting sized
// circuit, lazy-compiles it if needed, runs the prover, and persists
// the artifact. Returns the store-level artifact (base64 proof + hex
// public inputs) plus the decoded tallies.
func GenerateTallyProof(s *store.FSStore, p *prover.Prover, pollID string) (*store.TallyProofArtifact, error) {
	assignment, circuitName, _, err := BuildTallyProofWitnessSized(s, pollID)
	if err != nil {
		return nil, err
	}

	// Ensure the selected circuit is compiled and stored. For the 16/64
	// tiers this is a no-op (registered eagerly at startup); for the 256
	// tier it triggers the lazy compile on first use.
	if _, err := prover.EnsureCompiled(p, circuitName); err != nil {
		return nil, fmt.Errorf("EnsureCompiled %s: %w", circuitName, err)
	}

	artifact, err := prover.ProveTally(p, circuitName, assignment)
	if err != nil {
		return nil, fmt.Errorf("ProveTally %s: %w", circuitName, err)
	}

	tallies, numReveals := extractTalliesFromAssignment(assignment)

	stored := &store.TallyProofArtifact{
		PollID:             pollID,
		GeneratedAt:        time.Now().UTC(),
		CircuitName:        circuitName,
		ProofBytes:         base64.StdEncoding.EncodeToString(artifact.ProofBytes),
		PublicWitnessBytes: base64.StdEncoding.EncodeToString(artifact.PublicWitnessBytes),
		PublicInputs:       artifact.PublicInputs,
		Tallies:            tallies,
		NumReveals:         int(numReveals),
	}
	if err := s.SaveTallyProof(pollID, stored); err != nil {
		return nil, fmt.Errorf("SaveTallyProof: %w", err)
	}
	return stored, nil
}

// extractTalliesFromAssignment reads the Tallies and NumReveals fields
// off whichever sized circuit struct got populated, so we don't have to
// thread the raw tallySlots through to the persistence path.
func extractTalliesFromAssignment(a frontend.Circuit) ([]int64, int64) {
	switch c := a.(type) {
	case *prover.TallyProofCircuit16:
		out := make([]int64, prover.TallyProofMaxChoices)
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			out[j] = toInt64(c.Tallies[j])
		}
		return out, toInt64(c.NumReveals)
	case *prover.TallyProofCircuit64:
		out := make([]int64, prover.TallyProofMaxChoices)
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			out[j] = toInt64(c.Tallies[j])
		}
		return out, toInt64(c.NumReveals)
	case *prover.TallyProofCircuit256:
		out := make([]int64, prover.TallyProofMaxChoices)
		for j := 0; j < prover.TallyProofMaxChoices; j++ {
			out[j] = toInt64(c.Tallies[j])
		}
		return out, toInt64(c.NumReveals)
	default:
		return make([]int64, prover.TallyProofMaxChoices), 0
	}
}

// pollIDToField converts the 16-byte hex poll ID string into a BN254
// field element (as a big.Int, since gnark accepts *big.Int for
// frontend.Variable assignments). Keeps parity with however JS callers
// derive the circuit's PollID input.
func pollIDToField(pollID string) (*big.Int, error) {
	clean := strings.TrimPrefix(pollID, "0x")
	raw, err := hex.DecodeString(clean)
	if err != nil {
		// Not hex — fall back to decimal parse.
		n, ok := new(big.Int).SetString(pollID, 10)
		if !ok {
			return nil, fmt.Errorf("pollID %q is neither hex nor decimal", pollID)
		}
		return n, nil
	}
	return new(big.Int).SetBytes(raw), nil
}

// parseFieldLoose accepts 0x-hex, bare hex, or decimal strings and
// returns a big.Int. Every string the server persists for commitments,
// nullifiers, or secrets should land somewhere in this set.
func parseFieldLoose(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty field element")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex %q", s)
		}
		return n, nil
	}
	if n, ok := new(big.Int).SetString(s, 10); ok {
		return n, nil
	}
	if n, ok := new(big.Int).SetString(s, 16); ok {
		return n, nil
	}
	return nil, fmt.Errorf("unrecognized number %q", s)
}

// toInt64 extracts the int64 value from a frontend.Variable assignment.
// Witness builders use int / int64 / *big.Int interchangeably; this
// normalizes them when we need to write them into a JSON artifact.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	case *big.Int:
		return n.Int64()
	default:
		return 0
	}
}
