package prover

import (
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// mimcHash computes MiMC hash of two inputs in a gnark circuit.
func mimcHash(api frontend.API, left, right frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(left)
	h.Write(right)
	return h.Sum()
}

// TransferCircuit proves: balances[from] >= amount
// Public inputs: preStateRoot, postStateRoot, from, to, amount
// Private inputs: balance, merkle proof
type TransferCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	From          frontend.Variable `gnark:",public"`
	To            frontend.Variable `gnark:",public"`
	Amount        frontend.Variable `gnark:",public"`

	// Private inputs
	BalanceFrom frontend.Variable
	BalanceTo   frontend.Variable

	// Merkle proof for balance (20 levels)
	PathElements [20]frontend.Variable
	PathIndices  [20]frontend.Variable
}

func (c *TransferCircuit) Define(api frontend.API) error {
	// Guard: balance_from >= amount
	diff := api.Sub(c.BalanceFrom, c.Amount)
	api.ToBinary(diff, 64) // Proves diff is non-negative

	// Verify pre-state Merkle proof
	leaf := mimcHash(api, c.From, c.BalanceFrom)
	current := leaf
	for i := 0; i < 20; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], current)
		right := api.Select(c.PathIndices[i], current, c.PathElements[i])
		current = mimcHash(api, left, right)
	}
	api.AssertIsEqual(current, c.PreStateRoot)

	// Verify post-state: new balances must hash to PostStateRoot
	newBalanceFrom := api.Sub(c.BalanceFrom, c.Amount)
	newBalanceTo := api.Add(c.BalanceTo, c.Amount)
	postLeaf := mimcHash(api, c.From, newBalanceFrom)
	postLeaf2 := mimcHash(api, c.To, newBalanceTo)
	computedPost := mimcHash(api, postLeaf, postLeaf2)
	api.AssertIsEqual(computedPost, c.PostStateRoot)

	return nil
}

// TransferFromCircuit proves: balances[from] >= amount && allowances[from][caller] >= amount
type TransferFromCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	From          frontend.Variable `gnark:",public"`
	To            frontend.Variable `gnark:",public"`
	Caller        frontend.Variable `gnark:",public"`
	Amount        frontend.Variable `gnark:",public"`

	// Private inputs
	BalanceFrom   frontend.Variable
	AllowanceFrom frontend.Variable

	// Merkle proofs (simplified: 10 levels each)
	BalancePath    [10]frontend.Variable
	BalanceIndices [10]frontend.Variable
	AllowancePath  [10]frontend.Variable
	AllowanceIdx   [10]frontend.Variable
}

func (c *TransferFromCircuit) Define(api frontend.API) error {
	// Guard 1: balance >= amount
	diff1 := api.Sub(c.BalanceFrom, c.Amount)
	api.ToBinary(diff1, 64)

	// Guard 2: allowance >= amount
	diff2 := api.Sub(c.AllowanceFrom, c.Amount)
	api.ToBinary(diff2, 64)

	// Verify balance Merkle proof
	balanceLeaf := mimcHash(api, c.From, c.BalanceFrom)
	current := balanceLeaf
	for i := 0; i < 10; i++ {
		api.AssertIsBoolean(c.BalanceIndices[i])
		left := api.Select(c.BalanceIndices[i], c.BalancePath[i], current)
		right := api.Select(c.BalanceIndices[i], current, c.BalancePath[i])
		current = mimcHash(api, left, right)
	}
	balanceRoot := current

	// Verify allowance Merkle proof
	allowanceKey := mimcHash(api, c.From, c.Caller)
	allowanceLeaf := mimcHash(api, allowanceKey, c.AllowanceFrom)
	current = allowanceLeaf
	for i := 0; i < 10; i++ {
		api.AssertIsBoolean(c.AllowanceIdx[i])
		left := api.Select(c.AllowanceIdx[i], c.AllowancePath[i], current)
		right := api.Select(c.AllowanceIdx[i], current, c.AllowancePath[i])
		current = mimcHash(api, left, right)
	}
	allowanceRoot := current

	// Verify pre-state root
	computedRoot := mimcHash(api, balanceRoot, allowanceRoot)
	api.AssertIsEqual(computedRoot, c.PreStateRoot)

	// Verify post-state: new balance and reduced allowance
	newBalance := api.Sub(c.BalanceFrom, c.Amount)
	newAllowance := api.Sub(c.AllowanceFrom, c.Amount)
	postBalanceLeaf := mimcHash(api, c.From, newBalance)
	postAllowanceLeaf := mimcHash(api, allowanceKey, newAllowance)
	computedPost := mimcHash(api, postBalanceLeaf, postAllowanceLeaf)
	api.AssertIsEqual(computedPost, c.PostStateRoot)

	return nil
}

// MintCircuit proves: caller == minter
type MintCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	Caller        frontend.Variable `gnark:",public"`
	To            frontend.Variable `gnark:",public"`
	Amount        frontend.Variable `gnark:",public"`

	// Private inputs
	Minter    frontend.Variable // The authorized minter address
	BalanceTo frontend.Variable
}

func (c *MintCircuit) Define(api frontend.API) error {
	// Guard: caller == minter
	api.AssertIsEqual(c.Caller, c.Minter)

	// Verify post-state: new balance must hash to PostStateRoot
	newBalance := api.Add(c.BalanceTo, c.Amount)
	postLeaf := mimcHash(api, c.To, newBalance)
	api.AssertIsEqual(postLeaf, c.PostStateRoot)

	return nil
}

// BurnCircuit proves: balances[from] >= amount
type BurnCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	From          frontend.Variable `gnark:",public"`
	Amount        frontend.Variable `gnark:",public"`

	// Private inputs
	BalanceFrom frontend.Variable

	// Merkle proof
	PathElements [20]frontend.Variable
	PathIndices  [20]frontend.Variable
}

func (c *BurnCircuit) Define(api frontend.API) error {
	// Guard: balance >= amount
	diff := api.Sub(c.BalanceFrom, c.Amount)
	api.ToBinary(diff, 64)

	// Verify pre-state Merkle proof
	leaf := mimcHash(api, c.From, c.BalanceFrom)
	current := leaf
	for i := 0; i < 20; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], current)
		right := api.Select(c.PathIndices[i], current, c.PathElements[i])
		current = mimcHash(api, left, right)
	}
	api.AssertIsEqual(current, c.PreStateRoot)

	// Verify post-state: reduced balance
	newBalance := api.Sub(c.BalanceFrom, c.Amount)
	postLeaf := mimcHash(api, c.From, newBalance)
	api.AssertIsEqual(postLeaf, c.PostStateRoot)

	return nil
}

// ApproveCircuit proves: owner == caller
type ApproveCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	Caller        frontend.Variable `gnark:",public"`
	Spender       frontend.Variable `gnark:",public"`
	Amount        frontend.Variable `gnark:",public"`

	// Private inputs
	Owner frontend.Variable
}

func (c *ApproveCircuit) Define(api frontend.API) error {
	// Guard: owner == caller (only owner can approve)
	api.AssertIsEqual(c.Owner, c.Caller)

	// Verify post-state: allowance set to amount
	postLeaf := mimcHash(api, c.Spender, c.Amount)
	api.AssertIsEqual(postLeaf, c.PostStateRoot)

	return nil
}

// VestingClaimCircuit proves: vestSchedules[tokenId] exists && vestOwners[tokenId] == caller
type VestingClaimCircuit struct {
	// Public inputs
	PreStateRoot  frontend.Variable `gnark:",public"`
	PostStateRoot frontend.Variable `gnark:",public"`
	TokenID       frontend.Variable `gnark:",public"`
	Caller        frontend.Variable `gnark:",public"`
	ClaimAmount   frontend.Variable `gnark:",public"`

	// Private inputs
	VestedAmount frontend.Variable // Total vested so far
	Claimed      frontend.Variable // Already claimed
	Owner        frontend.Variable // NFT owner

	// Merkle proofs
	SchedulePath    [10]frontend.Variable
	ScheduleIndices [10]frontend.Variable
	OwnerPath       [10]frontend.Variable
	OwnerIndices    [10]frontend.Variable
}

func (c *VestingClaimCircuit) Define(api frontend.API) error {
	// Guard 1: owner == caller
	api.AssertIsEqual(c.Owner, c.Caller)

	// Guard 2: claimAmount <= vestedAmount - claimed
	available := api.Sub(c.VestedAmount, c.Claimed)
	diff := api.Sub(available, c.ClaimAmount)
	api.ToBinary(diff, 64) // Proves diff is non-negative

	// Verify schedule Merkle proof
	scheduleLeaf := mimcHash(api, c.TokenID, c.VestedAmount)
	current := scheduleLeaf
	for i := 0; i < 10; i++ {
		api.AssertIsBoolean(c.ScheduleIndices[i])
		left := api.Select(c.ScheduleIndices[i], c.SchedulePath[i], current)
		right := api.Select(c.ScheduleIndices[i], current, c.SchedulePath[i])
		current = mimcHash(api, left, right)
	}
	scheduleRoot := current

	// Verify owner Merkle proof
	ownerLeaf := mimcHash(api, c.TokenID, c.Owner)
	current = ownerLeaf
	for i := 0; i < 10; i++ {
		api.AssertIsBoolean(c.OwnerIndices[i])
		left := api.Select(c.OwnerIndices[i], c.OwnerPath[i], current)
		right := api.Select(c.OwnerIndices[i], current, c.OwnerPath[i])
		current = mimcHash(api, left, right)
	}
	ownerRoot := current

	// Verify pre-state root
	computedRoot := mimcHash(api, scheduleRoot, ownerRoot)
	api.AssertIsEqual(computedRoot, c.PreStateRoot)

	// Verify post-state: updated claimed amount
	newClaimed := api.Add(c.Claimed, c.ClaimAmount)
	postLeaf := mimcHash(api, c.TokenID, newClaimed)
	api.AssertIsEqual(postLeaf, c.PostStateRoot)

	return nil
}

// VoteCastCircuit proves: "I am an eligible voter and my vote is valid" without revealing identity or choice.
// Public inputs: pollId, voterRegistryRoot, nullifier, voteCommitment, maxChoices
// Private inputs: voterSecret, voteChoice, voterWeight, pathElements[20], pathIndices[20]
//
// The voteCommitment = mimcHash(voterSecret, voteChoice) binds the choice to the voter's secret.
// Since voterSecret is private and unknown to observers, the commitment cannot be brute-forced
// even though voteChoice is only 8 bits.
type VoteCastCircuit struct {
	// Public inputs
	PollID             frontend.Variable `gnark:",public"`
	VoterRegistryRoot  frontend.Variable `gnark:",public"`
	Nullifier          frontend.Variable `gnark:",public"`
	VoteCommitment     frontend.Variable `gnark:",public"`
	MaxChoices         frontend.Variable `gnark:",public"`

	// Private inputs
	VoterSecret  frontend.Variable
	VoteChoice   frontend.Variable
	VoterWeight  frontend.Variable

	// Merkle proof for voter commitment (20 levels)
	PathElements [20]frontend.Variable
	PathIndices  [20]frontend.Variable
}

func (c *VoteCastCircuit) Define(api frontend.API) error {
	// 1. Commitment: leaf = mimcHash(voterSecret, voterWeight)
	leaf := mimcHash(api, c.VoterSecret, c.VoterWeight)

	// 2. Merkle proof: walk path up to root, assert root == voterRegistryRoot
	current := leaf
	for i := 0; i < 20; i++ {
		api.AssertIsBoolean(c.PathIndices[i])
		left := api.Select(c.PathIndices[i], c.PathElements[i], current)
		right := api.Select(c.PathIndices[i], current, c.PathElements[i])
		current = mimcHash(api, left, right)
	}
	api.AssertIsEqual(current, c.VoterRegistryRoot)

	// 3. Nullifier binding: nullifier == mimcHash(voterSecret, pollId)
	expectedNullifier := mimcHash(api, c.VoterSecret, c.PollID)
	api.AssertIsEqual(c.Nullifier, expectedNullifier)

	// 4. Vote range: choice fits in 8 bits AND choice < maxChoices
	api.ToBinary(c.VoteChoice, 8)
	diff := api.Sub(c.MaxChoices, c.VoteChoice)   // maxChoices - choice
	diffMinusOne := api.Sub(diff, 1)               // must be >= 0 (i.e., choice <= maxChoices-1)
	api.ToBinary(diffMinusOne, 8)                   // proves non-negative

	// 5. Vote commitment: binds choice to voter secret (blinded — can't brute-force)
	expectedCommitment := mimcHash(api, c.VoterSecret, c.VoteChoice)
	api.AssertIsEqual(c.VoteCommitment, expectedCommitment)

	return nil
}

// RegisterStandardCircuits registers all standard ERC-20 circuits with the prover.
// Circuits are compiled in parallel for faster startup.
func RegisterStandardCircuits(p *Prover) error {
	circuits := map[string]frontend.Circuit{
		"transfer":     &TransferCircuit{},
		"transferFrom": &TransferFromCircuit{},
		"mint":         &MintCircuit{},
		"burn":         &BurnCircuit{},
		"approve":      &ApproveCircuit{},
		"vestClaim":    &VestingClaimCircuit{},
		"voteCast":     &VoteCastCircuit{},
	}

	return RegisterCircuitsParallel(p, circuits)
}

// RegisterCircuitsParallel compiles and registers multiple circuits concurrently.
// This significantly speeds up startup when registering many circuits.
func RegisterCircuitsParallel(p *Prover, circuits map[string]frontend.Circuit) error {
	// Compile all circuits in parallel
	type compiledResult struct {
		name string
		cc   *CompiledCircuit
	}

	var (
		g       errgroup.Group
		mu      sync.Mutex
		results []compiledResult
	)

	for name, circuit := range circuits {
		name, circuit := name, circuit // capture for goroutine
		g.Go(func() error {
			log.Debug().Str("circuit", name).Msg("Compiling circuit...")

			cc, err := p.CompileCircuit(name, circuit)
			if err != nil {
				return err
			}

			mu.Lock()
			results = append(results, compiledResult{name: name, cc: cc})
			mu.Unlock()

			log.Debug().
				Str("circuit", name).
				Int("constraints", cc.Constraints).
				Msg("Circuit compiled")

			return nil
		})
	}

	// Wait for all compilations
	if err := g.Wait(); err != nil {
		return err
	}

	// Register all compiled circuits (sequential, but fast)
	for _, r := range results {
		p.StoreCircuit(r.name, r.cc)
	}

	return nil
}
