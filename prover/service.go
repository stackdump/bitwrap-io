package prover

import (
	"fmt"
	"time"

	"github.com/consensys/gnark/frontend"
	goprover "github.com/pflow-xyz/go-pflow/prover"
	"github.com/rs/zerolog/log"
)

// ArcnetWitnessFactory creates circuit assignments for arcnet's domain-specific circuits.
type ArcnetWitnessFactory struct{}

// CreateAssignment implements goprover.WitnessFactory.
func (f *ArcnetWitnessFactory) CreateAssignment(circuitName string, witness map[string]string) (frontend.Circuit, error) {
	switch circuitName {
	case "transfer", "transferSynth":
		var err error
		var pre, post, from, to, amount, balanceFrom, balanceTo frontend.Variable
		var pathElems, pathIdx [20]frontend.Variable
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if from, err = goprover.ParseWitnessField(witness, "from"); err != nil {
			return nil, err
		}
		if to, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if balanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
			return nil, err
		}
		if balanceTo, err = goprover.ParseWitnessField(witness, "balanceTo"); err != nil {
			return nil, err
		}
		for i := 0; i < 20; i++ {
			if pathElems[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("pathElement%d", i)); err != nil {
				return nil, err
			}
			if pathIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("pathIndex%d", i)); err != nil {
				return nil, err
			}
		}
		if circuitName == "transfer" {
			return &TransferCircuit{
				PreStateRoot: pre, PostStateRoot: post, From: from, To: to, Amount: amount,
				BalanceFrom: balanceFrom, BalanceTo: balanceTo,
				PathElements: pathElems, PathIndices: pathIdx,
			}, nil
		}
		return &TransferSynthCircuit{
			PreStateRoot: pre, PostStateRoot: post, From: from, To: to, Amount: amount,
			BalanceFrom: balanceFrom, BalanceTo: balanceTo,
			PathElements: pathElems, PathIndices: pathIdx,
		}, nil

	case "mint", "mintSynth":
		// Same witness schema for both hand-written and synthesized Mint —
		// parity tests depend on this sharing the assignment path.
		var target interface {
			// kept as interface so the switch below can share code
		}
		if circuitName == "mint" {
			target = &MintCircuit{}
		} else {
			target = &MintSynthCircuit{}
		}
		var err error
		var pre, post, caller, to, amount, minter, balanceTo frontend.Variable
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if to, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if minter, err = goprover.ParseWitnessField(witness, "minter"); err != nil {
			return nil, err
		}
		if balanceTo, err = goprover.ParseWitnessField(witness, "balanceTo"); err != nil {
			return nil, err
		}
		switch a := target.(type) {
		case *MintCircuit:
			a.PreStateRoot, a.PostStateRoot, a.Caller = pre, post, caller
			a.To, a.Amount, a.Minter, a.BalanceTo = to, amount, minter, balanceTo
			return a, nil
		case *MintSynthCircuit:
			a.PreStateRoot, a.PostStateRoot, a.Caller = pre, post, caller
			a.To, a.Amount, a.Minter, a.BalanceTo = to, amount, minter, balanceTo
			return a, nil
		}
		return nil, fmt.Errorf("unreachable")

	case "burn", "burnSynth":
		// Shared witness schema for hand-written and synthesized Burn.
		var err error
		var pre, post, from, amount, balanceFrom frontend.Variable
		var pathElems, pathIdx [20]frontend.Variable
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if from, err = goprover.ParseWitnessField(witness, "from"); err != nil {
			return nil, err
		}
		if amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if balanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
			return nil, err
		}
		for i := 0; i < 20; i++ {
			if pathElems[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("pathElement%d", i)); err != nil {
				return nil, err
			}
			if pathIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("pathIndex%d", i)); err != nil {
				return nil, err
			}
		}
		if circuitName == "burn" {
			return &BurnCircuit{
				PreStateRoot: pre, PostStateRoot: post, From: from, Amount: amount,
				BalanceFrom: balanceFrom, PathElements: pathElems, PathIndices: pathIdx,
			}, nil
		}
		return &BurnSynthCircuit{
			PreStateRoot: pre, PostStateRoot: post, From: from, Amount: amount,
			BalanceFrom: balanceFrom, PathElements: pathElems, PathIndices: pathIdx,
		}, nil

	case "approve", "approveSynth":
		var pre, post, caller, spender, amount, owner frontend.Variable
		var err error
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if spender, err = goprover.ParseWitnessField(witness, "spender"); err != nil {
			return nil, err
		}
		if amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if owner, err = goprover.ParseWitnessField(witness, "owner"); err != nil {
			return nil, err
		}
		if circuitName == "approve" {
			return &ApproveCircuit{
				PreStateRoot: pre, PostStateRoot: post, Caller: caller,
				Spender: spender, Amount: amount, Owner: owner,
			}, nil
		}
		return &ApproveSynthCircuit{
			PreStateRoot: pre, PostStateRoot: post, Caller: caller,
			Spender: spender, Amount: amount, Owner: owner,
		}, nil

	case "transferFrom", "transferFromSynth":
		// Shared witness schema — same field names and dimensions.
		var pre, post, from, to, caller, amount, balanceFrom, allowanceFrom frontend.Variable
		var balPath, balIdx, allowPath, allowIdx [10]frontend.Variable
		var err error
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if from, err = goprover.ParseWitnessField(witness, "from"); err != nil {
			return nil, err
		}
		if to, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if balanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
			return nil, err
		}
		if allowanceFrom, err = goprover.ParseWitnessField(witness, "allowanceFrom"); err != nil {
			return nil, err
		}
		for i := 0; i < 10; i++ {
			if balPath[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("balancePath%d", i)); err != nil {
				return nil, err
			}
			if balIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("balanceIndex%d", i)); err != nil {
				return nil, err
			}
			if allowPath[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("allowancePath%d", i)); err != nil {
				return nil, err
			}
			if allowIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("allowanceIndex%d", i)); err != nil {
				return nil, err
			}
		}
		if circuitName == "transferFrom" {
			return &TransferFromCircuit{
				PreStateRoot: pre, PostStateRoot: post, From: from, To: to, Caller: caller, Amount: amount,
				BalanceFrom: balanceFrom, AllowanceFrom: allowanceFrom,
				BalancePath: balPath, BalanceIndices: balIdx,
				AllowancePath: allowPath, AllowanceIdx: allowIdx,
			}, nil
		}
		return &TransferFromSynthCircuit{
			PreStateRoot: pre, PostStateRoot: post, From: from, To: to, Caller: caller, Amount: amount,
			BalanceFrom: balanceFrom, AllowanceFrom: allowanceFrom,
			BalancePath: balPath, BalanceIndices: balIdx,
			AllowancePath: allowPath, AllowanceIdx: allowIdx,
		}, nil

	case "vestClaim", "vestClaimSynth":
		var pre, post, tokenID, caller, claimAmount, vestedAmount, claimed, owner frontend.Variable
		var schedulePath, scheduleIdx, ownerPath, ownerIdx [10]frontend.Variable
		var err error
		if pre, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if post, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if tokenID, err = goprover.ParseWitnessField(witness, "tokenID"); err != nil {
			return nil, err
		}
		if caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if claimAmount, err = goprover.ParseWitnessField(witness, "claimAmount"); err != nil {
			return nil, err
		}
		if vestedAmount, err = goprover.ParseWitnessField(witness, "vestedAmount"); err != nil {
			return nil, err
		}
		if claimed, err = goprover.ParseWitnessField(witness, "claimed"); err != nil {
			return nil, err
		}
		if owner, err = goprover.ParseWitnessField(witness, "owner"); err != nil {
			return nil, err
		}
		for i := 0; i < 10; i++ {
			if schedulePath[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("schedulePath%d", i)); err != nil {
				return nil, err
			}
			if scheduleIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("scheduleIndex%d", i)); err != nil {
				return nil, err
			}
			if ownerPath[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("ownerPath%d", i)); err != nil {
				return nil, err
			}
			if ownerIdx[i], err = goprover.ParseWitnessField(witness, fmt.Sprintf("ownerIndex%d", i)); err != nil {
				return nil, err
			}
		}
		if circuitName == "vestClaim" {
			return &VestingClaimCircuit{
				PreStateRoot: pre, PostStateRoot: post, TokenID: tokenID, Caller: caller,
				ClaimAmount: claimAmount, VestedAmount: vestedAmount, Claimed: claimed, Owner: owner,
				SchedulePath: schedulePath, ScheduleIndices: scheduleIdx,
				OwnerPath: ownerPath, OwnerIndices: ownerIdx,
			}, nil
		}
		return &VestingClaimSynthCircuit{
			PreStateRoot: pre, PostStateRoot: post, TokenID: tokenID, Caller: caller,
			ClaimAmount: claimAmount, VestedAmount: vestedAmount, Claimed: claimed, Owner: owner,
			SchedulePath: schedulePath, ScheduleIndices: scheduleIdx,
			OwnerPath: ownerPath, OwnerIndices: ownerIdx,
		}, nil

	case "voteCast":
		assignment := &VoteCastCircuit{}
		var err error
		if assignment.PollID, err = goprover.ParseWitnessField(witness, "pollId"); err != nil {
			return nil, err
		}
		if assignment.VoterRegistryRoot, err = goprover.ParseWitnessField(witness, "voterRegistryRoot"); err != nil {
			return nil, err
		}
		if assignment.Nullifier, err = goprover.ParseWitnessField(witness, "nullifier"); err != nil {
			return nil, err
		}
		if assignment.VoteCommitment, err = goprover.ParseWitnessField(witness, "voteCommitment"); err != nil {
			return nil, err
		}
		if assignment.MaxChoices, err = goprover.ParseWitnessField(witness, "maxChoices"); err != nil {
			return nil, err
		}
		if assignment.VoterSecret, err = goprover.ParseWitnessField(witness, "voterSecret"); err != nil {
			return nil, err
		}
		if assignment.VoteChoice, err = goprover.ParseWitnessField(witness, "voteChoice"); err != nil {
			return nil, err
		}
		if assignment.VoterWeight, err = goprover.ParseWitnessField(witness, "voterWeight"); err != nil {
			return nil, err
		}
		for i := 0; i < 20; i++ {
			key := fmt.Sprintf("pathElement%d", i)
			if assignment.PathElements[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("pathIndex%d", i)
			if assignment.PathIndices[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
		}
		return assignment, nil

	default:
		return nil, fmt.Errorf("unknown circuit: %s", circuitName)
	}
}

// NewArcnetService creates a new prover service with arcnet's circuits and witness factory.
// If keyDir is non-empty, keys are persisted to disk for fast restarts.
func NewArcnetService(keyDir string) (*Service, *KeyStore, error) {
	p := NewProver()

	log.Info().Msg("Registering standard circuits...")
	start := time.Now()

	var ks *KeyStore
	if keyDir != "" {
		var err error
		ks, err = NewKeyStore(keyDir)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create keystore: %w", err)
		}

		circuits := standardCircuits()
		if err := RegisterWithKeyStore(p, ks, circuits); err != nil {
			return nil, nil, fmt.Errorf("failed to register circuits: %w", err)
		}
	} else {
		if err := RegisterStandardCircuits(p); err != nil {
			return nil, nil, fmt.Errorf("failed to register circuits: %w", err)
		}
	}

	log.Info().
		Dur("elapsed", time.Since(start)).
		Int("circuits", len(p.ListCircuits())).
		Bool("cached", ks != nil).
		Msg("Circuits registered")

	return goprover.NewService(p, &ArcnetWitnessFactory{}), ks, nil
}

// standardCircuits returns the circuit definitions (without compiling them).
func standardCircuits() map[string]frontend.Circuit {
	return map[string]frontend.Circuit{
		"transfer":     &TransferCircuit{},
		"transferFrom": &TransferFromCircuit{},
		"mint":         &MintCircuit{},
		"burn":         &BurnCircuit{},
		"approve":      &ApproveCircuit{},
		"vestClaim":    &VestingClaimCircuit{},
		"voteCast":     &VoteCastCircuit{},
	}
}
