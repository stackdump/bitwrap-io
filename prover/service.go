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
	case "transfer":
		assignment := &TransferCircuit{}
		var err error
		if assignment.PreStateRoot, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if assignment.PostStateRoot, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if assignment.From, err = goprover.ParseWitnessField(witness, "from"); err != nil {
			return nil, err
		}
		if assignment.To, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if assignment.Amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if assignment.BalanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
			return nil, err
		}
		if assignment.BalanceTo, err = goprover.ParseWitnessField(witness, "balanceTo"); err != nil {
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

	case "approve":
		assignment := &ApproveCircuit{}
		var err error
		if assignment.PreStateRoot, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if assignment.PostStateRoot, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if assignment.Caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if assignment.Spender, err = goprover.ParseWitnessField(witness, "spender"); err != nil {
			return nil, err
		}
		if assignment.Amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if assignment.Owner, err = goprover.ParseWitnessField(witness, "owner"); err != nil {
			return nil, err
		}
		return assignment, nil

	case "transferFrom":
		assignment := &TransferFromCircuit{}
		var err error
		if assignment.PreStateRoot, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if assignment.PostStateRoot, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if assignment.From, err = goprover.ParseWitnessField(witness, "from"); err != nil {
			return nil, err
		}
		if assignment.To, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if assignment.Caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if assignment.Amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if assignment.BalanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
			return nil, err
		}
		if assignment.AllowanceFrom, err = goprover.ParseWitnessField(witness, "allowanceFrom"); err != nil {
			return nil, err
		}
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("balancePath%d", i)
			if assignment.BalancePath[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("balanceIndex%d", i)
			if assignment.BalanceIndices[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("allowancePath%d", i)
			if assignment.AllowancePath[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("allowanceIndex%d", i)
			if assignment.AllowanceIdx[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
		}
		return assignment, nil

	case "vestClaim":
		assignment := &VestingClaimCircuit{}
		var err error
		if assignment.PreStateRoot, err = goprover.ParseWitnessField(witness, "preStateRoot"); err != nil {
			return nil, err
		}
		if assignment.PostStateRoot, err = goprover.ParseWitnessField(witness, "postStateRoot"); err != nil {
			return nil, err
		}
		if assignment.TokenID, err = goprover.ParseWitnessField(witness, "tokenID"); err != nil {
			return nil, err
		}
		if assignment.Caller, err = goprover.ParseWitnessField(witness, "caller"); err != nil {
			return nil, err
		}
		if assignment.ClaimAmount, err = goprover.ParseWitnessField(witness, "claimAmount"); err != nil {
			return nil, err
		}
		if assignment.VestedAmount, err = goprover.ParseWitnessField(witness, "vestedAmount"); err != nil {
			return nil, err
		}
		if assignment.Claimed, err = goprover.ParseWitnessField(witness, "claimed"); err != nil {
			return nil, err
		}
		if assignment.Owner, err = goprover.ParseWitnessField(witness, "owner"); err != nil {
			return nil, err
		}
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("schedulePath%d", i)
			if assignment.SchedulePath[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("scheduleIndex%d", i)
			if assignment.ScheduleIndices[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("ownerPath%d", i)
			if assignment.OwnerPath[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
			key = fmt.Sprintf("ownerIndex%d", i)
			if assignment.OwnerIndices[i], err = goprover.ParseWitnessField(witness, key); err != nil {
				return nil, err
			}
		}
		return assignment, nil

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
