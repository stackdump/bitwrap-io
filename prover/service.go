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

	case "mint":
		assignment := &MintCircuit{}
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
		if assignment.To, err = goprover.ParseWitnessField(witness, "to"); err != nil {
			return nil, err
		}
		if assignment.Amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if assignment.Minter, err = goprover.ParseWitnessField(witness, "minter"); err != nil {
			return nil, err
		}
		if assignment.BalanceTo, err = goprover.ParseWitnessField(witness, "balanceTo"); err != nil {
			return nil, err
		}
		return assignment, nil

	case "burn":
		assignment := &BurnCircuit{}
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
		if assignment.Amount, err = goprover.ParseWitnessField(witness, "amount"); err != nil {
			return nil, err
		}
		if assignment.BalanceFrom, err = goprover.ParseWitnessField(witness, "balanceFrom"); err != nil {
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

	default:
		return nil, fmt.Errorf("unknown circuit: %s", circuitName)
	}
}

// NewArcnetService creates a new prover service with arcnet's circuits and witness factory.
func NewArcnetService() (*Service, error) {
	p := NewProver()

	log.Info().Msg("Registering standard circuits...")
	start := time.Now()

	if err := RegisterStandardCircuits(p); err != nil {
		return nil, fmt.Errorf("failed to register circuits: %w", err)
	}

	log.Info().
		Dur("elapsed", time.Since(start)).
		Int("circuits", len(p.ListCircuits())).
		Msg("Circuits registered")

	return goprover.NewService(p, &ArcnetWitnessFactory{}), nil
}
