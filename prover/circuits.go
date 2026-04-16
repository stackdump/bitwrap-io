package prover

import (
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

// Hand-written gnark circuits retired in slice 2.6 cutover. Every circuit
// now lives in prover/*_gen.go, generated from the ERC schemas in erc/.
// This file keeps only the registration machinery that the service and
// tests rely on. The MiMC helper used by generated code is in
// prover/synth_runtime.go.

// RegisterStandardCircuits registers all generated ZK circuits with the
// prover. Each circuit name matches its schema action ID so the witness
// factory in prover/service.go can dispatch by the same key.
func RegisterStandardCircuits(p *Prover) error {
	circuits := map[string]frontend.Circuit{
		"transfer":       &TransferCircuit{},
		"transferFrom":   &TransferFromCircuit{},
		"mint":           &MintCircuit{},
		"burn":           &BurnCircuit{},
		"approve":        &ApproveCircuit{},
		"vestClaim":      &VestingClaimCircuit{},
		"voteCast":       &VoteCastCircuit{},
		"tallyProof":     &TallyProofCircuit16{}, // legacy alias, kept for back-compat
		"tallyProof_16":  &TallyProofCircuit16{},
		"tallyProof_64":  &TallyProofCircuit64{},
	}
	// tallyProof_256 is lazy: ~30-60s compile + hundreds of MB of keys.
	// Most polls don't need it; server starts without it and pays the cost
	// on first request from a poll that does.
	RegisterLazyCircuit("tallyProof_256", func() frontend.Circuit { return &TallyProofCircuit256{} })
	return RegisterCircuitsParallel(p, circuits)
}

// RegisterCircuitsParallel compiles and registers multiple circuits
// concurrently. Significantly speeds up startup.
func RegisterCircuitsParallel(p *Prover, circuits map[string]frontend.Circuit) error {
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

	if err := g.Wait(); err != nil {
		return err
	}

	for _, r := range results {
		p.StoreCircuit(r.name, r.cc)
	}
	return nil
}
