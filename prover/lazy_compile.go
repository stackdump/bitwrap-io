package prover

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

// lazyCircuits is the set of circuits we know how to compile on demand
// but deliberately DON'T compile at startup — they're expensive enough
// that paying the cost up front is worse than letting the first request
// wait. tallyProof_256 is the canonical example (~30-60s + large keys).
var lazyCircuits = map[string]func() frontend.Circuit{}

// lazyMu serializes concurrent EnsureCompiled calls for the same circuit
// so N simultaneous requests don't each trigger a full compile+setup.
var lazyMu sync.Mutex

// RegisterLazyCircuit registers a circuit factory that EnsureCompiled can
// instantiate on first use. Callers should not use the Prover's standard
// registration path for lazy circuits — use this instead.
func RegisterLazyCircuit(name string, factory func() frontend.Circuit) {
	lazyCircuits[name] = factory
}

// EnsureCompiled returns the compiled circuit for `name`, compiling it on
// demand if it was registered as a lazy circuit. No-op if the circuit is
// already compiled and stored. Safe to call concurrently.
func EnsureCompiled(p *Prover, name string) (*CompiledCircuit, error) {
	if cc, ok := p.GetCircuit(name); ok {
		return cc, nil
	}

	lazyMu.Lock()
	defer lazyMu.Unlock()

	// Re-check under the lock in case another goroutine beat us here.
	if cc, ok := p.GetCircuit(name); ok {
		return cc, nil
	}

	factory, ok := lazyCircuits[name]
	if !ok {
		return nil, fmt.Errorf("circuit %q not registered (neither eager nor lazy)", name)
	}

	log.Info().Str("circuit", name).Msg("lazy-compiling circuit (first use)...")
	cc, err := p.CompileCircuit(name, factory())
	if err != nil {
		return nil, fmt.Errorf("lazy compile %q: %w", name, err)
	}
	p.StoreCircuit(name, cc)
	log.Info().
		Str("circuit", name).
		Int("constraints", cc.Constraints).
		Msg("lazy-compile complete")
	return cc, nil
}
