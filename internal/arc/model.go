// Package arc implements Petri net primitives with cryptographic identity.
// This is the "arc" in arcnet - the core wiring and flow semantics.
//
// Deprecated: Use github.com/stackdump/bitwrap-io/internal/petri instead.
// This package re-exports types for backward compatibility.
package arc

import "github.com/stackdump/bitwrap-io/internal/petri"

// Place represents a state container in the Petri net.
// Deprecated: Use petri.Place from metamodel/petri package.
type Place = petri.Place

// Transition represents a state change operation.
// Deprecated: Use petri.Transition from metamodel/petri package.
type Transition = petri.Transition

// Arc connects places and transitions, defining token flow.
// Deprecated: Use petri.Arc from metamodel/petri package.
type Arc = petri.Arc

// Invariant represents a property that must hold across all markings.
// Deprecated: Use petri.Invariant from metamodel/petri package.
type Invariant = petri.Invariant

// Model is a complete Petri net definition with cryptographic identity.
// Deprecated: Use petri.Model from metamodel/petri package.
type Model = petri.Model

// NewModel creates a new empty model.
// Deprecated: Use petri.NewModel from metamodel/petri package.
func NewModel(name string) *Model {
	return petri.NewModel(name)
}
