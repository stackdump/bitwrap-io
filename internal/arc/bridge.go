package arc

import (
	"github.com/bitwrap-io/bitwrap/internal/metamodel"
	"github.com/bitwrap-io/bitwrap/internal/petri"
)

// Type aliases for backward compatibility.
// These allow existing code to use Petri net terminology while
// the underlying implementation uses metamodel types.
//
// Deprecated: Use types from metamodel package directly.

// PlaceAlias is a type alias for metamodel.State (Petri net terminology).
type PlaceAlias = metamodel.State

// TransitionAlias is a type alias for metamodel.Action (Petri net terminology).
type TransitionAlias = metamodel.Action

// ArcAlias is a type alias for metamodel.Arc (same name, kept for completeness).
type ArcAlias = metamodel.Arc

// InvariantAlias is a type alias for metamodel.Constraint (Petri net terminology).
type InvariantAlias = metamodel.Constraint

// SchemaAlias is a type alias for metamodel.Schema.
type SchemaAlias = metamodel.Schema

// ToSchema converts a Petri net Model to a metamodel Schema.
// This method is available on Model via the petri.Model type alias.
// Deprecated: Use petri.Model.ToSchema() from metamodel/petri package.

// FromSchema creates a Petri net Model from a metamodel Schema.
// Deprecated: Use petri.FromSchema from metamodel/petri package.
func FromSchema(s *metamodel.Schema) *Model {
	return petri.FromSchema(s)
}

// StateToPlace converts a metamodel.State to a Petri net Place.
// Deprecated: Use petri.StateToPlace from metamodel/petri package.
func StateToPlace(st metamodel.State) Place {
	return petri.StateToPlace(st)
}

// PlaceToState converts a Petri net Place to a metamodel.State.
// Deprecated: Use petri.PlaceToState from metamodel/petri package.
func PlaceToState(p Place) metamodel.State {
	return petri.PlaceToState(p)
}

// ActionToTransition converts a metamodel.Action to a Petri net Transition.
// Deprecated: Use petri.ActionToTransition from metamodel/petri package.
func ActionToTransition(a metamodel.Action) Transition {
	return petri.ActionToTransition(a)
}

// TransitionToAction converts a Petri net Transition to a metamodel.Action.
// Deprecated: Use petri.TransitionToAction from metamodel/petri package.
func TransitionToAction(t Transition) metamodel.Action {
	return petri.TransitionToAction(t)
}

// ConstraintToInvariant converts a metamodel.Constraint to a Petri net Invariant.
// Deprecated: Use petri.ConstraintToInvariant from metamodel/petri package.
func ConstraintToInvariant(c metamodel.Constraint) Invariant {
	return petri.ConstraintToInvariant(c)
}

// InvariantToConstraint converts a Petri net Invariant to a metamodel.Constraint.
// Deprecated: Use petri.InvariantToConstraint from metamodel/petri package.
func InvariantToConstraint(inv Invariant) metamodel.Constraint {
	return petri.InvariantToConstraint(inv)
}
