package arc

import (
	"github.com/stackdump/bitwrap-io/internal/metamodel/guard"
	"github.com/stackdump/bitwrap-io/internal/petri"
)

// Marking represents the current token state of all places.
// Deprecated: Use petri.Marking from metamodel/petri package.
type Marking = petri.Marking

// Bindings represent variable bindings for colored/parameterized transitions.
// Deprecated: Use petri.Bindings from metamodel/petri package.
type Bindings = petri.Bindings

// State holds the runtime state of a Petri net execution.
// Deprecated: Use petri.State from metamodel/petri package.
type State = petri.State

// InvariantViolation describes a failed invariant check.
// Deprecated: Use petri.InvariantViolation from metamodel/petri package.
type InvariantViolation = petri.InvariantViolation

// NewState creates a new execution state from a model.
// Deprecated: Use petri.NewState from metamodel/petri package.
func NewState(m *Model) *State {
	return petri.NewState(m)
}

// GuardFunc is a custom function that can be called in guard expressions.
// Deprecated: Use guard.GuardFunc from metamodel/guard package.
type GuardFunc = guard.GuardFunc
