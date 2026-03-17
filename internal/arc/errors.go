package arc

import "github.com/stackdump/bitwrap-io/internal/petri"

// Model validation errors
// Deprecated: Use errors from metamodel/petri package.
var (
	ErrEmptyID              = petri.ErrEmptyID
	ErrDuplicateID          = petri.ErrDuplicateID
	ErrInvalidArcSource     = petri.ErrInvalidArcSource
	ErrInvalidArcTarget     = petri.ErrInvalidArcTarget
	ErrInvalidArcConnection = petri.ErrInvalidArcConnection
)

// Firing errors
// Deprecated: Use errors from metamodel/petri package.
var (
	ErrTransitionNotFound   = petri.ErrTransitionNotFound
	ErrInsufficientTokens   = petri.ErrInsufficientTokens
	ErrGuardNotSatisfied    = petri.ErrGuardNotSatisfied
	ErrGuardEvaluation      = petri.ErrGuardEvaluation
	ErrTransitionNotEnabled = petri.ErrTransitionNotEnabled
)

// Invariant errors
// Deprecated: Use errors from metamodel/petri package.
var (
	ErrInvariantViolated   = petri.ErrInvariantViolated
	ErrInvariantEvaluation = petri.ErrInvariantEvaluation
)
