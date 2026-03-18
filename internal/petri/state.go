package petri

// Marking represents the current token state of all places.
type Marking map[string]int

// Clone creates a deep copy of the marking.
func (m Marking) Clone() Marking {
	clone := make(Marking)
	for k, v := range m {
		clone[k] = v
	}
	return clone
}

// Bindings represent variable bindings for colored/parameterized transitions.
type Bindings map[string]interface{}

// State holds the runtime state of a Petri net execution.
type State struct {
	Model    *Model
	Marking  Marking
	Sequence uint64
}

// NewState creates a new execution state from a model.
func NewState(m *Model) *State {
	marking := make(Marking)
	for _, p := range m.Places {
		marking[p.ID] = p.Initial
	}
	return &State{
		Model:    m,
		Marking:  marking,
		Sequence: 0,
	}
}

// Clone creates a deep copy of the state.
func (s *State) Clone() *State {
	marking := make(Marking)
	for k, v := range s.Marking {
		marking[k] = v
	}
	return &State{
		Model:    s.Model,
		Marking:  marking,
		Sequence: s.Sequence,
	}
}

// Tokens returns the token count at a place.
func (s *State) Tokens(placeID string) int {
	return s.Marking[placeID]
}

// SetTokens sets the token count at a place.
func (s *State) SetTokens(placeID string, count int) {
	s.Marking[placeID] = count
}

// Enabled returns true if a transition can fire.
// Simplified: checks all input arcs have tokens >= 1 (skips keyed arcs).
func (s *State) Enabled(transitionID string) bool {
	t := s.Model.TransitionByID(transitionID)
	if t == nil {
		return false
	}

	for _, arc := range s.Model.InputArcs(transitionID) {
		if len(arc.Keys) > 0 {
			continue
		}
		if s.Marking[arc.Source] < 1 {
			return false
		}
	}

	return true
}

// EnabledTransitions returns all transitions that can fire.
func (s *State) EnabledTransitions() []string {
	var enabled []string
	for _, t := range s.Model.Transitions {
		if s.Enabled(t.ID) {
			enabled = append(enabled, t.ID)
		}
	}
	return enabled
}

// Fire executes a transition, consuming and producing tokens.
func (s *State) Fire(transitionID string) error {
	if !s.Enabled(transitionID) {
		return ErrTransitionNotEnabled
	}

	// Consume tokens from input places (all arcs have weight 1)
	// Skip keyed arcs - their state is managed by the engine layer
	for _, arc := range s.Model.InputArcs(transitionID) {
		if len(arc.Keys) > 0 {
			continue
		}
		s.Marking[arc.Source]--
	}

	// Produce tokens at output places
	// Skip keyed arcs - their state is managed by the engine layer
	for _, arc := range s.Model.OutputArcs(transitionID) {
		if len(arc.Keys) > 0 {
			continue
		}
		s.Marking[arc.Target]++
	}

	s.Sequence++

	return nil
}

// CanReach returns true if the target marking is reachable from current state.
// This is a simple BFS; complex reachability requires more sophisticated analysis.
func (s *State) CanReach(target Marking, maxSteps int) bool {
	visited := make(map[string]bool)
	queue := []*State{s.Clone()}

	for len(queue) > 0 && maxSteps > 0 {
		current := queue[0]
		queue = queue[1:]
		maxSteps--

		key := current.markingKey()
		if visited[key] {
			continue
		}
		visited[key] = true

		if current.matchesMarking(target) {
			return true
		}

		for _, tid := range current.EnabledTransitions() {
			next := current.Clone()
			next.Fire(tid)
			queue = append(queue, next)
		}
	}

	return false
}

func (s *State) markingKey() string {
	// Simple serialization for visited set
	result := ""
	for _, p := range s.Model.Places {
		result += p.ID + ":" + string(rune(s.Marking[p.ID])) + ";"
	}
	return result
}

func (s *State) matchesMarking(target Marking) bool {
	for k, v := range target {
		if s.Marking[k] != v {
			return false
		}
	}
	return true
}
