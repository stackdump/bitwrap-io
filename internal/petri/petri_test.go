package petri

import (
	"testing"
)

func TestNewModel(t *testing.T) {
	m := NewModel("test")
	if m.Name != "test" {
		t.Fatalf("expected name=test, got %s", m.Name)
	}
	if len(m.Places) != 0 {
		t.Fatal("new model should have no places")
	}
}

func TestAddElements(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 3})
	m.AddPlace(Place{ID: "p1", Initial: 0})
	m.AddTransition(Transition{ID: "t0"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})
	m.AddArc(Arc{Source: "t0", Target: "p1"})

	if len(m.Places) != 2 {
		t.Fatalf("expected 2 places, got %d", len(m.Places))
	}
	if len(m.Transitions) != 1 {
		t.Fatalf("expected 1 transition, got %d", len(m.Transitions))
	}
	if len(m.Arcs) != 2 {
		t.Fatalf("expected 2 arcs, got %d", len(m.Arcs))
	}
}

func TestValidate(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0"})
	m.AddTransition(Transition{ID: "t0"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})
	if err := m.Validate(); err != nil {
		t.Fatalf("valid model failed validation: %v", err)
	}
}

func TestValidateDuplicateID(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0"})
	m.AddPlace(Place{ID: "p0"})
	if err := m.Validate(); err != ErrDuplicateID {
		t.Fatalf("expected ErrDuplicateID, got %v", err)
	}
}

func TestValidateInvalidArc(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0"})
	m.AddArc(Arc{Source: "p0", Target: "missing"})
	if err := m.Validate(); err != ErrInvalidArcTarget {
		t.Fatalf("expected ErrInvalidArcTarget, got %v", err)
	}
}

func TestValidatePlaceToPlace(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0"})
	m.AddPlace(Place{ID: "p1"})
	m.AddArc(Arc{Source: "p0", Target: "p1"})
	if err := m.Validate(); err != ErrInvalidArcConnection {
		t.Fatalf("expected ErrInvalidArcConnection, got %v", err)
	}
}

func TestFireSimple(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 1})
	m.AddPlace(Place{ID: "p1", Initial: 0})
	m.AddTransition(Transition{ID: "t0"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})
	m.AddArc(Arc{Source: "t0", Target: "p1"})

	s := NewState(m)
	if s.Tokens("p0") != 1 || s.Tokens("p1") != 0 {
		t.Fatal("wrong initial state")
	}

	if !s.Enabled("t0") {
		t.Fatal("t0 should be enabled")
	}

	if err := s.Fire("t0"); err != nil {
		t.Fatalf("fire failed: %v", err)
	}

	if s.Tokens("p0") != 0 || s.Tokens("p1") != 1 {
		t.Fatalf("wrong state after fire: p0=%d p1=%d", s.Tokens("p0"), s.Tokens("p1"))
	}

	if s.Enabled("t0") {
		t.Fatal("t0 should not be enabled (no tokens in p0)")
	}
}

func TestFireNotEnabled(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 0})
	m.AddTransition(Transition{ID: "t0"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})

	s := NewState(m)
	if err := s.Fire("t0"); err != ErrTransitionNotEnabled {
		t.Fatalf("expected ErrTransitionNotEnabled, got %v", err)
	}
}

func TestEnabledTransitions(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 1})
	m.AddPlace(Place{ID: "p1", Initial: 0})
	m.AddTransition(Transition{ID: "t0"})
	m.AddTransition(Transition{ID: "t1"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})
	m.AddArc(Arc{Source: "p1", Target: "t1"})

	s := NewState(m)
	enabled := s.EnabledTransitions()
	if len(enabled) != 1 || enabled[0] != "t0" {
		t.Fatalf("expected [t0], got %v", enabled)
	}
}

func TestCloneState(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 5})
	s := NewState(m)
	clone := s.Clone()
	clone.SetTokens("p0", 0)
	if s.Tokens("p0") != 5 {
		t.Fatal("clone modified original")
	}
}

func TestSequence(t *testing.T) {
	m := NewModel("test")
	m.AddPlace(Place{ID: "p0", Initial: 3})
	m.AddPlace(Place{ID: "p1", Initial: 0})
	m.AddTransition(Transition{ID: "t0"})
	m.AddArc(Arc{Source: "p0", Target: "t0"})
	m.AddArc(Arc{Source: "t0", Target: "p1"})

	s := NewState(m)
	s.Fire("t0")
	s.Fire("t0")
	if s.Sequence != 2 {
		t.Fatalf("expected sequence=2, got %d", s.Sequence)
	}
}

func TestFromJSON(t *testing.T) {
	data := `{"name":"test","places":[{"id":"p0","initial":1}],"transitions":[{"id":"t0"}],"arcs":[{"source":"p0","target":"t0"}]}`
	m, err := FromJSON([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "test" {
		t.Fatalf("expected name=test, got %s", m.Name)
	}
	if len(m.Places) != 1 {
		t.Fatalf("expected 1 place, got %d", len(m.Places))
	}
}
