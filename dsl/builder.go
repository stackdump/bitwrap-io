package dsl

import (
	"fmt"
	"strings"

	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// Build converts a parsed DSL AST into a *metamodel.Schema.
func Build(ast *Schema) (*metamodel.Schema, error) {
	s := metamodel.NewSchema(ast.Name)
	s.Version = ast.Version

	// Build initial value lookup for registers
	initials := make(map[string]InitialValue)
	for _, iv := range ast.InitialState {
		initials[iv.Place] = iv
	}

	// Convert registers to States
	for _, reg := range ast.Registers {
		kind := metamodel.DataState
		if isScalarType(reg.Type) {
			kind = metamodel.TokenState
		}

		st := metamodel.State{
			ID:       reg.Name,
			Kind:     kind,
			Type:     reg.Type,
			Exported: reg.Observable,
		}

		// Apply initial value if present
		if iv, ok := initials[reg.Name]; ok {
			if iv.IsMap {
				m := make(map[string]any, len(iv.MapValue))
				for k, v := range iv.MapValue {
					m[k] = v
				}
				st.Initial = m
			} else {
				st.Initial = iv.Scalar
			}
		}

		s.AddState(st)
	}

	// Convert events
	for _, evt := range ast.Events {
		params := make([]metamodel.EventParameter, len(evt.Fields))
		for i, f := range evt.Fields {
			params[i] = metamodel.EventParameter{
				Name:    f.Name,
				Type:    f.Type,
				Indexed: f.Indexed,
			}
		}
		s.AddEvent(metamodel.Event{
			ID:         evt.Name,
			Parameters: params,
		})
	}

	// Convert functions to Actions and Arcs
	for _, fn := range ast.Functions {
		action := metamodel.Action{
			ID:      fn.Name,
			Guard:   fn.Require,
			EventID: fn.EventRef,
		}
		s.AddAction(action)

		// Convert arcs
		for _, arc := range fn.Arcs {
			mArc, err := buildArc(fn.Name, arc)
			if err != nil {
				return nil, fmt.Errorf("function %s: %w", fn.Name, err)
			}
			s.AddArc(mArc)
		}
	}

	return s, nil
}

// buildArc converts a DSL Arc into a metamodel.Arc.
// The function name determines direction:
//   - PLACE -|w|> fnName  =>  input arc (Source=PLACE, Target=fnName)
//   - fnName -|w|> PLACE  =>  output arc (Source=fnName, Target=PLACE)
func buildArc(fnName string, a Arc) (metamodel.Arc, error) {
	arc := metamodel.Arc{
		Source: a.Source,
		Target: a.Target,
		Value:  a.Weight,
	}

	// Determine which side has the indices (the place side)
	if a.Source == fnName {
		// output arc: fnName -|w|> PLACE[idx1][idx2]
		if len(a.TargetIndices) > 0 {
			arc.Keys = a.TargetIndices
		}
	} else if a.Target == fnName {
		// input arc: PLACE[idx1][idx2] -|w|> fnName
		if len(a.SourceIndices) > 0 {
			arc.Keys = a.SourceIndices
		}
	} else {
		return metamodel.Arc{}, fmt.Errorf("arc %s -|%s|> %s does not reference function %s",
			a.Source, a.Weight, a.Target, fnName)
	}

	return arc, nil
}

// isScalarType returns true for simple numeric types (no map prefix).
func isScalarType(t string) bool {
	return !strings.HasPrefix(t, "map[")
}
