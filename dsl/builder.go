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

	// Validate the built schema
	if err := validate(ast, s); err != nil {
		return nil, err
	}

	return s, nil
}

// validate checks the DSL AST and built schema for common errors.
func validate(ast *Schema, s *metamodel.Schema) error {
	// Build lookup tables
	registers := make(map[string]Register)
	for _, r := range ast.Registers {
		registers[r.Name] = r
	}

	fnVars := make(map[string]map[string]bool) // fn name → var names
	for _, fn := range ast.Functions {
		vars := make(map[string]bool)
		for _, v := range fn.Vars {
			vars[v.Name] = true
		}
		fnVars[fn.Name] = vars
	}

	// 1. Duplicate detection
	{
		seen := make(map[string]string) // name → kind
		for _, r := range ast.Registers {
			if prev, ok := seen[r.Name]; ok {
				return fmt.Errorf("duplicate name %q (already declared as %s)", r.Name, prev)
			}
			seen[r.Name] = "register"
		}
		for _, e := range ast.Events {
			if prev, ok := seen[e.Name]; ok {
				return fmt.Errorf("duplicate name %q (already declared as %s)", e.Name, prev)
			}
			seen[e.Name] = "event"
		}
		for _, f := range ast.Functions {
			if prev, ok := seen[f.Name]; ok {
				return fmt.Errorf("duplicate name %q (already declared as %s)", f.Name, prev)
			}
			seen[f.Name] = "function"
		}
	}

	// 2. Reserved name checking
	if err := checkReservedName(ast.Name, "schema"); err != nil {
		return err
	}
	for _, r := range ast.Registers {
		if err := checkReservedName(r.Name, "register"); err != nil {
			return err
		}
	}
	for _, f := range ast.Functions {
		if err := checkReservedName(f.Name, "function"); err != nil {
			return err
		}
	}

	// 3. Arc type checking
	for _, fn := range ast.Functions {
		for _, arc := range fn.Arcs {
			// Determine the place side (not the function side)
			placeName := arc.Source
			indices := arc.SourceIndices
			if arc.Source == fn.Name {
				placeName = arc.Target
				indices = arc.TargetIndices
			}

			reg, ok := registers[placeName]
			if !ok {
				// Arc references a non-existent register
				return fmt.Errorf("function %s: arc references unknown register %q", fn.Name, placeName)
			}

			mapDepth := mapKeyDepth(reg.Type)
			indexCount := len(indices)

			if mapDepth == 0 && indexCount > 0 {
				return fmt.Errorf("function %s: register %s is %s (scalar), cannot index with [%s]",
					fn.Name, reg.Name, reg.Type, strings.Join(indices, "]["))
			}

			if indexCount > 0 && indexCount != mapDepth {
				return fmt.Errorf("function %s: register %s needs %d index key(s) (type %s), got %d",
					fn.Name, reg.Name, mapDepth, reg.Type, indexCount)
			}
		}
	}

	// 4. Guard variable validation
	for _, fn := range ast.Functions {
		if fn.Require == "" {
			continue
		}
		vars := fnVars[fn.Name]
		if err := validateGuardIdents(fn.Name, fn.Require, registers, vars); err != nil {
			return err
		}
	}

	// 5. Event reference validation
	eventNames := make(map[string]bool)
	for _, e := range ast.Events {
		eventNames[e.Name] = true
	}
	for _, fn := range ast.Functions {
		if fn.EventRef != "" && !eventNames[fn.EventRef] {
			return fmt.Errorf("function %s: @event references undeclared event %q", fn.Name, fn.EventRef)
		}
	}

	return nil
}

// checkReservedName returns an error if the name conflicts with Solidity or Foundry.
func checkReservedName(name, kind string) error {
	reserved := map[string]string{
		// Solidity keywords
		"function": "Solidity keyword", "event": "Solidity keyword",
		"mapping": "Solidity keyword", "constructor": "Solidity keyword",
		"require": "Solidity keyword", "revert": "Solidity keyword",
		"assert": "Solidity keyword", "return": "Solidity keyword",
		"if": "Solidity keyword", "else": "Solidity keyword",
		"for": "Solidity keyword", "while": "Solidity keyword",
		"true": "Solidity keyword", "false": "Solidity keyword",
		// Solidity built-in variables
		"msg": "Solidity built-in", "block": "Solidity built-in",
		"tx": "Solidity built-in", "this": "Solidity built-in",
		// Forge-std conflicts
		"Test": "forge-std class", "Script": "forge-std class",
		"Vm": "forge-std class", "console": "forge-std class",
		// Generated contract internals
		"contractOwner": "generated internal", "currentEpoch": "generated internal",
		"eventSequence": "generated internal",
	}
	if reason, ok := reserved[name]; ok {
		return fmt.Errorf("%s name %q conflicts with %s", kind, name, reason)
	}
	return nil
}

// mapKeyDepth returns the nesting depth of a map type.
// "uint256" → 0, "map[address]uint256" → 1, "map[address]map[address]uint256" → 2
func mapKeyDepth(typ string) int {
	depth := 0
	remaining := typ
	for strings.HasPrefix(remaining, "map[") {
		close := strings.Index(remaining, "]")
		if close == -1 {
			break
		}
		depth++
		remaining = remaining[close+1:]
	}
	return depth
}

// validateGuardIdents checks that all identifiers in a guard expression
// are known registers, function variables, or built-in names.
func validateGuardIdents(fnName, guard string, registers map[string]Register, vars map[string]bool) error {
	// Extract identifiers from the guard using simple scanning
	// (avoid importing guard package to prevent circular deps)
	idents := extractIdents(guard)

	builtins := map[string]bool{
		"caller": true, "address": true, "true": true, "false": true,
		"msg": true, "sender": true, // for msg.sender
	}

	for _, id := range idents {
		if builtins[id] {
			continue
		}
		if _, ok := registers[id]; ok {
			continue
		}
		if vars[id] {
			continue
		}
		// Allow numeric literals
		if isNumeric(id) {
			continue
		}
		// Allow known function-like calls (vestedAmount, etc.)
		// These are generated helper functions, not user-defined
		if strings.Contains(guard, id+"(") {
			continue
		}
		return fmt.Errorf("function %s: guard references unknown identifier %q", fnName, id)
	}
	return nil
}

// extractIdents returns all identifier-like tokens from an expression string.
func extractIdents(expr string) []string {
	var idents []string
	i := 0
	for i < len(expr) {
		if isLetter(expr[i]) || expr[i] == '_' {
			start := i
			for i < len(expr) && (isLetter(expr[i]) || isDigit(expr[i]) || expr[i] == '_' || expr[i] == '.') {
				i++
			}
			idents = append(idents, expr[start:i])
		} else {
			i++
		}
	}
	return idents
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
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
