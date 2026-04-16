// Package dsl implements a parser and builder for the .btw Petri net schema DSL.
package dsl

// Schema is the top-level AST node representing a complete .btw file.
type Schema struct {
	Name         string
	Version      string
	Domain       string
	Asset        string
	Registers    []Register
	Events       []Event
	Functions    []Function
	InitialState []InitialValue
}

// Register declares a named state container with a type and optional observability.
type Register struct {
	Name       string // dotted name, e.g. "ASSETS.AVAILABLE"
	Type       string // e.g. "map[address]uint256", "uint256"
	Observable bool
}

// Event declares a named event with typed, optionally indexed fields.
type Event struct {
	Name   string
	Fields []EventField
}

// EventField is a single parameter in an event declaration.
type EventField struct {
	Name    string
	Type    string
	Indexed bool
}

// Function declares a named transition (action) with variables, a guard,
// an event reference, and arcs defining token/data flow.
type Function struct {
	Name     string
	Vars     []Var
	Require  string // raw guard expression string
	EventRef string // name of the linked event, from @event
	Roles    []string // role bindings declared via `requires <role>` — e.g. []string{"minter"}
	Arcs     []Arc
}

// Var is a local variable declaration inside a function.
type Var struct {
	Name string
	Type string
}

// Arc represents a directed, weighted connection between a place and a transition.
// The DSL syntax is: SOURCE -|WEIGHT|> TARGET
// When the function name is the source, it is an output arc (function produces tokens).
// When the function name is the target, it is an input arc (function consumes tokens).
type Arc struct {
	Source        string   // place or function name
	SourceIndices []string // index variables, e.g. ["owner","spender"] in ALLOWANCES[owner][spender]
	Target        string   // place or function name
	TargetIndices []string // index variables
	Weight        string   // weight expression, e.g. "amount"
}

// InitialValue assigns an initial value to a place.
// Value is either a scalar int (Scalar) or a map of string keys to int values (MapValue).
// Exactly one of Scalar/MapValue is set; use IsMap to distinguish.
type InitialValue struct {
	Place    string
	Scalar   int
	MapValue map[string]int
	IsMap    bool
}
