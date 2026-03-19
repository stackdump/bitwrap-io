package server

import (
	"github.com/stackdump/bitwrap-io/erc"
	"github.com/stackdump/bitwrap-io/internal/metamodel"
)

// PollEvent represents a single action fired on a poll's Petri net state machine.
type PollEvent struct {
	Action   string            `json:"action"`
	Bindings map[string]string `json:"bindings,omitempty"`
}

// PollRuntime creates a fresh metamodel.Runtime from the vote schema
// and replays events to derive current state.
// This is the event sourcing pattern: State(t) = fold(apply, initialState, events[0..t])
func PollRuntime(events []PollEvent) *metamodel.Runtime {
	vote := erc.NewVote("ZKPoll")
	rt := metamodel.NewRuntime(vote.Schema())
	rt.CheckConstraints = false // guards checked at API level

	for _, ev := range events {
		bindings := make(metamodel.Bindings)
		for k, v := range ev.Bindings {
			bindings[k] = v
		}
		_ = rt.ExecuteWithBindings(ev.Action, bindings)
	}

	return rt
}

// PollTallies extracts the current tallies from a runtime snapshot.
func PollTallies(rt *metamodel.Runtime, choiceCount int) []int64 {
	tallies := make([]int64, choiceCount)
	dataMap := rt.DataMap("tallies")
	if dataMap == nil {
		return tallies
	}
	for i := range tallies {
		key := intToString(i)
		tallies[i] = mapInt64(dataMap, key)
	}
	return tallies
}

// PollConfig extracts the poll lifecycle state from a runtime snapshot.
// 0=pending, 1=active, 2=closed
func PollConfig(rt *metamodel.Runtime) int64 {
	dataMap := rt.DataMap("pollConfig")
	if dataMap == nil {
		return 0
	}
	// pollConfig is a simple uint256, stored as map with no keys
	// When there are no arcs to pollConfig, we track it via the event log
	return 0
}

func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}

func mapInt64(m map[string]any, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	default:
		return 0
	}
}
