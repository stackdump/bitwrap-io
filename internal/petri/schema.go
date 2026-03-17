package petri

import "encoding/json"

// FromJSON parses a Petri net model from JSON bytes.
func FromJSON(data []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ToJSON serializes a Petri net model to JSON bytes.
func ToJSON(m *Model) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
