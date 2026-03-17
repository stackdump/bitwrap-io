// Package erc implements ERC token standard templates as metamodels.
// Each token standard is expressed as an explicit, verifiable metamodel schema.
package erc

import (
	"github.com/bitwrap-io/bitwrap/internal/arc"
	"github.com/bitwrap-io/bitwrap/internal/metamodel"
)

// Standard identifies a token standard type.
type Standard string

const (
	StandardERC020   Standard = "ERC-020"
	StandardERC0721  Standard = "ERC-0721"
	StandardERC01155 Standard = "ERC-01155"
	StandardERC04626 Standard = "ERC-04626"
	StandardERC05725 Standard = "ERC-05725"
	StandardBridge   Standard = "Bridge"
)

// TokenMetadata holds common token metadata.
type TokenMetadata struct {
	Name     string   `json:"name"`
	Symbol   string   `json:"symbol"`
	Decimals uint8    `json:"decimals,omitempty"`
	Standard Standard `json:"standard"`
}

// Template defines the interface for token standard templates.
type Template interface {
	Schema() *metamodel.Schema
	Model() *arc.Model
	Metadata() TokenMetadata
	Standard() Standard
}

// BaseTemplate provides common template functionality.
type BaseTemplate struct {
	schema   *metamodel.Schema
	model    *arc.Model
	metadata TokenMetadata
	standard Standard
}

func (t *BaseTemplate) Schema() *metamodel.Schema { return t.schema }
func (t *BaseTemplate) Model() *arc.Model          { return t.model }
func (t *BaseTemplate) Metadata() TokenMetadata     { return t.metadata }
func (t *BaseTemplate) Standard() Standard          { return t.standard }
