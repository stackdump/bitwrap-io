package dsl

import (
	"fmt"
	"strconv"
)

// Parser is a recursive-descent parser for .btw files.
type Parser struct {
	tokens []Token
	pos    int
}

// Parse parses .btw source text and returns the AST.
func Parse(source string) (*Schema, error) {
	lexer := NewLexer(source)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return nil, err
	}
	p := &Parser{tokens: tokens, pos: 0}
	return p.parseSchema()
}

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) advance() Token {
	t := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return t
}

func (p *Parser) expect(tt TokenType) (Token, error) {
	t := p.advance()
	if t.Type != tt {
		return t, fmt.Errorf("line %d: expected token type %d, got %d (%q)", t.Line, tt, t.Type, t.Value)
	}
	return t, nil
}

func (p *Parser) parseSchema() (*Schema, error) {
	if _, err := p.expect(TokenSchema); err != nil {
		return nil, err
	}
	nameToken, err := p.expect(TokenIdent)
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	schema := &Schema{Name: nameToken.Value}

	for p.peek().Type != TokenRBrace && p.peek().Type != TokenEOF {
		switch p.peek().Type {
		case TokenVersion:
			p.advance()
			tok, err := p.expect(TokenString)
			if err != nil {
				return nil, err
			}
			schema.Version = tok.Value

		case TokenDomain:
			p.advance()
			tok, err := p.expect(TokenString)
			if err != nil {
				return nil, err
			}
			schema.Domain = tok.Value

		case TokenAsset:
			p.advance()
			tok, err := p.expect(TokenString)
			if err != nil {
				return nil, err
			}
			schema.Asset = tok.Value

		case TokenInitialState:
			initVals, err := p.parseInitialState()
			if err != nil {
				return nil, err
			}
			schema.InitialState = initVals

		case TokenRegister:
			reg, err := p.parseRegister()
			if err != nil {
				return nil, err
			}
			schema.Registers = append(schema.Registers, reg)

		case TokenEvent:
			evt, err := p.parseEvent()
			if err != nil {
				return nil, err
			}
			schema.Events = append(schema.Events, evt)

		case TokenFn:
			fn, err := p.parseFunction()
			if err != nil {
				return nil, err
			}
			schema.Functions = append(schema.Functions, fn)

		default:
			t := p.peek()
			return nil, fmt.Errorf("line %d: unexpected token %q in schema body", t.Line, t.Value)
		}
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}
	return schema, nil
}

func (p *Parser) parseInitialState() ([]InitialValue, error) {
	p.advance() // consume initial_state
	if _, err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var vals []InitialValue
	for p.peek().Type != TokenRBrace && p.peek().Type != TokenEOF {
		nameTok, err := p.expect(TokenIdent)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TokenColon); err != nil {
			return nil, err
		}

		if p.peek().Type == TokenLBrace {
			// map value
			p.advance() // consume {
			m := make(map[string]int)
			for p.peek().Type != TokenRBrace && p.peek().Type != TokenEOF {
				keyTok, err := p.expect(TokenString)
				if err != nil {
					return nil, err
				}
				if _, err := p.expect(TokenColon); err != nil {
					return nil, err
				}
				numTok, err := p.expect(TokenNumber)
				if err != nil {
					return nil, err
				}
				n, _ := strconv.Atoi(numTok.Value)
				m[keyTok.Value] = n
			}
			if _, err := p.expect(TokenRBrace); err != nil {
				return nil, err
			}
			vals = append(vals, InitialValue{Place: nameTok.Value, MapValue: m, IsMap: true})
		} else {
			// scalar value
			numTok, err := p.expect(TokenNumber)
			if err != nil {
				return nil, err
			}
			n, _ := strconv.Atoi(numTok.Value)
			vals = append(vals, InitialValue{Place: nameTok.Value, Scalar: n})
		}
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}
	return vals, nil
}

func (p *Parser) parseRegister() (Register, error) {
	p.advance() // consume register
	nameTok, err := p.expect(TokenIdent)
	if err != nil {
		return Register{}, err
	}

	// Type: could be a simple ident like "uint256" or a compound like "map[address]uint256"
	typStr, err := p.parseTypeString()
	if err != nil {
		return Register{}, err
	}

	observable := false
	if p.peek().Type == TokenObservable {
		p.advance()
		observable = true
	}

	return Register{
		Name:       nameTok.Value,
		Type:       typStr,
		Observable: observable,
	}, nil
}

// parseTypeString reads a type like "uint256" or "map[address]uint256".
func (p *Parser) parseTypeString() (string, error) {
	tok := p.advance()
	if tok.Type != TokenIdent {
		return "", fmt.Errorf("line %d: expected type identifier, got %q", tok.Line, tok.Value)
	}

	// Check for map[...] type
	if tok.Value == "map" && p.peek().Type == TokenLBracket {
		result := "map"
		p.advance() // [
		keyTok, err := p.expect(TokenIdent)
		if err != nil {
			return "", err
		}
		if _, err := p.expect(TokenRBracket); err != nil {
			return "", err
		}
		valTok, err := p.expect(TokenIdent)
		if err != nil {
			return "", err
		}
		result += "[" + keyTok.Value + "]" + valTok.Value
		return result, nil
	}

	return tok.Value, nil
}

func (p *Parser) parseEvent() (Event, error) {
	p.advance() // consume event
	nameTok, err := p.expect(TokenIdent)
	if err != nil {
		return Event{}, err
	}
	if _, err := p.expect(TokenLBrace); err != nil {
		return Event{}, err
	}

	var fields []EventField
	for p.peek().Type != TokenRBrace && p.peek().Type != TokenEOF {
		fieldName, err := p.expect(TokenIdent)
		if err != nil {
			return Event{}, err
		}
		if _, err := p.expect(TokenColon); err != nil {
			return Event{}, err
		}
		fieldType, err := p.expect(TokenIdent)
		if err != nil {
			return Event{}, err
		}

		indexed := false
		if p.peek().Type == TokenIndexed {
			p.advance()
			indexed = true
		}

		fields = append(fields, EventField{
			Name:    fieldName.Value,
			Type:    fieldType.Value,
			Indexed: indexed,
		})
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return Event{}, err
	}

	return Event{Name: nameTok.Value, Fields: fields}, nil
}

func (p *Parser) parseFunction() (Function, error) {
	p.advance() // consume fn
	if _, err := p.expect(TokenLParen); err != nil {
		return Function{}, err
	}
	nameTok, err := p.expect(TokenIdent)
	if err != nil {
		return Function{}, err
	}
	if _, err := p.expect(TokenRParen); err != nil {
		return Function{}, err
	}
	if _, err := p.expect(TokenLBrace); err != nil {
		return Function{}, err
	}

	fn := Function{Name: nameTok.Value}

	for p.peek().Type != TokenRBrace && p.peek().Type != TokenEOF {
		switch p.peek().Type {
		case TokenVar:
			p.advance()
			vName, err := p.expect(TokenIdent)
			if err != nil {
				return Function{}, err
			}
			vType, err := p.expect(TokenIdent)
			if err != nil {
				return Function{}, err
			}
			fn.Vars = append(fn.Vars, Var{Name: vName.Value, Type: vType.Value})

		case TokenRequire:
			p.advance()
			expr, err := p.parseRequireExpr()
			if err != nil {
				return Function{}, err
			}
			fn.Require = expr

		case TokenAt:
			p.advance()
			if _, err := p.expect(TokenEvent); err != nil {
				return Function{}, err
			}
			evtName, err := p.expect(TokenIdent)
			if err != nil {
				return Function{}, err
			}
			fn.EventRef = evtName.Value

		default:
			// Try to parse an arc: IDENT[idx] -|w|> IDENT[idx]
			arc, err := p.parseArc()
			if err != nil {
				return Function{}, err
			}
			fn.Arcs = append(fn.Arcs, arc)
		}
	}

	if _, err := p.expect(TokenRBrace); err != nil {
		return Function{}, err
	}

	return fn, nil
}

// parseRequireExpr reads a require(...) expression and returns the inner expression string.
func (p *Parser) parseRequireExpr() (string, error) {
	if _, err := p.expect(TokenLParen); err != nil {
		return "", err
	}

	// Collect tokens until matching closing paren
	depth := 1
	var parts []string
	for depth > 0 && p.peek().Type != TokenEOF {
		t := p.peek()
		if t.Type == TokenLParen {
			depth++
		} else if t.Type == TokenRParen {
			depth--
			if depth == 0 {
				p.advance()
				break
			}
		}
		p.advance()

		// Reconstruct the expression string from tokens
		switch t.Type {
		case TokenIdent:
			parts = append(parts, t.Value)
		case TokenNumber:
			parts = append(parts, t.Value)
		case TokenString:
			parts = append(parts, `"`+t.Value+`"`)
		case TokenGE:
			parts = append(parts, ">=")
		case TokenGT:
			parts = append(parts, ">")
		case TokenLE:
			parts = append(parts, "<=")
		case TokenLT:
			parts = append(parts, "<")
		case TokenEQ:
			parts = append(parts, "==")
		case TokenNE:
			parts = append(parts, "!=")
		case TokenAnd:
			parts = append(parts, "&&")
		case TokenOr:
			parts = append(parts, "||")
		case TokenLBracket:
			parts = append(parts, "[")
		case TokenRBracket:
			parts = append(parts, "]")
		case TokenLParen:
			parts = append(parts, "(")
		case TokenRParen:
			parts = append(parts, ")")
		default:
			parts = append(parts, t.Value)
		}
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += " "
		}
		result += part
	}
	return result, nil
}

// parseArc parses: SOURCE -|WEIGHT|> TARGET
// where SOURCE and TARGET can be NAME or NAME[index].
func (p *Parser) parseArc() (Arc, error) {
	source, sourceIdx, err := p.parsePlaceRef()
	if err != nil {
		return Arc{}, err
	}

	if _, err := p.expect(TokenArcIn); err != nil {
		return Arc{}, fmt.Errorf("line %d: expected -| in arc, got %q", p.peek().Line, p.peek().Value)
	}

	weightTok := p.advance()
	if weightTok.Type != TokenIdent && weightTok.Type != TokenNumber {
		return Arc{}, fmt.Errorf("line %d: expected weight expression, got %q", weightTok.Line, weightTok.Value)
	}

	if _, err := p.expect(TokenArcOut); err != nil {
		return Arc{}, err
	}

	target, targetIdx, err := p.parsePlaceRef()
	if err != nil {
		return Arc{}, err
	}

	return Arc{
		Source:      source,
		SourceIndex: sourceIdx,
		Target:      target,
		TargetIndex: targetIdx,
		Weight:      weightTok.Value,
	}, nil
}

// parsePlaceRef parses NAME or NAME[index].
func (p *Parser) parsePlaceRef() (string, string, error) {
	nameTok, err := p.expect(TokenIdent)
	if err != nil {
		return "", "", err
	}

	idx := ""
	if p.peek().Type == TokenLBracket {
		p.advance() // [
		idxTok, err := p.expect(TokenIdent)
		if err != nil {
			return "", "", err
		}
		if _, err := p.expect(TokenRBracket); err != nil {
			return "", "", err
		}
		idx = idxTok.Value
	}

	return nameTok.Value, idx, nil
}
