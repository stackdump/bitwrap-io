package dsl

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType enumerates the kinds of tokens the lexer produces.
type TokenType int

const (
	// Special
	TokenEOF TokenType = iota
	TokenError

	// Literals
	TokenIdent   // alphanumeric + dots + underscores (e.g. ASSETS.AVAILABLE)
	TokenString  // "..."
	TokenNumber  // integer literal

	// Keywords
	TokenSchema
	TokenVersion
	TokenDomain
	TokenAsset
	TokenInitialState
	TokenRegister
	TokenEvent
	TokenFn
	TokenVar
	TokenRequire
	TokenRequires
	TokenObservable
	TokenIndexed

	// Symbols
	TokenLBrace    // {
	TokenRBrace    // }
	TokenLParen    // (
	TokenRParen    // )
	TokenLBracket  // [
	TokenRBracket  // ]
	TokenColon     // :
	TokenArcIn     // -|
	TokenArcOut    // |>
	TokenAt        // @
	TokenComma     // ,

	// Operators
	TokenGE   // >=
	TokenGT   // >
	TokenLE   // <=
	TokenLT   // <
	TokenEQ   // ==
	TokenNE   // !=
	TokenAnd  // &&
	TokenOr   // ||
)

// String returns a human-readable name for the token type.
func (t TokenType) String() string {
	switch t {
	case TokenEOF:
		return "end of file"
	case TokenError:
		return "error"
	case TokenIdent:
		return "identifier"
	case TokenString:
		return "string"
	case TokenNumber:
		return "number"
	case TokenSchema:
		return "schema"
	case TokenRegister:
		return "register"
	case TokenEvent:
		return "event"
	case TokenFn:
		return "fn"
	case TokenVar:
		return "var"
	case TokenRequire:
		return "require"
	case TokenRequires:
		return "requires"
	case TokenLBrace:
		return "{"
	case TokenRBrace:
		return "}"
	case TokenLParen:
		return "("
	case TokenRParen:
		return ")"
	case TokenLBracket:
		return "["
	case TokenRBracket:
		return "]"
	case TokenArcIn:
		return "-|"
	case TokenArcOut:
		return "|>"
	case TokenAt:
		return "@"
	default:
		return fmt.Sprintf("token(%d)", int(t))
	}
}

// Token is a single lexical token with its position.
type Token struct {
	Type    TokenType
	Value   string
	Line    int
}

func (t Token) String() string {
	return fmt.Sprintf("Token(%d, %q, line %d)", t.Type, t.Value, t.Line)
}

// keywords maps keyword strings to their token types.
var keywords = map[string]TokenType{
	"schema":        TokenSchema,
	"version":       TokenVersion,
	"domain":        TokenDomain,
	"asset":         TokenAsset,
	"initial_state": TokenInitialState,
	"register":      TokenRegister,
	"event":         TokenEvent,
	"fn":            TokenFn,
	"var":           TokenVar,
	"require":       TokenRequire,
	"requires":      TokenRequires,
	"observable":    TokenObservable,
	"indexed":       TokenIndexed,
}

// Lexer tokenizes .btw source text.
type Lexer struct {
	input  []rune
	pos    int
	line   int
	tokens []Token
}

// NewLexer creates a lexer for the given source text.
func NewLexer(input string) *Lexer {
	return &Lexer{
		input: []rune(input),
		pos:   0,
		line:  1,
	}
}

// Tokenize scans the entire input and returns all tokens.
func (l *Lexer) Tokenize() ([]Token, error) {
	for {
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		l.tokens = append(l.tokens, tok)
		if tok.Type == TokenEOF {
			break
		}
	}
	return l.tokens, nil
}

func (l *Lexer) peek() rune {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *Lexer) advance() rune {
	if l.pos >= len(l.input) {
		return 0
	}
	r := l.input[l.pos]
	l.pos++
	if r == '\n' {
		l.line++
	}
	return r
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		r := l.input[l.pos]
		if r == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '/' {
			// line comment (//)
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		if r == '#' {
			// line comment (#)
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		if unicode.IsSpace(r) {
			if r == '\n' {
				l.line++
			}
			l.pos++
			continue
		}
		break
	}
}

func (l *Lexer) next() (Token, error) {
	l.skipWhitespace()

	if l.pos >= len(l.input) {
		return Token{Type: TokenEOF, Line: l.line}, nil
	}

	line := l.line
	r := l.peek()

	// Two-character tokens
	if l.pos+1 < len(l.input) {
		two := string(l.input[l.pos : l.pos+2])
		switch two {
		case "-|":
			l.pos += 2
			return Token{Type: TokenArcIn, Value: "-|", Line: line}, nil
		case "|>":
			l.pos += 2
			return Token{Type: TokenArcOut, Value: "|>", Line: line}, nil
		case ">=":
			l.pos += 2
			return Token{Type: TokenGE, Value: ">=", Line: line}, nil
		case "<=":
			l.pos += 2
			return Token{Type: TokenLE, Value: "<=", Line: line}, nil
		case "==":
			l.pos += 2
			return Token{Type: TokenEQ, Value: "==", Line: line}, nil
		case "!=":
			l.pos += 2
			return Token{Type: TokenNE, Value: "!=", Line: line}, nil
		case "&&":
			l.pos += 2
			return Token{Type: TokenAnd, Value: "&&", Line: line}, nil
		case "||":
			l.pos += 2
			return Token{Type: TokenOr, Value: "||", Line: line}, nil
		}
	}

	// Single-character tokens
	switch r {
	case '{':
		l.advance()
		return Token{Type: TokenLBrace, Value: "{", Line: line}, nil
	case '}':
		l.advance()
		return Token{Type: TokenRBrace, Value: "}", Line: line}, nil
	case '(':
		l.advance()
		return Token{Type: TokenLParen, Value: "(", Line: line}, nil
	case ')':
		l.advance()
		return Token{Type: TokenRParen, Value: ")", Line: line}, nil
	case '[':
		l.advance()
		return Token{Type: TokenLBracket, Value: "[", Line: line}, nil
	case ']':
		l.advance()
		return Token{Type: TokenRBracket, Value: "]", Line: line}, nil
	case ':':
		l.advance()
		return Token{Type: TokenColon, Value: ":", Line: line}, nil
	case '@':
		l.advance()
		return Token{Type: TokenAt, Value: "@", Line: line}, nil
	case ',':
		l.advance()
		return Token{Type: TokenComma, Value: ",", Line: line}, nil
	case '>':
		l.advance()
		return Token{Type: TokenGT, Value: ">", Line: line}, nil
	case '<':
		l.advance()
		return Token{Type: TokenLT, Value: "<", Line: line}, nil
	}

	// String literal
	if r == '"' {
		return l.readString()
	}

	// Number literal
	if unicode.IsDigit(r) {
		return l.readNumber()
	}

	// Identifier or keyword
	if isIdentStart(r) {
		return l.readIdent()
	}

	return Token{}, fmt.Errorf("line %d: unexpected character %q", line, r)
}

func (l *Lexer) readString() (Token, error) {
	line := l.line
	l.advance() // skip opening "
	var sb strings.Builder
	for {
		if l.pos >= len(l.input) {
			return Token{}, fmt.Errorf("line %d: unterminated string literal", line)
		}
		r := l.advance()
		if r == '"' {
			break
		}
		if r == '\\' {
			next := l.advance()
			switch next {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case '\\':
				sb.WriteByte('\\')
			case '"':
				sb.WriteByte('"')
			default:
				sb.WriteRune('\\')
				sb.WriteRune(next)
			}
			continue
		}
		sb.WriteRune(r)
	}
	return Token{Type: TokenString, Value: sb.String(), Line: line}, nil
}

func (l *Lexer) readNumber() (Token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.input) && unicode.IsDigit(l.input[l.pos]) {
		l.pos++
	}
	return Token{Type: TokenNumber, Value: string(l.input[start:l.pos]), Line: line}, nil
}

func (l *Lexer) readIdent() (Token, error) {
	line := l.line
	start := l.pos
	for l.pos < len(l.input) && isIdentContinue(l.input[l.pos]) {
		l.pos++
	}
	val := string(l.input[start:l.pos])

	if tt, ok := keywords[val]; ok {
		return Token{Type: tt, Value: val, Line: line}, nil
	}
	return Token{Type: TokenIdent, Value: val, Line: line}, nil
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_'
}

func isIdentContinue(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.'
}
