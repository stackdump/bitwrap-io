package arc

import (
	"errors"

	"github.com/holiman/uint256"
)

// Safe math errors
var (
	ErrOverflow      = errors.New("arithmetic overflow")
	ErrUnderflow     = errors.New("arithmetic underflow")
	ErrDivisionByZero = errors.New("division by zero")
)

// U256 is an alias for uint256.Int for convenience
type U256 = uint256.Int

// NewU256 creates a new U256 from a uint64
func NewU256(v uint64) *U256 {
	return uint256.NewInt(v)
}

// NewU256FromBig creates a U256 from a big.Int (returns nil if overflow)
func NewU256FromBig(b interface{ Bytes() []byte }) *U256 {
	z := new(U256)
	z.SetBytes(b.Bytes())
	return z
}

// SafeAdd returns a + b, or error if overflow
func SafeAdd(a, b *U256) (*U256, error) {
	result := new(U256)
	_, overflow := result.AddOverflow(a, b)
	if overflow {
		return nil, ErrOverflow
	}
	return result, nil
}

// SafeAdd64 returns a + b for uint64 values, or error if overflow
func SafeAdd64(a, b uint64) (uint64, error) {
	result := a + b
	if result < a {
		return 0, ErrOverflow
	}
	return result, nil
}

// SafeSub returns a - b, or error if underflow
func SafeSub(a, b *U256) (*U256, error) {
	result := new(U256)
	_, underflow := result.SubOverflow(a, b)
	if underflow {
		return nil, ErrUnderflow
	}
	return result, nil
}

// SafeSub64 returns a - b for uint64 values, or error if underflow
func SafeSub64(a, b uint64) (uint64, error) {
	if b > a {
		return 0, ErrUnderflow
	}
	return a - b, nil
}

// SafeMul returns a * b, or error if overflow
func SafeMul(a, b *U256) (*U256, error) {
	result := new(U256)
	_, overflow := result.MulOverflow(a, b)
	if overflow {
		return nil, ErrOverflow
	}
	return result, nil
}

// SafeMul64 returns a * b for uint64 values, or error if overflow
func SafeMul64(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	result := a * b
	if result/a != b {
		return 0, ErrOverflow
	}
	return result, nil
}

// SafeDiv returns a / b, or error if division by zero
func SafeDiv(a, b *U256) (*U256, error) {
	if b.IsZero() {
		return nil, ErrDivisionByZero
	}
	result := new(U256)
	result.Div(a, b)
	return result, nil
}

// SafeDiv64 returns a / b for uint64 values, or error if division by zero
func SafeDiv64(a, b uint64) (uint64, error) {
	if b == 0 {
		return 0, ErrDivisionByZero
	}
	return a / b, nil
}

// SafeMod returns a % b, or error if division by zero
func SafeMod(a, b *U256) (*U256, error) {
	if b.IsZero() {
		return nil, ErrDivisionByZero
	}
	result := new(U256)
	result.Mod(a, b)
	return result, nil
}

// MulDiv computes (a * b) / c with full precision intermediate result
// Returns error on overflow or division by zero
func MulDiv(a, b, c *U256) (*U256, error) {
	if c.IsZero() {
		return nil, ErrDivisionByZero
	}
	// Use uint256's MulDivOverflow for precision
	result := new(U256)
	result.MulDivOverflow(a, b, c)
	return result, nil
}

// MulDiv64 computes (a * b) / c for uint64 with overflow checking
func MulDiv64(a, b, c uint64) (uint64, error) {
	if c == 0 {
		return 0, ErrDivisionByZero
	}
	// Use U256 for intermediate precision
	ua := NewU256(a)
	ub := NewU256(b)
	uc := NewU256(c)

	product := new(U256)
	product.Mul(ua, ub)

	result := new(U256)
	result.Div(product, uc)

	if !result.IsUint64() {
		return 0, ErrOverflow
	}
	return result.Uint64(), nil
}

// ConvertToShares computes shares = (assets * totalShares) / totalAssets
// This is the standard ERC-4626 conversion with rounding down
func ConvertToShares(assets, totalShares, totalAssets *U256) (*U256, error) {
	if totalAssets.IsZero() {
		// First deposit: 1:1 ratio
		return new(U256).Set(assets), nil
	}
	return MulDiv(assets, totalShares, totalAssets)
}

// ConvertToAssets computes assets = (shares * totalAssets) / totalShares
// This is the standard ERC-4626 conversion with rounding down
func ConvertToAssets(shares, totalAssets, totalShares *U256) (*U256, error) {
	if totalShares.IsZero() {
		// No shares: 1:1 ratio
		return new(U256).Set(shares), nil
	}
	return MulDiv(shares, totalAssets, totalShares)
}

// Min returns the smaller of a and b
func Min(a, b *U256) *U256 {
	if a.Lt(b) {
		return new(U256).Set(a)
	}
	return new(U256).Set(b)
}

// Max returns the larger of a and b
func Max(a, b *U256) *U256 {
	if a.Gt(b) {
		return new(U256).Set(a)
	}
	return new(U256).Set(b)
}

// Min64 returns the smaller of a and b
func Min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// Max64 returns the larger of a and b
func Max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
