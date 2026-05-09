// Package prover — Pedersen / ElGamal primitives for the homomorphic
// tally protocol (Phase B / vote schema v3).
//
// Curve: BabyJubJub — twisted Edwards curve embedded over BN254's
// scalar field Fr. Coordinates and arithmetic live natively in Fr,
// which is the constraint field of the BN254 Groth16 proof system —
// so in-circuit ElGamal scalar mults cost ~constant per bit instead
// of the ~50× overhead of non-native BN254 G1.
//
// Curve equation: a·x² + y² = 1 + d·x²·y², with a = -1 (gnark-crypto
// reduced parameters). Prime-order subgroup ℓ; cofactor = 8.
//
//   G = curve canonical base point (returned by gnark-crypto).
//   H = independent generator derived by hash-to-curve (try-and-increment
//       on SHA-256 of "bitwrap-h-generator-v1" + counter, post-multiplied
//       by the cofactor to land in the prime-order subgroup). Reusable
//       as a Pedersen commitment base. Not used by ElGamal itself but
//       defined for downstream constructions; both sides must agree on
//       the same byte sequence.
//
// ElGamal encoding (additively homomorphic, exponential, additive
// notation suitable for Edwards):
//
//	A = G · r
//	B = G · v + pk · r
//
// Aggregation is pointwise. Decryption:
//
//	M = B − sk · A   recovers G · v_total
//	v_total          via small-range search bounded by maxTally.
//
// Wire encoding: 32-byte compressed point in gnark-crypto / RFC 8032
// format — little-endian Y with the sign of X in the MSB of byte 31.
// JS parity is asserted by public/pedersen_parity_test.mjs against
// vectors emitted from prover/pedersen_test.go.

package prover

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// PedersenHDST is the domain separation tag used to derive H.
// Frozen — changing it produces an incompatible H.
const PedersenHDST = "bitwrap-h-generator-v1"

// Ciphertext is a single ElGamal ciphertext under the creator pk.
type Ciphertext struct {
	A tedwards.PointAffine
	B tedwards.PointAffine
}

// PedersenG returns the canonical BabyJubJub base point.
func PedersenG() tedwards.PointAffine {
	return tedwards.GetEdwardsCurve().Base
}

// PedersenH returns the deterministic independent generator H.
// Cached after first computation.
var (
	pedersenHOnce  sync.Once
	pedersenHValue tedwards.PointAffine
)

func PedersenH() tedwards.PointAffine {
	pedersenHOnce.Do(func() {
		pedersenHValue = deriveH(PedersenHDST)
	})
	return pedersenHValue
}

// deriveH performs a deterministic try-and-increment hash-to-curve:
//
//  1. counter = 0
//  2. seed  = SHA-256(dst || counter_be_4)
//  3. y     = seed mod Fr
//  4. solve x² = (y² − 1) / (d·y² − a) for x; if not a QR, ++counter.
//  5. pick the canonical x-root (lex-smallest), build (x, y).
//  6. multiply by cofactor=8 to land in the prime-order subgroup.
//  7. if result is identity (y=1, x=0), ++counter and retry.
//
// JS mirror does not reproduce this — H is loaded as a fixed constant
// from the parity-vector fixture (a single deterministic point that
// both sides must agree on byte-for-byte).
func deriveH(dst string) tedwards.PointAffine {
	curve := tedwards.GetEdwardsCurve()

	var aFr, dFr fr.Element
	aFr.Set(&curve.A)
	dFr.Set(&curve.D)

	for counter := uint32(0); counter < 1<<16; counter++ {
		var ctrBuf [4]byte
		binary.BigEndian.PutUint32(ctrBuf[:], counter)
		h := sha256.New()
		h.Write([]byte(dst))
		h.Write(ctrBuf[:])
		seed := h.Sum(nil)

		var y fr.Element
		y.SetBytes(seed) // reduces mod Fr

		// num = y² − 1, den = d·y² − a
		var ySq, num, den fr.Element
		ySq.Square(&y)
		num.Sub(&ySq, new(fr.Element).SetOne())
		den.Mul(&dFr, &ySq)
		den.Sub(&den, &aFr)
		if den.IsZero() {
			continue
		}
		var xSq fr.Element
		xSq.Div(&num, &den)

		// x = sqrt(xSq); Sqrt returns nil if non-residue.
		var x fr.Element
		if x.Sqrt(&xSq) == nil {
			continue
		}
		// canonicalize: pick lex-smallest x.
		if x.LexicographicallyLargest() {
			x.Neg(&x)
		}

		var p tedwards.PointAffine
		p.X.Set(&x)
		p.Y.Set(&y)
		if !p.IsOnCurve() {
			continue
		}
		// clear cofactor to land in the prime-order subgroup.
		var cof big.Int
		curve.Cofactor.BigInt(&cof)
		var cleared tedwards.PointAffine
		cleared.ScalarMultiplication(&p, &cof)
		if cleared.IsZero() {
			continue
		}
		return cleared
	}
	panic("pedersen: deriveH counter exhausted (DST is degenerate)")
}

// Encrypt returns the ElGamal ciphertext (A, B) for plaintext scalar v
// under public key pk and randomness r.
//
//	A = G · r
//	B = G · v + pk · r
//
// All scalars are reduced mod the BabyJubJub subgroup order before
// scalar mul. (gnark-crypto's PointAffine.ScalarMultiplication accepts
// any *big.Int but we canonicalize for parity with JS.)
func Encrypt(v, r *big.Int, pk *tedwards.PointAffine) Ciphertext {
	g := PedersenG()
	vRed := reduceSubgroup(v)
	rRed := reduceSubgroup(r)

	var A, B, gv, pkr tedwards.PointAffine
	A.ScalarMultiplication(&g, rRed)
	gv.ScalarMultiplication(&g, vRed)
	pkr.ScalarMultiplication(pk, rRed)
	B.Add(&gv, &pkr)
	return Ciphertext{A: A, B: B}
}

// Aggregate sums a list of ciphertexts component-wise. Empty input
// returns the identity (0, 1) on both A and B.
func Aggregate(cts []Ciphertext) Ciphertext {
	var A, B tedwards.PointAffine
	identityPoint(&A)
	identityPoint(&B)
	for i := range cts {
		A.Add(&A, &cts[i].A)
		B.Add(&B, &cts[i].B)
	}
	return Ciphertext{A: A, B: B}
}

// Decrypt recovers the aggregate plaintext from a ciphertext using
// secret key sk. maxTally bounds the small-range search; returns
// ErrTallyExceedsRange if no t in [0, maxTally] satisfies G·t = M.
//
//	M = B − sk · A
func Decrypt(ct Ciphertext, sk *big.Int, maxTally int) (int, error) {
	if maxTally < 0 {
		return 0, errors.New("pedersen: maxTally must be non-negative")
	}
	skRed := reduceSubgroup(sk)

	g := PedersenG()
	var skA, negSkA, M tedwards.PointAffine
	skA.ScalarMultiplication(&ct.A, skRed)
	negSkA.Neg(&skA)
	M.Add(&ct.B, &negSkA)

	var probe tedwards.PointAffine
	identityPoint(&probe)
	if probe.Equal(&M) {
		return 0, nil
	}
	for t := 1; t <= maxTally; t++ {
		probe.Add(&probe, &g)
		if probe.Equal(&M) {
			return t, nil
		}
	}
	return 0, ErrTallyExceedsRange
}

// ErrTallyExceedsRange — Decrypt found no t in [0, maxTally] matching M.
var ErrTallyExceedsRange = errors.New("pedersen: tally exceeds maxTally range")

// EncodePoint returns the 32-byte compressed encoding (gnark-crypto /
// RFC 8032 format).
func EncodePoint(p *tedwards.PointAffine) []byte {
	b := p.Bytes()
	return b[:]
}

// DecodePoint parses a 32-byte compressed point and verifies it lies
// on the curve. Does not enforce subgroup membership — callers that
// need it (e.g. accepting pk_creator from untrusted input) should call
// IsInPrimeSubgroup separately.
func DecodePoint(buf []byte) (tedwards.PointAffine, error) {
	var p tedwards.PointAffine
	if len(buf) != 32 {
		return p, fmt.Errorf("pedersen: expected 32 bytes, got %d", len(buf))
	}
	if _, err := p.SetBytes(buf); err != nil {
		return p, fmt.Errorf("pedersen: decode point: %w", err)
	}
	if !p.IsOnCurve() {
		return p, errors.New("pedersen: decoded point not on curve")
	}
	return p, nil
}

// IsInPrimeSubgroup checks that ℓ · p == identity, where ℓ is the
// prime-order subgroup order. Critical for any pk accepted from
// untrusted input — small-subgroup attacks otherwise leak sk bits.
func IsInPrimeSubgroup(p *tedwards.PointAffine) bool {
	curve := tedwards.GetEdwardsCurve()
	var probe tedwards.PointAffine
	probe.ScalarMultiplication(p, &curve.Order)
	return probe.IsZero()
}

// identityPoint sets p to the twisted-Edwards identity (0, 1).
func identityPoint(p *tedwards.PointAffine) {
	p.X.SetZero()
	p.Y.SetOne()
}

// reduceSubgroup normalizes a scalar to [0, ℓ).
func reduceSubgroup(x *big.Int) *big.Int {
	curve := tedwards.GetEdwardsCurve()
	return new(big.Int).Mod(x, &curve.Order)
}
