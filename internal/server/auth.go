package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// secp256k1 curve parameters
var (
	secp256k1P  = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secp256k1N  = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secp256k1B  = big.NewInt(7)
	secp256k1Gx = fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secp256k1Gy = fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

func fromHex(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

// keccak256 computes the Keccak-256 hash.
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// RecoverAddress recovers an Ethereum address from an EIP-191 personal_sign signature.
func RecoverAddress(message string, signature string) (string, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}

	// EIP-191 personal_sign prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	hash := keccak256(append([]byte(prefix), []byte(message)...))

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return "", errors.New("invalid signature recovery id")
	}

	pubX, pubY, err := ecRecover(hash, r, s, v)
	if err != nil {
		return "", fmt.Errorf("public key recovery failed: %w", err)
	}

	// Derive Ethereum address: keccak256(uncompressed_pubkey[1:])
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	xBytes := pubX.Bytes()
	yBytes := pubY.Bytes()
	copy(pubBytes[1+32-len(xBytes):33], xBytes)
	copy(pubBytes[33+32-len(yBytes):65], yBytes)

	addr := keccak256(pubBytes[1:])
	return "0x" + hex.EncodeToString(addr[12:]), nil
}

// ecRecover recovers the public key from an ECDSA signature on secp256k1.
// Returns (pubX, pubY) or error.
func ecRecover(hash []byte, r, s *big.Int, v byte) (*big.Int, *big.Int, error) {
	// Calculate R point x-coordinate
	rx := new(big.Int).Set(r)
	if v == 1 {
		rx.Add(rx, secp256k1N)
	}

	// Decompress R point: find y from x on secp256k1
	ry := decompressPoint(rx, v%2 == 1)
	if ry == nil {
		return nil, nil, errors.New("invalid signature: R not on curve")
	}

	// e = hash as big.Int
	e := new(big.Int).SetBytes(hash)

	// r_inv = r^(-1) mod N
	rInv := new(big.Int).ModInverse(r, secp256k1N)
	if rInv == nil {
		return nil, nil, errors.New("invalid signature: r has no inverse")
	}

	// Recover: Q = r_inv * (s*R - e*G)
	// Step 1: s*R
	sRx, sRy := ecMul(rx, ry, s)

	// Step 2: e*G
	eGx, eGy := ecMul(secp256k1Gx, secp256k1Gy, e)

	// Step 3: s*R - e*G  (subtract = add with negated y)
	negEGy := new(big.Int).Sub(secp256k1P, eGy)
	diffX, diffY := ecAdd(sRx, sRy, eGx, negEGy)

	// Step 4: r_inv * (s*R - e*G)
	qx, qy := ecMul(diffX, diffY, rInv)

	return qx, qy, nil
}

// ecAdd adds two points on secp256k1.
func ecAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	p := secp256k1P

	// If points are the same, use doubling
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return ecDouble(x1, y1)
	}

	// If x1 == x2 and y1 != y2, result is point at infinity
	if x1.Cmp(x2) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	// lambda = (y2 - y1) / (x2 - x1) mod p
	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, p)
	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, p)
	denInv := new(big.Int).ModInverse(den, p)
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// ecDouble doubles a point on secp256k1.
func ecDouble(x, y *big.Int) (*big.Int, *big.Int) {
	// Point at infinity
	if x.Sign() == 0 && y.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	p := secp256k1P

	// lambda = (3*x^2 + a) / (2*y) mod p   (a=0 for secp256k1)
	num := new(big.Int).Mul(x, x)
	num.Mul(num, big.NewInt(3))
	num.Mod(num, p)

	den := new(big.Int).Mul(big.NewInt(2), y)
	den.Mod(den, p)
	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return big.NewInt(0), big.NewInt(0) // degenerate case
	}
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - 2*x mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x))
	x3.Mod(x3, p)

	// y3 = lambda * (x - x3) - y mod p
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y)
	y3.Mod(y3, p)

	return x3, y3
}

// ecMul performs scalar multiplication on secp256k1 using double-and-add.
func ecMul(x, y *big.Int, k *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(0) // point at infinity
	px, py := new(big.Int).Set(x), new(big.Int).Set(y)

	for _, b := range k.Bytes() {
		for i := 7; i >= 0; i-- {
			rx, ry = ecDouble(rx, ry)
			if b&(1<<uint(i)) != 0 {
				rx, ry = ecAdd(rx, ry, px, py)
			}
		}
	}

	return rx, ry
}

// decompressPoint finds y for a given x on secp256k1: y² = x³ + 7 (mod p).
func decompressPoint(x *big.Int, odd bool) *big.Int {
	p := secp256k1P

	// y² = x³ + 7 mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)
	y2 := new(big.Int).Add(x3, secp256k1B)
	y2.Mod(y2, p)

	// sqrt: p ≡ 3 mod 4, so y = y2^((p+1)/4) mod p
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, p)

	// Verify
	check := new(big.Int).Mul(y, y)
	check.Mod(check, p)
	if check.Cmp(y2) != 0 {
		return nil
	}

	if odd != (y.Bit(0) == 1) {
		y.Sub(p, y)
	}

	return y
}
