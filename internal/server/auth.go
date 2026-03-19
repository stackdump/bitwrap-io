package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// secp256k1 curve parameters
var secp256k1 = &elliptic.CurveParams{
	P:       fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
	N:       fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
	B:       big.NewInt(7),
	Gx:      fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
	Gy:      fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
	BitSize: 256,
	Name:    "secp256k1",
}

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
// message: the original message text (without prefix)
// signature: hex-encoded 65-byte signature (r || s || v)
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

	// Extract r, s, v from signature
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	// Normalize v (27/28 -> 0/1)
	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return "", errors.New("invalid signature recovery id")
	}

	// Recover public key
	pubKey, err := recoverPubKey(hash, r, s, v)
	if err != nil {
		return "", fmt.Errorf("public key recovery failed: %w", err)
	}

	// Derive Ethereum address from public key
	pubBytes := elliptic.Marshal(secp256k1, pubKey.X, pubKey.Y)
	addr := keccak256(pubBytes[1:]) // skip 0x04 prefix
	return "0x" + hex.EncodeToString(addr[12:]), nil
}

// recoverPubKey recovers the ECDSA public key from a signature.
func recoverPubKey(hash []byte, r, s *big.Int, v byte) (*ecdsa.PublicKey, error) {
	// Calculate R point on the curve
	rx := new(big.Int).Set(r)
	if v == 1 {
		rx.Add(rx, secp256k1.N)
	}

	// Calculate y from x on secp256k1: y^2 = x^3 + 7
	ry := decompressPoint(rx, v%2 == 1)
	if ry == nil {
		return nil, errors.New("invalid signature: point not on curve")
	}

	// R = (rx, ry)
	// e = hash as big.Int
	e := new(big.Int).SetBytes(hash)

	// Recover public key: Q = r^-1 * (s*R - e*G)
	rInv := new(big.Int).ModInverse(r, secp256k1.N)
	if rInv == nil {
		return nil, errors.New("invalid signature: r has no inverse")
	}

	// s*R
	sRx, sRy := secp256k1.ScalarMult(rx, ry, s.Bytes())

	// e*G
	eGx, eGy := secp256k1.ScalarBaseMult(e.Bytes())

	// s*R - e*G
	eGy.Neg(eGy)
	eGy.Mod(eGy, secp256k1.P)
	sumX, sumY := secp256k1.Add(sRx, sRy, eGx, eGy)

	// Q = r^-1 * (s*R - e*G)
	qx, qy := secp256k1.ScalarMult(sumX, sumY, rInv.Bytes())

	return &ecdsa.PublicKey{Curve: secp256k1, X: qx, Y: qy}, nil
}

// decompressPoint finds the y coordinate for a given x on secp256k1.
func decompressPoint(x *big.Int, odd bool) *big.Int {
	// y^2 = x^3 + 7 (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, secp256k1.P)

	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, secp256k1.P)

	// sqrt via Tonelli-Shanks (p ≡ 3 mod 4 for secp256k1)
	exp := new(big.Int).Add(secp256k1.P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, secp256k1.P)

	// Verify
	check := new(big.Int).Mul(y, y)
	check.Mod(check, secp256k1.P)
	if check.Cmp(y2) != 0 {
		return nil
	}

	// Adjust parity
	if odd != (y.Bit(0) == 1) {
		y.Sub(secp256k1.P, y)
	}

	return y
}
