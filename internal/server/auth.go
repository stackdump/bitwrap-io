package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"golang.org/x/crypto/sha3"
)

// devKeys are well-known test keys (anvil HD wallet accounts 0-9). Only used in dev mode.
var devKeys = []*big.Int{
	fromHex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
	fromHex("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
	fromHex("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
	fromHex("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"),
	fromHex("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"),
	fromHex("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"),
	fromHex("92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"),
	fromHex("4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"),
	fromHex("dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97"),
	fromHex("2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"),
}

// handleDevSign signs a message with a built-in dev key.
// Accepts optional "account" field (0-9) to select which anvil account signs.
// Only available when server is started with -dev flag.
func (s *Server) handleDevSign(w http.ResponseWriter, r *http.Request) {
	if !s.opts.DevMode {
		http.Error(w, "dev mode not enabled (start with -dev flag)", http.StatusForbidden)
		return
	}

	var req struct {
		Message string `json:"message"`
		Account int    `json:"account"` // 0-9, defaults to 0
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		http.Error(w, "message field required", http.StatusBadRequest)
		return
	}
	if req.Account < 0 || req.Account >= len(devKeys) {
		req.Account = 0
	}

	sig, addr := devSignWithKey(req.Message, devKeys[req.Account])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"signature": sig,
		"address":   addr,
	})
}

// devSign signs a message with anvil account 0.
func devSign(message string) (string, string) {
	return devSignWithKey(message, devKeys[0])
}

// devSignWithKey signs a message with the given private key using EIP-191 personal_sign.
func devSignWithKey(message string, privKey *big.Int) (string, string) {
	// EIP-191 prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(message))
	hash := keccak256(append([]byte(prefix), []byte(message)...))
	z := new(big.Int).SetBytes(hash)

	// Deterministic k (RFC 6979 simplified)
	kMat := make([]byte, 64)
	copy(kMat[:32], privKey.Bytes())
	copy(kMat[32:], hash)
	k := new(big.Int).SetBytes(keccak256(kMat))
	k.Mod(k, new(big.Int).Sub(secp256k1N, big.NewInt(1)))
	k.Add(k, big.NewInt(1))

	rx, ry := ecMul(secp256k1Gx, secp256k1Gy, k)
	r := new(big.Int).Mod(rx, secp256k1N)
	s := new(big.Int).Mul(r, privKey)
	s.Add(s, z)
	s.Mod(s, secp256k1N)
	s.Mul(s, new(big.Int).ModInverse(k, secp256k1N))
	s.Mod(s, secp256k1N)

	// Recovery id
	v := byte(27)
	if ry.Bit(0) == 1 {
		v = 28
	}

	// Low-s normalization (EIP-2)
	halfN := new(big.Int).Rsh(secp256k1N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(secp256k1N, s)
		if v == 27 {
			v = 28
		} else {
			v = 27
		}
	}

	sigBytes := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	sigBytes[64] = v

	sigHex := "0x" + hex.EncodeToString(sigBytes)

	// Derive address
	pubX, pubY := ecMul(secp256k1Gx, secp256k1Gy, privKey)
	pubBytes := make([]byte, 64)
	pxBytes := pubX.Bytes()
	pyBytes := pubY.Bytes()
	copy(pubBytes[32-len(pxBytes):32], pxBytes)
	copy(pubBytes[64-len(pyBytes):64], pyBytes)
	addrHash := keccak256(pubBytes)
	addr := "0x" + hex.EncodeToString(addrHash[12:])

	return sigHex, addr
}

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
	// R point x-coordinate is just r (the rx += N case is for v >= 2, extremely rare)
	rx := new(big.Int).Set(r)

	// v encodes the parity of R.y: v=0 → even, v=1 → odd
	ry := decompressPoint(rx, v == 1)
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
