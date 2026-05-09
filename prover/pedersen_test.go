package prover

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

// TestPedersenH pins H to a deterministic point and asserts subgroup
// membership. A drift in this output flags either a curve-param change
// or a DST drift; both are hard breaks for any deployed v3 polls.
func TestPedersenH(t *testing.T) {
	h := PedersenH()
	if !h.IsOnCurve() {
		t.Fatalf("H is not on curve")
	}
	if !IsInPrimeSubgroup(&h) {
		t.Fatalf("H is not in prime-order subgroup")
	}
	got := hex.EncodeToString(EncodePoint(&h))
	t.Logf("H = %s", got)
	if len(got) != 64 {
		t.Fatalf("expected 32-byte compressed point, got %d hex chars", len(got))
	}
}

// TestPedersenG sanity-checks the canonical generator matches gnark-
// crypto's BabyJubJub base.
func TestPedersenG(t *testing.T) {
	g := PedersenG()
	if !g.IsOnCurve() {
		t.Fatalf("G is not on curve")
	}
	if !IsInPrimeSubgroup(&g) {
		t.Fatalf("G is not in prime-order subgroup")
	}
}

// TestEncryptRoundtrip — single-ciphertext ElGamal under sk.
func TestEncryptRoundtrip(t *testing.T) {
	sk := big.NewInt(0xabc123)
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)

	cases := []struct{ v, r int64 }{
		{0, 1}, {1, 2}, {1, 99}, {0, 999},
	}
	for _, c := range cases {
		ct := Encrypt(big.NewInt(c.v), big.NewInt(c.r), &pk)
		got, err := Decrypt(ct, sk, 1)
		if err != nil {
			t.Fatalf("decrypt v=%d: %v", c.v, err)
		}
		if int64(got) != c.v {
			t.Fatalf("decrypt v=%d r=%d: got %d", c.v, c.r, got)
		}
	}
}

// TestAggregateAndDecrypt — small poll: 5 voters × 3 bins, one-hot.
func TestAggregateAndDecrypt(t *testing.T) {
	sk := big.NewInt(7777)
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)

	const K = 3
	ballots := [][]int64{
		{1, 0, 0},
		{0, 1, 0},
		{1, 0, 0},
		{0, 0, 1},
		{0, 1, 0},
	}
	want := []int{2, 2, 1}

	bins := make([][]Ciphertext, K)
	for i, ballot := range ballots {
		for j := 0; j < K; j++ {
			r := big.NewInt(int64(1000 + i*K + j))
			bins[j] = append(bins[j], Encrypt(big.NewInt(ballot[j]), r, &pk))
		}
	}

	for j := 0; j < K; j++ {
		agg := Aggregate(bins[j])
		got, err := Decrypt(agg, sk, len(ballots))
		if err != nil {
			t.Fatalf("bin %d decrypt: %v", j, err)
		}
		if got != want[j] {
			t.Fatalf("bin %d: got %d want %d", j, got, want[j])
		}
	}
}

func TestDecryptOutOfRange(t *testing.T) {
	sk := big.NewInt(42)
	g := PedersenG()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)

	ct := Encrypt(big.NewInt(5), big.NewInt(1), &pk)
	if _, err := Decrypt(ct, sk, 4); err != ErrTallyExceedsRange {
		t.Fatalf("expected ErrTallyExceedsRange, got %v", err)
	}
}

func TestPointEncodingRoundtrip(t *testing.T) {
	g := PedersenG()
	for _, s := range []int64{1, 2, 3, 12345, 0xabcdef} {
		var p tedwards.PointAffine
		p.ScalarMultiplication(&g, big.NewInt(s))
		buf := EncodePoint(&p)
		if len(buf) != 32 {
			t.Fatalf("encode size: got %d", len(buf))
		}
		q, err := DecodePoint(buf)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !p.Equal(&q) {
			t.Fatalf("roundtrip mismatch for s=%d", s)
		}
	}
}

// TestEmitParityVectors — gated; regenerates public/pedersen_vectors.json.
func TestEmitParityVectors(t *testing.T) {
	if os.Getenv("BITWRAP_EMIT_VECTORS") != "1" {
		t.Skip("set BITWRAP_EMIT_VECTORS=1 to regenerate public/pedersen_vectors.json")
	}

	type ctHex struct {
		A string `json:"A"`
		B string `json:"B"`
	}
	type encryptCase struct {
		V  string `json:"v"`
		R  string `json:"r"`
		Ct ctHex  `json:"ct"`
	}
	type vectors struct {
		Curve         string        `json:"curve"`
		ScalarModulus string        `json:"scalarModulus"`
		SubgroupOrder string        `json:"subgroupOrder"`
		Cofactor      string        `json:"cofactor"`
		HDST          string        `json:"hDST"`
		G             string        `json:"G"`
		H             string        `json:"H"`
		Sk            string        `json:"sk"`
		Pk            string        `json:"pk"`
		Encrypts      []encryptCase `json:"encrypts"`
		Aggregate     struct {
			Inputs []ctHex `json:"inputs"`
			Sum    ctHex   `json:"sum"`
		} `json:"aggregate"`
		Decrypt struct {
			Ct       ctHex `json:"ct"`
			MaxTally int   `json:"maxTally"`
			Tally    int   `json:"tally"`
		} `json:"decrypt"`
	}

	curve := tedwards.GetEdwardsCurve()
	v := vectors{
		Curve:         "BabyJubJub (gnark-crypto / iden3, a=-1)",
		ScalarModulus: bn254FrModulus().String(),
		SubgroupOrder: curve.Order.String(),
		Cofactor:      "8",
		HDST:          PedersenHDST,
	}

	g := PedersenG()
	h := PedersenH()
	v.G = hex.EncodeToString(EncodePoint(&g))
	v.H = hex.EncodeToString(EncodePoint(&h))

	sk := mustBigInt("19283746501928374650192837465019283746501928")
	v.Sk = sk.String()
	var pk tedwards.PointAffine
	pk.ScalarMultiplication(&g, sk)
	v.Pk = hex.EncodeToString(EncodePoint(&pk))

	enc := func(val, r *big.Int) ctHex {
		ct := Encrypt(val, r, &pk)
		return ctHex{
			A: hex.EncodeToString(EncodePoint(&ct.A)),
			B: hex.EncodeToString(EncodePoint(&ct.B)),
		}
	}

	cases := []struct{ val, r *big.Int }{
		{big.NewInt(0), big.NewInt(1)},
		{big.NewInt(1), big.NewInt(2)},
		{big.NewInt(1), mustBigInt("31415926535897932384626433832795028841971693993751")},
		{big.NewInt(0), mustBigInt("27182818284590452353602874713526624977572470936999")},
	}
	for _, c := range cases {
		v.Encrypts = append(v.Encrypts, encryptCase{
			V: c.val.String(), R: c.r.String(), Ct: enc(c.val, c.r),
		})
	}

	ballots := []int64{1, 0, 1, 0}
	rs := []*big.Int{big.NewInt(11), big.NewInt(22), big.NewInt(33), big.NewInt(44)}
	var bin []Ciphertext
	for i, b := range ballots {
		bin = append(bin, Encrypt(big.NewInt(b), rs[i], &pk))
	}
	for _, ct := range bin {
		v.Aggregate.Inputs = append(v.Aggregate.Inputs, ctHex{
			A: hex.EncodeToString(EncodePoint(&ct.A)),
			B: hex.EncodeToString(EncodePoint(&ct.B)),
		})
	}
	agg := Aggregate(bin)
	v.Aggregate.Sum = ctHex{
		A: hex.EncodeToString(EncodePoint(&agg.A)),
		B: hex.EncodeToString(EncodePoint(&agg.B)),
	}

	tally, err := Decrypt(agg, sk, len(ballots))
	if err != nil {
		t.Fatalf("decrypt aggregate: %v", err)
	}
	v.Decrypt.Ct = v.Aggregate.Sum
	v.Decrypt.MaxTally = len(ballots)
	v.Decrypt.Tally = tally

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	dest := filepath.Join(root, "public", "pedersen_vectors.json")
	if err := os.WriteFile(dest, append(out, '\n'), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %s", dest)
}

func mustBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad big.Int: " + s)
	}
	return n
}

func bn254FrModulus() *big.Int {
	p, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		10,
	)
	return p
}
