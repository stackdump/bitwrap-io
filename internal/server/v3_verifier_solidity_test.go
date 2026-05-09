package server

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/stackdump/bitwrap-io/internal/store"
	"github.com/stackdump/bitwrap-io/prover"
)

func attachV3KeyStore(t *testing.T, srv *Server) {
	t.Helper()
	attachV3FullProver(t, srv)

	ks, err := prover.NewKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"voteCastHomomorphic_8", "tallyDecrypt_8"} {
		cc, ok := srv.proverSvc.Prover().GetCircuit(name)
		if !ok {
			t.Fatalf("missing compiled circuit %s", name)
		}
		if err := ks.Save(name, cc); err != nil {
			t.Fatalf("save keys for %s: %v", name, err)
		}
	}
	srv.keyStore = ks
}

func TestHandleVKV3SolidityShape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles v3 circuits")
	}
	srv := testServer(t)
	attachV3KeyStore(t, srv)

	for _, circuit := range []string{"voteCastHomomorphic_8", "tallyDecrypt_8"} {
		w := getReq(t, srv, "/api/vk/"+circuit+"/solidity")
		if w.Code != 200 {
			t.Fatalf("%s: expected 200, got %d body=%q", circuit, w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
			t.Fatalf("%s: content-type=%q", circuit, ct)
		}
		body := w.Body.String()
		if !strings.Contains(body, "contract Verifier") {
			t.Fatalf("%s: expected verifier contract, got %q", circuit, body[:min(160, len(body))])
		}
	}
}

func TestHandleVKV3SolidityCompilesAndVerifiesOnChain(t *testing.T) {
	t.Skip("known limitation: exported BabyJubJub-based Groth16 verifiers reject valid proofs on-chain (see issue #6)")
	if testing.Short() {
		t.Skip("requires large circuit compile + forge")
	}
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not installed")
	}

	srv := testServer(t)
	attachV3KeyStore(t, srv)

	// Build a real v3 lifecycle:
	// - one captured vote proof for voteCastHomomorphic_8
	// - close artifact (tally.json shape) for tallyDecrypt_8
	pollID, sk, pk := seedV3Poll(t, srv)
	_, creatorAddr := testCreatorDevSign(t, "warm-up")
	poll, _ := srv.store.ReadPoll(pollID)
	poll.Creator = creatorAddr
	_ = srv.store.SavePoll(poll)

	registerTestVoter(t, srv, pollID)
	registerTestVoter(t, srv, pollID)

	voteProof, voteCiphertexts, voteNullifier, voteRoot := buildV3VoteRequest(t, srv, pollID, pk, 1, 8)
	alignPollRoot(t, srv, pollID, voteRoot)
	voteBody := map[string]any{
		"nullifier":   voteNullifier.String(),
		"ciphertexts": voteCiphertexts,
		"proofBytes":  base64.StdEncoding.EncodeToString(voteProof),
	}
	if w := postJSON(t, srv, "/api/polls/"+pollID+"/vote", voteBody); w.Code != 200 {
		t.Fatalf("vote fixture cast: %d body=%q", w.Code, w.Body.String())
	}
	// Additional votes for non-trivial tally close artifact.
	castV3Vote(t, srv, pollID, pk, 4, 8)
	castV3Vote(t, srv, pollID, pk, 6, 8)

	decryptProof, tallies := buildTallyDecryptProof(t, srv, pollID, sk, pk)
	sig, _ := signAggregate(t, pollID, tallies)
	aggregateBody := map[string]any{
		"creator":           creatorAddr,
		"signature":         sig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(decryptProof),
	}
	if w := postJSON(t, srv, "/api/polls/"+pollID+"/aggregate", aggregateBody); w.Code != 200 {
		t.Fatalf("aggregate: %d body=%q", w.Code, w.Body.String())
	}
	artifact, err := srv.store.ReadHomomorphicTally(pollID)
	if err != nil {
		t.Fatalf("read tally artifact: %v", err)
	}
	decryptProofBytes, err := base64.StdEncoding.DecodeString(artifact.DecryptProof)
	if err != nil {
		t.Fatalf("decode decrypt proof: %v", err)
	}

	voteInputs := buildVotePublicInputs(t, pollID, voteRoot.String(), voteNullifier.String(), pk, voteCiphertexts)
	tallyInputs := buildTallyPublicInputs(t, pk, artifact.Aggregate, artifact.Tallies)
	voteProofWords := proofWords(t, voteProof, 8)
	tallyProofWords := proofWords(t, decryptProofBytes, 8)

	voteVerifier := getReq(t, srv, "/api/vk/voteCastHomomorphic_8/solidity")
	if voteVerifier.Code != 200 {
		t.Fatalf("vote verifier: %d body=%q", voteVerifier.Code, voteVerifier.Body.String())
	}
	tallyVerifier := getReq(t, srv, "/api/vk/tallyDecrypt_8/solidity")
	if tallyVerifier.Code != 200 {
		t.Fatalf("tally verifier: %d body=%q", tallyVerifier.Code, tallyVerifier.Body.String())
	}

	foundryDir := t.TempDir()
	for _, d := range []string{"src", "test"} {
		if err := os.MkdirAll(filepath.Join(foundryDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(foundryDir, "foundry.toml"), []byte(v3FoundryToml), 0o644); err != nil {
		t.Fatal(err)
	}

	voteVerifierSol, err := renameVerifierContract(voteVerifier.Body.String(), "Verifier_voteCastHomomorphic_8")
	if err != nil {
		t.Fatal(err)
	}
	tallyVerifierSol, err := renameVerifierContract(tallyVerifier.Body.String(), "Verifier_tallyDecrypt_8")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foundryDir, "src", "Verifier_voteCastHomomorphic_8.sol"), []byte(voteVerifierSol), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foundryDir, "src", "Verifier_tallyDecrypt_8.sol"), []byte(tallyVerifierSol), 0o644); err != nil {
		t.Fatal(err)
	}

	testCode := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {Verifier_voteCastHomomorphic_8} from "../src/Verifier_voteCastHomomorphic_8.sol";
import {Verifier_tallyDecrypt_8} from "../src/Verifier_tallyDecrypt_8.sol";

contract V3PollHarnessTest is Test {
    Verifier_voteCastHomomorphic_8 voteVerifier;
    Verifier_tallyDecrypt_8 tallyVerifier;

    function setUp() public {
        voteVerifier = new Verifier_voteCastHomomorphic_8();
        tallyVerifier = new Verifier_tallyDecrypt_8();
    }

    function testVerifyCastVoteProof() public view {
        uint256[8] memory proof = [%s];
        uint256[38] memory inputs = [%s];
        voteVerifier.verifyProof(proof, inputs);
    }

    function testVerifyTallyDecryptProof() public view {
        uint256[8] memory proof = [%s];
        uint256[42] memory inputs = [%s];
        tallyVerifier.verifyProof(proof, inputs);
    }
}
`, strings.Join(voteProofWords, ","), strings.Join(voteInputs, ","), strings.Join(tallyProofWords, ","), strings.Join(tallyInputs, ","))
	if err := os.WriteFile(filepath.Join(foundryDir, "test", "V3PollHarness.t.sol"), []byte(testCode), 0o644); err != nil {
		t.Fatal(err)
	}

	runLocalCmd(t, foundryDir, "git", "init")
	runLocalCmd(t, foundryDir, "forge", "install", "foundry-rs/forge-std")
	runLocalCmd(t, foundryDir, "forge", "build")
	runLocalCmd(t, foundryDir, "forge", "test", "-vv")
}

func TestBundleVoteV3ContainsExpectedFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles v3 circuits")
	}
	srv := testServer(t)
	attachV3KeyStore(t, srv)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/bundle/vote-v3", nil)
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d body=%q", w.Code, w.Body.String())
	}

	r, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("zip parse: %v", err)
	}

	files := map[string]bool{}
	for _, f := range r.File {
		files[f.Name] = true
	}
	for _, name := range []string{
		"foundry.toml",
		"README.md",
		"src/BitwrapZKPollV3.sol",
		"src/Verifier_voteCastHomomorphic_8.sol",
		"src/Verifier_tallyDecrypt_8.sol",
		"test/BitwrapZKPollV3.t.sol",
		"script/DeployV3.s.sol",
	} {
		if !files[name] {
			t.Fatalf("bundle missing %s", name)
		}
	}
}

func buildVotePublicInputs(
	t *testing.T,
	pollID, root, nullifier string,
	pk tedwards.PointAffine,
	ciphertexts []store.HomomorphicCiphertext,
) []string {
	t.Helper()
	pollIDInt := new(big.Int).SetBytes([]byte(pollID))
	pkx, pky := pointStrings(&pk)

	inputs := []string{
		pollIDInt.String(),
		root,
		nullifier,
		"8",
		pkx,
		pky,
	}
	for i := 0; i < len(ciphertexts); i++ {
		aBytes, err := hex.DecodeString(ciphertexts[i].A)
		if err != nil {
			t.Fatalf("decode ciphertext[%d].A: %v", i, err)
		}
		bBytes, err := hex.DecodeString(ciphertexts[i].B)
		if err != nil {
			t.Fatalf("decode ciphertext[%d].B: %v", i, err)
		}
		a, err := prover.DecodePoint(aBytes)
		if err != nil {
			t.Fatalf("decode point A[%d]: %v", i, err)
		}
		b, err := prover.DecodePoint(bBytes)
		if err != nil {
			t.Fatalf("decode point B[%d]: %v", i, err)
		}
		ax, ay := pointStrings(&a)
		bx, by := pointStrings(&b)
		inputs = append(inputs, ax, ay, bx, by)
	}
	if len(inputs) != 38 {
		t.Fatalf("vote input length = %d, want 38", len(inputs))
	}
	return inputs
}

func buildTallyPublicInputs(
	t *testing.T,
	pk tedwards.PointAffine,
	aggregate []store.HomomorphicCiphertext,
	tallies []int64,
) []string {
	t.Helper()
	pkx, pky := pointStrings(&pk)
	inputs := []string{pkx, pky}
	for i := 0; i < len(aggregate); i++ {
		aBytes, err := hex.DecodeString(aggregate[i].A)
		if err != nil {
			t.Fatalf("decode aggregate[%d].A: %v", i, err)
		}
		bBytes, err := hex.DecodeString(aggregate[i].B)
		if err != nil {
			t.Fatalf("decode aggregate[%d].B: %v", i, err)
		}
		a, err := prover.DecodePoint(aBytes)
		if err != nil {
			t.Fatalf("decode aggregate point A[%d]: %v", i, err)
		}
		b, err := prover.DecodePoint(bBytes)
		if err != nil {
			t.Fatalf("decode aggregate point B[%d]: %v", i, err)
		}
		ax, ay := pointStrings(&a)
		bx, by := pointStrings(&b)
		inputs = append(inputs, ax, ay, bx, by)
	}
	for _, tally := range tallies {
		inputs = append(inputs, fmt.Sprintf("%d", tally))
	}
	if len(inputs) != 42 {
		t.Fatalf("tally input length = %d, want 42", len(inputs))
	}
	return inputs
}

func pointStrings(p *tedwards.PointAffine) (string, string) {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return x.String(), y.String()
}

func proofWords(t *testing.T, proof []byte, want int) []string {
	t.Helper()
	if len(proof) == 0 {
		t.Fatal("empty proof bytes")
	}
	decoded := groth16.NewProof(ecc.BN254)
	if _, err := decoded.ReadFrom(bytes.NewReader(proof)); err != nil {
		t.Fatalf("invalid groth16 proof encoding: %v", err)
	}
	var raw bytes.Buffer
	if _, err := decoded.WriteRawTo(&raw); err != nil {
		t.Fatalf("raw proof serialization failed: %v", err)
	}
	rawBytes := raw.Bytes()
	if len(rawBytes) < want*32 {
		t.Fatalf("unexpected raw proof length %d", len(rawBytes))
	}
	out := make([]string, want)
	for i := 0; i < want; i++ {
		v := new(big.Int).SetBytes(rawBytes[i*32 : (i+1)*32])
		out[i] = v.String()
	}
	return out
}

func runLocalCmd(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed:\n%s\n%v", name, strings.Join(args, " "), out, err)
	}
}
