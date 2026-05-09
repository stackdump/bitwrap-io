package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	gtw "github.com/consensys/gnark/std/algebra/native/twistededwards"

	"github.com/stackdump/bitwrap-io/internal/server"
	"github.com/stackdump/bitwrap-io/prover"
)

// Exit codes for the close-poll subcommand.
const (
	exitOK            = 0 // success
	exitErr           = 1 // fatal error
	exitNeedsSignature = 2 // tallies computed; re-run with --signature or --eth-key
)

// closePollUsage prints usage for the close-poll subcommand.
func closePollUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `Usage: bitwrap close-poll <pollID> [flags]

Closes a v3 ZK poll by aggregating ciphertexts, decrypting tallies with the
creator's BabyJubJub secret key, generating a Groth16 decrypt proof, and
posting the signed aggregate request to the server.

When --signature is omitted the subcommand prints the canonical EIP-191
message that must be signed by the poll creator's Ethereum wallet and exits
with code 2 (exitNeedsSignature).  Sign the printed message and re-run with
--signature or supply --eth-key to sign internally.

Flags:
`)
	fs.PrintDefaults()
}

// runClosePoll is the implementation of `bitwrap close-poll`.
// Returns an OS exit code:
//
//	0 (exitOK)             – poll closed successfully.
//	1 (exitErr)            – fatal error (details printed to stderr).
//	2 (exitNeedsSignature) – tallies computed and printed; re-run with --signature.
func runClosePoll(args []string) int {
	fs := flag.NewFlagSet("close-poll", flag.ContinueOnError)
	fs.Usage = func() { closePollUsage(fs) }

	skHex := fs.String("sk-hex", "", "Creator's BabyJubJub secret key (hex, required)")
	sigHex := fs.String("signature", "", "EIP-191 signature over bitwrap-aggregate-tally:{pollID}:{tallies} (optional; if omitted the payload is printed for external signing)")
	ethKeyHex := fs.String("eth-key", "", "Ethereum private key hex to sign internally (alternative to --signature)")
	serverURL := fs.String("server", "http://localhost:8088", "Base URL of the bitwrap server")
	keyDir := fs.String("key-dir", "", "Directory for persistent circuit keys (enables fast restarts)")

	// Extract the poll ID from args: it is the first arg that does not start
	// with "-".  The Go flag package stops at the first non-flag arg, so if
	// the caller writes `close-poll <id> --flag ...` the flags after <id> are
	// left unparsed.  We detect this and re-parse the tail so that the user
	// can place the poll ID anywhere in the argument list.
	var pollID string
	var flagArgs []string
	for i, a := range args {
		if len(a) > 0 && a[0] != '-' && pollID == "" {
			pollID = a
			flagArgs = append(flagArgs, args[:i]...)
			flagArgs = append(flagArgs, args[i+1:]...)
			break
		}
	}
	if pollID == "" {
		flagArgs = args
	}

	if err := fs.Parse(flagArgs); err != nil {
		return exitErr
	}

	// Fall back to first remaining positional if pollID not yet found.
	if pollID == "" && fs.NArg() > 0 {
		pollID = fs.Arg(0)
	}

	if pollID == "" {
		fmt.Fprintf(os.Stderr, "error: exactly one positional argument <pollID> required\n")
		closePollUsage(fs)
		return exitErr
	}

	if *skHex == "" {
		fmt.Fprintf(os.Stderr, "error: --sk-hex is required\n")
		return exitErr
	}
	if *sigHex != "" && *ethKeyHex != "" {
		fmt.Fprintf(os.Stderr, "error: --signature and --eth-key are mutually exclusive\n")
		return exitErr
	}

	return closePollCore(pollID, *skHex, *sigHex, *ethKeyHex, *serverURL, *keyDir, http.DefaultClient)
}

// closePollCore is the testable core of the close-poll subcommand.
// client can be overridden in tests to target an httptest.Server.
func closePollCore(pollID, skHex, sigHex, ethKeyHex, serverURL, keyDir string, client *http.Client) int {
	// 1. Parse BabyJubJub secret key.
	skBytes, err := hex.DecodeString(strings.TrimPrefix(skHex, "0x"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --sk-hex: %v\n", err)
		return exitErr
	}
	sk := new(big.Int).SetBytes(skBytes)

	// 2. Fetch poll metadata.
	poll, err := fetchPoll(client, serverURL, pollID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching poll: %v\n", err)
		return exitErr
	}
	if poll.VoteSchemaVersion != 3 {
		fmt.Fprintf(os.Stderr, "error: poll %q is v%d, close-poll only supports v3\n", pollID, poll.VoteSchemaVersion)
		return exitErr
	}
	if poll.Status == "closed" {
		fmt.Fprintf(os.Stderr, "error: poll %q is already closed\n", pollID)
		return exitErr
	}

	// 3. Decode creator's public key from poll.
	pkBytes, err := hex.DecodeString(poll.PkCreator)
	if err != nil || len(pkBytes) != 32 {
		fmt.Fprintf(os.Stderr, "error: poll pkCreator is malformed\n")
		return exitErr
	}
	pk, err := prover.DecodePoint(pkBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: decode pkCreator: %v\n", err)
		return exitErr
	}

	// 4. Fetch votes.
	voteCiphertexts, err := fetchVoteCiphertexts(client, serverURL, pollID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching votes: %v\n", err)
		return exitErr
	}
	if len(voteCiphertexts) == 0 {
		fmt.Fprintf(os.Stderr, "error: poll has no votes to aggregate\n")
		return exitErr
	}

	// 5. Aggregate ciphertexts per-bin.
	aggA := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	aggB := make([]tedwards.PointAffine, prover.TallyDecryptChoices)
	for j := range aggA {
		aggA[j].X.SetZero()
		aggA[j].Y.SetOne()
		aggB[j].X.SetZero()
		aggB[j].Y.SetOne()
	}
	for i, cts := range voteCiphertexts {
		if len(cts) != prover.TallyDecryptChoices {
			fmt.Fprintf(os.Stderr, "error: vote[%d] has %d ciphertexts, want %d\n", i, len(cts), prover.TallyDecryptChoices)
			return exitErr
		}
		for j := 0; j < prover.TallyDecryptChoices; j++ {
			aBuf, err := hex.DecodeString(cts[j].A)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: vote[%d].ct[%d].A decode: %v\n", i, j, err)
				return exitErr
			}
			bBuf, err := hex.DecodeString(cts[j].B)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: vote[%d].ct[%d].B decode: %v\n", i, j, err)
				return exitErr
			}
			a, err := prover.DecodePoint(aBuf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: vote[%d].ct[%d].A: %v\n", i, j, err)
				return exitErr
			}
			b, err := prover.DecodePoint(bBuf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: vote[%d].ct[%d].B: %v\n", i, j, err)
				return exitErr
			}
			aggA[j].Add(&aggA[j], &a)
			aggB[j].Add(&aggB[j], &b)
		}
	}

	// 6. Decrypt each bin to recover tallies.
	tallies := make([]int64, prover.TallyDecryptChoices)
	maxTally := len(voteCiphertexts) // upper bound: can't have more than N votes for one bin
	for j := 0; j < prover.TallyDecryptChoices; j++ {
		ct := prover.Ciphertext{A: aggA[j], B: aggB[j]}
		t_, err := prover.Decrypt(ct, sk, maxTally)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: decrypt bin %d: %v\n", j, err)
			return exitErr
		}
		tallies[j] = int64(t_)
	}

	// 7. Build and print the signing payload.
	sigPayload := server.AggregateSigPayload(pollID, tallies)
	fmt.Printf("Tallies: %v\n", tallies)
	fmt.Printf("Signing payload: %s\n", sigPayload)

	// 8. Resolve signature.
	var finalSig, creator string
	switch {
	case sigHex != "":
		finalSig = sigHex
		creator = poll.Creator
	case ethKeyHex != "":
		s, addr, err := server.SignEIP191(sigPayload, ethKeyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: sign with eth-key: %v\n", err)
			return exitErr
		}
		finalSig = s
		creator = addr
	default:
		fmt.Printf("\nSign the payload above with your Ethereum wallet, then re-run with:\n")
		fmt.Printf("  bitwrap close-poll %s --sk-hex=<hex> --signature=<sig>\n", pollID)
		return exitNeedsSignature
	}

	// 9. Compile tallyDecrypt_8 and build proof.
	fmt.Printf("Compiling tallyDecrypt_8 circuit (this may take a few seconds)...\n")
	proofBytes, err := buildTallyDecryptProof(aggA, aggB, sk, &pk, tallies, keyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build decrypt proof: %v\n", err)
		return exitErr
	}
	fmt.Printf("Proof generated (%d bytes)\n", len(proofBytes))

	// 10. POST aggregate request.
	body := map[string]any{
		"creator":           creator,
		"signature":         finalSig,
		"tallies":           tallies,
		"decryptProofBytes": base64.StdEncoding.EncodeToString(proofBytes),
	}
	respBody, statusCode, err := postJSON(client, serverURL+"/api/polls/"+pollID+"/aggregate", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: POST aggregate: %v\n", err)
		return exitErr
	}
	if statusCode == http.StatusConflict {
		fmt.Printf("Poll %q is already closed (server returned 409).\n", pollID)
		return exitOK
	}
	if statusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "error: server returned %d: %s\n", statusCode, string(respBody))
		return exitErr
	}
	fmt.Printf("Poll %q closed successfully.\n", pollID)
	// Pretty-print the server response.
	var pretty any
	if json.Unmarshal(respBody, &pretty) == nil {
		if out, err := json.MarshalIndent(pretty, "", "  "); err == nil {
			fmt.Printf("%s\n", out)
		}
	}
	return exitOK
}

// pollMeta is a minimal struct for deserialising GET /api/polls/{id}.
type pollMeta struct {
	ID                string `json:"id"`
	Creator           string `json:"creator"`
	PkCreator         string `json:"pkCreator"`
	VoteSchemaVersion int    `json:"voteSchemaVersion"`
	Status            string `json:"status"`
}

// fetchPoll fetches poll metadata from GET /api/polls/{id}.
func fetchPoll(client *http.Client, serverURL, pollID string) (*pollMeta, error) {
	resp, err := client.Get(serverURL + "/api/polls/" + pollID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("poll %q not found", pollID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var wrapper struct {
		Poll pollMeta `json:"poll"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decode poll: %w", err)
	}
	return &wrapper.Poll, nil
}

// ciphertextHex mirrors store.HomomorphicCiphertext.
type ciphertextHex struct {
	A string `json:"A"`
	B string `json:"B"`
}

// fetchVoteCiphertexts fetches vote ciphertexts from GET /api/polls/{id}/votes.
// Returns a slice of ciphertext sets, one per vote.
func fetchVoteCiphertexts(client *http.Client, serverURL, pollID string) ([][]ciphertextHex, error) {
	resp, err := client.Get(serverURL + "/api/polls/" + pollID + "/votes")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var wrapper struct {
		Votes []struct {
			Ciphertexts []ciphertextHex `json:"ciphertexts"`
		} `json:"votes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<24)).Decode(&wrapper); err != nil {
		return nil, fmt.Errorf("decode votes: %w", err)
	}
	out := make([][]ciphertextHex, len(wrapper.Votes))
	for i, v := range wrapper.Votes {
		out[i] = v.Ciphertexts
	}
	return out, nil
}

// buildTallyDecryptProof compiles tallyDecrypt_8 (or loads from keyDir),
// builds the full witness, and returns the serialised Groth16 proof bytes.
func buildTallyDecryptProof(
	aggA, aggB []tedwards.PointAffine,
	sk *big.Int,
	pk *tedwards.PointAffine,
	tallies []int64,
	keyDir string,
) ([]byte, error) {
	p := prover.NewProver()

	var cc *prover.CompiledCircuit
	if keyDir != "" {
		ks, err := prover.NewKeyStore(keyDir)
		if err == nil && ks.Has("tallyDecrypt_8") {
			loaded, err := ks.Load("tallyDecrypt_8")
			if err == nil {
				cc = loaded
			}
		}
	}
	if cc == nil {
		compiled, err := p.CompileCircuit("tallyDecrypt_8", &prover.TallyDecryptCircuit_8{})
		if err != nil {
			return nil, fmt.Errorf("compile circuit: %w", err)
		}
		cc = compiled
		if keyDir != "" {
			ks, err := prover.NewKeyStore(keyDir)
			if err == nil {
				_ = ks.Save("tallyDecrypt_8", cc)
			}
		}
	}

	// Build witness.
	w := &prover.TallyDecryptCircuit_8{}
	w.SkCreator = sk
	w.PkCreator = pointToGTW(pk)
	for j := 0; j < prover.TallyDecryptChoices; j++ {
		w.A[j] = pointToGTW(&aggA[j])
		w.B[j] = pointToGTW(&aggB[j])
		w.Tallies[j] = tallies[j]
	}

	wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("build witness: %w", err)
	}
	proof, err := groth16.Prove(cc.CS, cc.ProvingKey, wit)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("serialize proof: %w", err)
	}
	return buf.Bytes(), nil
}

// pointToGTW converts a tedwards.PointAffine (gnark-crypto) to a gnark-circuit
// twistededwards.Point used in circuit witness assignments.
func pointToGTW(p *tedwards.PointAffine) gtw.Point {
	var x, y big.Int
	p.X.BigInt(&x)
	p.Y.BigInt(&y)
	return gtw.Point{X: &x, Y: &y}
}

// postJSON marshals body as JSON, POSTs it to url, and returns the
// response body bytes and HTTP status code.
func postJSON(client *http.Client, url string, body any) ([]byte, int, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, err
}
