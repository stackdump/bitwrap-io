//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	circuits "github.com/stackdump/bitwrap-io/prover"
)

// compiled holds loaded circuit keys
var compiled = map[string]*compiledCircuit{}

type compiledCircuit struct {
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
}

func main() {
	fmt.Println("bitwrap-prover WASM loaded")

	api := map[string]interface{}{
		"version":       js.FuncOf(version),
		"compileCircuit": js.FuncOf(compileCircuit),
		"loadKeys":      js.FuncOf(loadKeys),
		"prove":         js.FuncOf(prove),
		"verify":        js.FuncOf(verify),
		"mimcHash":      js.FuncOf(mimcHashJS),
		"listCircuits":  js.FuncOf(listCircuits),
	}
	js.Global().Set("bitwrapProver", js.ValueOf(api))

	// Block forever
	select {}
}

func version(_ js.Value, _ []js.Value) interface{} {
	return "0.1.0"
}

// compileCircuit("transfer") — compiles a circuit from scratch (slow, ~seconds)
// Returns: {constraints: N, publicVars: N, privateVars: N}
func compileCircuit(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return jsError("usage: compileCircuit(name)")
	}
	name := args[0].String()

	circuit := circuitByName(name)
	if circuit == nil {
		return jsError(fmt.Sprintf("unknown circuit: %s", name))
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return jsError(fmt.Sprintf("compile failed: %v", err))
	}

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return jsError(fmt.Sprintf("setup failed: %v", err))
	}

	compiled[name] = &compiledCircuit{cs: cs, pk: pk, vk: vk}

	return js.ValueOf(map[string]interface{}{
		"constraints": cs.GetNbConstraints(),
		"publicVars":  cs.GetNbPublicVariables(),
		"privateVars": cs.GetNbSecretVariables(),
	})
}

// loadKeys("transfer", csBytes, pkBytes, vkBytes) — load pre-compiled keys
// csBytes/pkBytes/vkBytes are Uint8Array from fetched .cs/.pk/.vk files
func loadKeys(_ js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return jsError("usage: loadKeys(name, csBytes, pkBytes, vkBytes)")
	}
	name := args[0].String()

	csData := jsToBytes(args[1])
	pkData := jsToBytes(args[2])
	vkData := jsToBytes(args[3])

	cs := groth16.NewCS(ecc.BN254)
	if _, err := cs.ReadFrom(newBytesReader(csData)); err != nil {
		return jsError(fmt.Sprintf("load cs: %v", err))
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(newBytesReader(pkData)); err != nil {
		return jsError(fmt.Sprintf("load pk: %v", err))
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(newBytesReader(vkData)); err != nil {
		return jsError(fmt.Sprintf("load vk: %v", err))
	}

	compiled[name] = &compiledCircuit{cs: cs, pk: pk, vk: vk}

	return js.ValueOf(map[string]interface{}{
		"constraints": cs.GetNbConstraints(),
		"publicVars":  cs.GetNbPublicVariables(),
		"privateVars": cs.GetNbSecretVariables(),
	})
}

// prove("transfer", {from: "1", to: "2", ...}) — generate Groth16 proof
// Returns: {proof: "...", publicInputs: [...]}
func prove(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("usage: prove(circuit, witnessJSON)")
	}
	name := args[0].String()

	cc, ok := compiled[name]
	if !ok {
		return jsError(fmt.Sprintf("circuit %q not loaded — call compileCircuit or loadKeys first", name))
	}

	// Parse witness from JS object or JSON string
	var witnessMap map[string]string
	if args[1].Type() == js.TypeString {
		if err := json.Unmarshal([]byte(args[1].String()), &witnessMap); err != nil {
			return jsError(fmt.Sprintf("invalid witness JSON: %v", err))
		}
	} else {
		witnessMap = jsObjectToStringMap(args[1])
	}

	// Build assignment using the witness factory
	factory := &circuits.ArcnetWitnessFactory{}
	assignment, err := factory.CreateAssignment(name, witnessMap)
	if err != nil {
		return jsError(fmt.Sprintf("witness creation failed: %v", err))
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return jsError(fmt.Sprintf("witness build failed: %v", err))
	}

	proof, err := groth16.Prove(cc.cs, cc.pk, witness)
	if err != nil {
		return jsError(fmt.Sprintf("prove failed: %v", err))
	}

	// Serialize proof
	var proofBuf bytesBuffer
	proof.WriteTo(&proofBuf)

	// Get public witness
	pubWitness, _ := witness.Public()
	var pubBuf bytesBuffer
	pubWitness.WriteTo(&pubBuf)

	return js.ValueOf(map[string]interface{}{
		"proof":         bytesToJS(proofBuf.data),
		"publicWitness": bytesToJS(pubBuf.data),
	})
}

// verify("transfer", proofBytes, publicWitnessBytes) — verify a proof
func verify(_ js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return jsError("usage: verify(circuit, proofBytes, publicWitnessBytes)")
	}
	name := args[0].String()

	cc, ok := compiled[name]
	if !ok {
		return jsError(fmt.Sprintf("circuit %q not loaded", name))
	}

	proofData := jsToBytes(args[1])
	pubData := jsToBytes(args[2])

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(newBytesReader(proofData)); err != nil {
		return jsError(fmt.Sprintf("invalid proof: %v", err))
	}

	pubWitness, err := frontend.NewWitness(nil, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return jsError(fmt.Sprintf("create witness: %v", err))
	}
	if _, err := pubWitness.ReadFrom(newBytesReader(pubData)); err != nil {
		return jsError(fmt.Sprintf("invalid public witness: %v", err))
	}

	err = groth16.Verify(proof, cc.vk, pubWitness)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"valid": false, "error": err.Error()})
	}
	return js.ValueOf(map[string]interface{}{"valid": true})
}

// mimcHash("42", "100") — compute MiMC hash (for building witnesses client-side)
func mimcHashJS(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("usage: mimcHash(a, b)")
	}
	h := mimc.NewMiMC()
	for _, arg := range args {
		var e fr.Element
		b := new(big.Int)
		b.SetString(arg.String(), 10)
		e.SetBigInt(b)
		eb := e.Bytes()
		h.Write(eb[:])
	}
	result := h.Sum(nil)
	var r fr.Element
	r.SetBytes(result)
	var rBig big.Int
	r.BigInt(&rBig)
	return rBig.String()
}

// listCircuits() — list loaded circuits
func listCircuits(_ js.Value, _ []js.Value) interface{} {
	names := make([]interface{}, 0, len(compiled))
	for name := range compiled {
		names = append(names, name)
	}
	return js.ValueOf(names)
}

// circuitByName returns a zero-valued circuit struct for compilation
func circuitByName(name string) frontend.Circuit {
	switch name {
	case "transfer":
		return &circuits.TransferCircuit{}
	case "transferFrom":
		return &circuits.TransferFromCircuit{}
	case "mint":
		return &circuits.MintCircuit{}
	case "burn":
		return &circuits.BurnCircuit{}
	case "approve":
		return &circuits.ApproveCircuit{}
	case "vestClaim":
		return &circuits.VestingClaimCircuit{}
	case "voteCast":
		return &circuits.VoteCastCircuit{}
	default:
		return nil
	}
}

// Helpers

func jsError(msg string) interface{} {
	return js.ValueOf(map[string]interface{}{"error": msg})
}

func jsToBytes(v js.Value) []byte {
	length := v.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, v)
	return buf
}

func bytesToJS(data []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(arr, data)
	return arr
}

func jsObjectToStringMap(v js.Value) map[string]string {
	m := make(map[string]string)
	keys := js.Global().Get("Object").Call("keys", v)
	for i := 0; i < keys.Length(); i++ {
		key := keys.Index(i).String()
		m[key] = v.Get(key).String()
	}
	return m
}

// bytesBuffer wraps a byte slice as an io.Writer
type bytesBuffer struct {
	data []byte
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

// bytesReader wraps a byte slice as an io.Reader
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
