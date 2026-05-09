package prover

import (
	"os"
	"testing"

	"github.com/consensys/gnark/frontend"
)

// TestNativeExportKeys writes cs/pk/vk bytes for a circuit (selected
// via NATIVE_EXPORT_CIRCUIT, default `mint`) to /tmp/native-keys-<name>.{cs,pk,vk}
// using the same WriteTo path the keystore uses.
//
// Pairs with public/v3_wasm_export_diag.mjs which dumps the wasm-flavored
// bytes for the same circuit. A byte-level diff localizes the cross-arch
// serialization bug from issue #3.
//
// Run: go test -run TestNativeExportKeys -v ./prover
//
//	NATIVE_EXPORT_CIRCUIT=voteCastHomomorphic_8 go test -timeout 600s -run TestNativeExportKeys -v ./prover
func TestNativeExportKeys(t *testing.T) {
	name := os.Getenv("NATIVE_EXPORT_CIRCUIT")
	if name == "" {
		name = "mint"
	}

	circuit := nativeCircuitByName(name)
	if circuit == nil {
		t.Fatalf("unknown circuit %q", name)
	}

	p := NewProver()
	cc, err := p.CompileCircuit(name, circuit)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}

	csOut := "/tmp/native-keys-" + name + ".cs"
	pkOut := "/tmp/native-keys-" + name + ".pk"
	vkOut := "/tmp/native-keys-" + name + ".vk"

	if f, err := os.Create(csOut); err != nil {
		t.Fatal(err)
	} else {
		if _, err := cc.CS.WriteTo(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
	if f, err := os.Create(pkOut); err != nil {
		t.Fatal(err)
	} else {
		if _, err := cc.ProvingKey.WriteTo(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}
	if f, err := os.Create(vkOut); err != nil {
		t.Fatal(err)
	} else {
		if _, err := cc.VerifyingKey.WriteTo(f); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
	}

	csInfo, _ := os.Stat(csOut)
	pkInfo, _ := os.Stat(pkOut)
	vkInfo, _ := os.Stat(vkOut)
	t.Logf("wrote %s: cs=%dB pk=%dB vk=%dB", name, csInfo.Size(), pkInfo.Size(), vkInfo.Size())
}

func nativeCircuitByName(name string) frontend.Circuit {
	switch name {
	case "transfer":
		return &TransferCircuit{}
	case "transferFrom":
		return &TransferFromCircuit{}
	case "mint":
		return &MintCircuit{}
	case "burn":
		return &BurnCircuit{}
	case "approve":
		return &ApproveCircuit{}
	case "voteCast":
		return &VoteCastCircuit{}
	case "tallyProof", "tallyProof_16":
		return &TallyProofCircuit16{}
	case "tallyProof_64":
		return &TallyProofCircuit64{}
	case "tallyProof_256":
		return &TallyProofCircuit256{}
	case "voteCastHomomorphic_8":
		return &VoteCastHomomorphicCircuit_8{}
	case "tallyDecrypt_8":
		return &TallyDecryptCircuit_8{}
	}
	return nil
}
