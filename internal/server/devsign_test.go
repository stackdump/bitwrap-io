package server

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDevSignRecovery(t *testing.T) {
	msg := "bitwrap-create-poll:hello"

	// Test devSign → RecoverAddress round trip
	sig, addr := devSign(msg)
	recovered, err := RecoverAddress(msg, sig)
	if err != nil {
		t.Fatalf("RecoverAddress(devSign): %v", err)
	}
	t.Logf("devSign addr:   %s", addr)
	t.Logf("recovered addr: %s", recovered)

	if recovered != addr {
		t.Errorf("devSign/RecoverAddress mismatch")
	}

	// Also test with cast-generated signature if cast is available
	castBin, err := exec.LookPath("cast")
	if err != nil {
		t.Log("cast not installed, skipping cast parity test")
		return
	}

	privKey := "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	cmd := exec.Command(castBin, "wallet", "sign", "--private-key", privKey, msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cast wallet sign: %v\n%s", err, out)
	}
	castSig := strings.TrimSpace(string(out))

	castRecovered, err := RecoverAddress(msg, castSig)
	if err != nil {
		t.Fatalf("RecoverAddress(cast sig): %v", err)
	}
	t.Logf("cast recovered: %s", castRecovered)
	t.Logf("expected:       0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")

	if !strings.EqualFold(castRecovered, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266") {
		t.Errorf("RecoverAddress failed for cast signature too — RecoverAddress is broken")
	}
}
