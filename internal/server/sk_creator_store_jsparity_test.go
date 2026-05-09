package server

import (
	"os/exec"
	"testing"
)

// TestSkCreatorStoreJS runs the Node-side unit tests for
// public/sk-creator-store.js. The module is pure-data (save/load
// roundtrip, backup parse, tamper detection) and a divergence here
// would silently break the v3 close flow at runtime, so we gate it
// on `go test`.
func TestSkCreatorStoreJS(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping sk-creator-store JS tests")
	}
	cmd := exec.Command("node", "public/sk_creator_store_test.mjs")
	cmd.Dir = findProjectRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sk-creator-store JS tests failed:\n%s\n%v", out, err)
	}
	t.Logf("%s", out)
}
