package seal

import (
	"strings"
	"testing"
)

func TestSealJSONLD(t *testing.T) {
	raw := []byte(`{"@context":"https://pflow.xyz/schema","@type":"PetriNet","places":{},"transitions":{},"arcs":[],"token":[]}`)
	cid, canonical, err := SealJSONLD(raw)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	if cid == "" {
		t.Fatal("empty CID")
	}
	if !strings.HasPrefix(cid, "z") {
		t.Fatalf("CID should start with z (base58btc), got %s", cid)
	}
	if len(canonical) == 0 {
		t.Fatal("empty canonical output")
	}
}

func TestSealDeterministic(t *testing.T) {
	raw := []byte(`{"@context":"https://pflow.xyz/schema","@type":"PetriNet","places":{},"transitions":{},"arcs":[],"token":[]}`)
	cid1, _, _ := SealJSONLD(raw)
	cid2, _, _ := SealJSONLD(raw)
	if cid1 != cid2 {
		t.Fatalf("CIDs differ: %s vs %s", cid1, cid2)
	}
}

func TestSealInvalidJSON(t *testing.T) {
	_, _, err := SealJSONLD([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
