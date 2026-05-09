package server

import "testing"

// TestJSDevWalletParity validates that a signature produced by the
// browser-side dev-wallet.js (signMessage) verifies under VerifySignature.
// The vector below was produced by running:
//
//	node sign_test.mjs public/dev-wallet.js "bitwrap-create-poll:hello"
//
// with a fixed test private key (0x1111...1111).
func TestJSDevWalletParity(t *testing.T) {
	msg := "bitwrap-create-poll:hello"
	addr := "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	sig := "0x775d4a30860e69f813f9698ba1f74ec4ea3a4604b84e8c3c25a06f45c84b465739512c39885be16a516fa2178453d9686128646c9e3ea67198a4918249da953e1c"

	rec, err := RecoverAddress(msg, sig)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if rec != addr {
		t.Fatalf("recovered %s, want %s", rec, addr)
	}
	if !VerifySignature(msg, sig, addr) {
		t.Fatalf("VerifySignature returned false for JS-produced sig")
	}
}
