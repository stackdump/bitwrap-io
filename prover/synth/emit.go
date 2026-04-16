package synth

import (
	"fmt"
	"strings"
)

// emitStructField writes one line of a circuit struct: an indented field
// declaration with optional `gnark:",public"` tag.
func emitStructField(b *strings.Builder, name string, public bool) {
	if public {
		b.WriteString(fmt.Sprintf("\t%s frontend.Variable `gnark:\",public\"`\n", name))
	} else {
		b.WriteString(fmt.Sprintf("\t%s frontend.Variable\n", name))
	}
}

// emitCircuitStruct writes a full struct declaration given ordered public and
// private field names. Public fields come first; within each group, the order
// provided by the caller is preserved (callers must pre-sort for determinism).
func emitCircuitStruct(b *strings.Builder, name, doc string, public, private []string) {
	if doc != "" {
		b.WriteString("// " + doc + "\n")
	}
	b.WriteString(fmt.Sprintf("type %s struct {\n", name))
	for _, f := range public {
		emitStructField(b, f, true)
	}
	if len(public) > 0 && len(private) > 0 {
		b.WriteString("\n")
	}
	for _, f := range private {
		emitStructField(b, f, false)
	}
	b.WriteString("}\n\n")
}

// emitDefineHeader writes the opening of a `func (c *Name) Define(api frontend.API) error {`.
func emitDefineHeader(b *strings.Builder, circuitName string) {
	b.WriteString(fmt.Sprintf("func (c *%s) Define(api frontend.API) error {\n", circuitName))
}

// emitDefineFooter writes the closing of a Define() method.
func emitDefineFooter(b *strings.Builder) {
	b.WriteString("\treturn nil\n}\n\n")
}

// emitComment writes a one-line body comment at indentation level 1.
func emitComment(b *strings.Builder, text string) {
	b.WriteString("\t// " + text + "\n")
}

// emitAssertEq writes `api.AssertIsEqual(a, b)`.
func emitAssertEq(b *strings.Builder, a, bExpr string) {
	b.WriteString(fmt.Sprintf("\tapi.AssertIsEqual(%s, %s)\n", a, bExpr))
}

// emitAdd writes `name := api.Add(a, b)`.
func emitAdd(b *strings.Builder, name, a, bExpr string) {
	b.WriteString(fmt.Sprintf("\t%s := api.Add(%s, %s)\n", name, a, bExpr))
}

// emitMimcHashCall writes `name := synthMimcHash(api, a, b)`, invoking the
// helper that every generated file can rely on (emitted once per file via
// emitMimcHelper).
func emitMimcHashCall(b *strings.Builder, name, a, bExpr string) {
	b.WriteString(fmt.Sprintf("\t%s := synthMimcHash(api, %s, %s)\n", name, a, bExpr))
}

// emitMimcHelper is a no-op retained for call-site compatibility. The
// MiMC helper now lives in hand-written prover/synth_runtime.go so the
// gen files can share it without multi-file declaration collisions.
func emitMimcHelper(b *strings.Builder) {
	// intentional no-op
}

// emitMerkleMembership writes the gnark loop that walks a fixed-depth binary
// Merkle tree from a leaf expression up to a root assertion. Matches the
// hand-written pattern in prover/circuits.go exactly:
//
//	leaf := synthMimcHash(api, key, value)
//	current := leaf
//	for i := 0; i < depth; i++ {
//	    api.AssertIsBoolean(c.PathIndices[i])
//	    left := api.Select(c.PathIndices[i], c.PathElements[i], current)
//	    right := api.Select(c.PathIndices[i], current, c.PathElements[i])
//	    current = synthMimcHash(api, left, right)
//	}
//	api.AssertIsEqual(current, rootExpr)
//
// `pathName` is the struct-field prefix, usually "PathElements"/"PathIndices";
// pass "BalancePath"/"BalanceIndices" etc. when a circuit has multiple proofs.
func emitMerkleMembership(b *strings.Builder, depth int, leafExpr, rootExpr, elemsField, idxField, curVar string) {
	b.WriteString(fmt.Sprintf("\t%s := %s\n", curVar, leafExpr))
	b.WriteString(fmt.Sprintf("\tfor i := 0; i < %d; i++ {\n", depth))
	b.WriteString(fmt.Sprintf("\t\tapi.AssertIsBoolean(c.%s[i])\n", idxField))
	b.WriteString(fmt.Sprintf("\t\tleft := api.Select(c.%s[i], c.%s[i], %s)\n", idxField, elemsField, curVar))
	b.WriteString(fmt.Sprintf("\t\tright := api.Select(c.%s[i], %s, c.%s[i])\n", idxField, curVar, elemsField))
	b.WriteString(fmt.Sprintf("\t\t%s = synthMimcHash(api, left, right)\n", curVar))
	b.WriteString("\t}\n")
	b.WriteString(fmt.Sprintf("\tapi.AssertIsEqual(%s, %s)\n", curVar, rootExpr))
}

// emitRangeCheck writes `api.ToBinary(expr, bits)` which gnark uses as a
// non-negative range proof. The bit count must match the hand-written
// circuit exactly or the VK diverges.
func emitRangeCheck(b *strings.Builder, expr string, bits int) {
	b.WriteString(fmt.Sprintf("\tapi.ToBinary(%s, %d)\n", expr, bits))
}

// emitSub writes `name := api.Sub(a, b)`.
func emitSub(b *strings.Builder, name, a, bExpr string) {
	b.WriteString(fmt.Sprintf("\t%s := api.Sub(%s, %s)\n", name, a, bExpr))
}

// emitMerklePathFields appends fixed-size path-element + path-index array
// fields to a struct body. depth must match the emitter's loop depth.
func emitMerklePathFields(b *strings.Builder, elemsField, idxField string, depth int) {
	b.WriteString(fmt.Sprintf("\t%s [%d]frontend.Variable\n", elemsField, depth))
	b.WriteString(fmt.Sprintf("\t%s [%d]frontend.Variable\n", idxField, depth))
}
