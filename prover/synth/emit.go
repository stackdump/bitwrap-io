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

// emitMimcHelper writes the package-level MiMC hash helper. Call exactly
// once per generated file (tracked by hasMimcHelper flag in emitted output).
func emitMimcHelper(b *strings.Builder) {
	b.WriteString(`// synthMimcHash hashes two field elements with MiMC-BN254.
// Package-local helper so generated circuits don't collide with prover/circuits.go.
func synthMimcHash(api frontend.API, a, b frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(a)
	h.Write(b)
	return h.Sum()
}

`)
}
