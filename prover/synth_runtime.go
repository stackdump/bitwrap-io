package prover

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// synthMimcHash hashes two field elements with MiMC-BN254.
//
// Hand-written runtime helper shared by every generated circuit in
// prover/*_gen.go. Kept out of the generators so the gen files don't
// collide when multiple ERC templates are synthesized into the same
// package.
func synthMimcHash(api frontend.API, a, b frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(a)
	h.Write(b)
	return h.Sum()
}
